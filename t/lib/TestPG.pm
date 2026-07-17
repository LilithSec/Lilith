package TestPG;

# A tiny, dependency-free PostgreSQL harness for the test suite: initdb a
# throwaway cluster into a temp dir, start it on a random high TCP port on
# 127.0.0.1 with trust auth, and hand back a dsn/user/pass plus a dbh. The
# cluster is stopped and removed at process exit. Used by the migration tests
# so deploy/upgrade run against a real server; skipped when the server binaries
# are not installed.

use strict;
use warnings;
use File::Temp qw( tempdir );
use File::Spec ();
use DBI        ();

my @LIVE;    # instances to stop at exit

# The directory holding initdb/pg_ctl/postgres, or undef when they are not all
# found. Looks on PATH first, then falls back to `pg_config --bindir`.
sub bindir {
	my @need = qw( initdb pg_ctl postgres );

	for my $dir ( grep { length } split /:/, ( $ENV{PATH} // '' ) ) {
		return $dir if _all_in( $dir, @need );
	}

	my $bindir = `pg_config --bindir 2>/dev/null`;
	chomp $bindir  if defined $bindir;
	return $bindir if defined $bindir && length $bindir && _all_in( $bindir, @need );

	return undef;
} ## end sub bindir

sub _all_in {
	my ( $dir, @progs ) = @_;
	for my $p (@progs) {
		return 0 unless -x File::Spec->catfile( $dir, $p );
	}
	return 1;
}

# initdb a cluster and start it on a random high port. Dies on failure; callers
# gate on bindir() and skip the test when it is undef.
sub new {
	my ($class) = @_;

	my $bindir = bindir() or die "PostgreSQL server binaries not found\n";

	my $base = tempdir( CLEANUP => 1 );
	my $data = File::Spec->catdir( $base, 'data' );
	my $sock = File::Spec->catdir( $base, 'sock' );
	my $log  = File::Spec->catfile( $base, 'pg.log' );
	mkdir $sock;

	_run( $log, File::Spec->catfile( $bindir, 'initdb' ),
		'-D', $data, '-U', 'postgres', '--auth=trust', '--encoding=UTF8', '--no-sync' )
		or die "initdb failed; see $log\n" . _tail($log);

	my $pg_ctl = File::Spec->catfile( $bindir, 'pg_ctl' );
	my $port;
	my $started = 0;
	for ( 1 .. 20 ) {
		$port = 20000 + int( rand(40000) );
		my $opts = "-p $port -k $sock -c listen_addresses=127.0.0.1 -c fsync=off -c full_page_writes=off";
		if ( _run( $log, $pg_ctl, '-D', $data, '-l', $log, '-o', $opts, '-w', '-t', '60', 'start' ) ) {
			$started = 1;
			last;
		}
	}
	die "pg_ctl start failed after retries; see $log\n" . _tail($log) unless $started;

	my $self = bless {
		base   => $base,
		data   => $data,
		port   => $port,
		bindir => $bindir,
		log    => $log,
		dbname => 'lilith',
	}, $class;
	push @LIVE, $self;

	# Create the application database as the superuser.
	my $admin = DBI->connect(
		"dbi:Pg:dbname=postgres;host=127.0.0.1;port=$port",
		'postgres', '', { RaiseError => 1, PrintError => 0, AutoCommit => 1 },
	);
	$admin->do('CREATE DATABASE lilith');
	$admin->disconnect;

	return $self;
} ## end sub new

sub port    { $_[0]{port} }
sub user    { 'postgres' }
sub pass    { '' }
sub dsn     { $_[0]->dsn_for( $_[0]{dbname} ) }
sub dsn_for { "dbi:Pg:dbname=$_[1];host=127.0.0.1;port=$_[0]{port}" }

# Create an additional database and return its dsn (for tests that need a
# second, independently-migrated database).
sub create_db {
	my ( $self, $name ) = @_;
	my $admin = DBI->connect(
		$self->dsn_for('postgres'),
		$self->user, $self->pass, { RaiseError => 1, PrintError => 0, AutoCommit => 1 },
	);
	$admin->do("CREATE DATABASE $name");
	$admin->disconnect;
	return $self->dsn_for($name);
} ## end sub create_db

# A fresh connection to the application database, or to $dsn when given.
sub dbh {
	my ( $self, $dsn ) = @_;
	return DBI->connect( $dsn // $self->dsn,
		$self->user, $self->pass, { RaiseError => 1, PrintError => 0, AutoCommit => 1 } );
}

sub stop {
	my ($self) = @_;
	return unless $self->{data} && -d $self->{data};
	_run( $self->{log}, File::Spec->catfile( $self->{bindir}, 'pg_ctl' ),
		'-D', $self->{data}, '-m', 'immediate', '-w', 'stop' );
	delete $self->{data};
	return;
}

sub DESTROY { local ( $?, $@ ); $_[0]->stop }
END { local ( $?, $@ ); $_->stop for @LIVE }

# Run a command with stdout/stderr redirected to $log. True on success.
sub _run {
	my ( $log, @cmd ) = @_;
	open( my $oldout, '>&', \*STDOUT ) or die $!;
	open( my $olderr, '>&', \*STDERR ) or die $!;
	open( STDOUT,     '>>', $log )     or die $!;
	open( STDERR,     '>>', $log )     or die $!;
	my $rc = system(@cmd);
	open( STDOUT, '>&', $oldout ) or die $!;
	open( STDERR, '>&', $olderr ) or die $!;
	return $rc == 0;
} ## end sub _run

sub _tail {
	my ($file) = @_;
	open( my $fh, '<', $file ) or return '';
	my @lines = <$fh>;
	close($fh);
	@lines = splice( @lines, -20 ) if @lines > 20;
	return join( '', @lines );
}

1;
