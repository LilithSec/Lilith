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
# found. Looks on PATH first, then falls back to `pg_config --bindir`, which is
# how a packaged PostgreSQL that keeps the server binaries off PATH is found.
#
# This is the gate the tests skip on: a machine with only the client libraries
# installed can still run the rest of the suite. Plain function, not a method.
#
# Args: none.
#
# Returns: the directory as a string when all three programs are executable in
# one place, or undef when they are not -- callers treat undef as "skip", not
# as an error.
#
#     my $bindir = TestPG::bindir()
#         or plan skip_all => 'PostgreSQL server binaries not found';
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

# True when every named program is present and executable in $dir. Split out of
# bindir so both the PATH walk and the pg_config fallback test a directory the
# same way. Plain function, not a method.
#
# Args:
#
#   - $dir :: the directory to look in.
#   - @progs :: the program names that must all be there, e.g. initdb, pg_ctl,
#     postgres.
#
# Returns: 1 when all of them are executable in $dir, 0 as soon as one is not.
#
#     _all_in( '/usr/local/bin', qw( initdb pg_ctl postgres ) );
sub _all_in {
	my ( $dir, @progs ) = @_;
	for my $p (@progs) {
		return 0 unless -x File::Spec->catfile( $dir, $p );
	}
	return 1;
}

# initdb a cluster and start it on a random high port. Dies on failure; callers
# gate on bindir() and skip the test when it is undef.
#
# The port is picked at random and retried up to 20 times, since there is no way
# to reserve one ahead of asking the server to bind it and parallel test runs
# would otherwise collide. The cluster runs with fsync and full_page_writes off:
# it is thrown away at exit, so durability buys nothing and costs a good deal of
# wall clock. An empty 'lilith' database is created ready for a deploy.
#
# Args: none.
#
# Returns: the blessed TestPG object, with the cluster up and accepting
# connections. Registered for shutdown at process exit, so a test that dies
# partway does not leave a postgres running. Dies with the last 20 lines of the
# log when initdb or pg_ctl fails.
#
#     my $pg = TestPG->new;
#     my $dbh = $pg->dbh;
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

# The TCP port the cluster was started on, picked at random in new().
#
# Args: none.
#
# Returns: the port as an integer.
sub port { $_[0]{port} }

# The database user the harness connects as. Always the superuser initdb
# created, since the cluster is throwaway and trust authenticated.
#
# Args: none.
#
# Returns: 'postgres' as a string.
sub user { 'postgres' }

# The password for that user. The cluster runs with trust auth, so there is
# none.
#
# Args: none.
#
# Returns: the empty string.
sub pass { '' }

# The DSN for the application database created in new().
#
# Args: none.
#
# Returns: the DSN as a string, e.g.
# 'dbi:Pg:dbname=lilith;host=127.0.0.1;port=24242'.
sub dsn { $_[0]->dsn_for( $_[0]{dbname} ) }

# The DSN for any database on this cluster.
#
# Args:
#
#   - $name :: the database name to build a DSN for, e.g. 'postgres' for the
#     maintenance database or whatever create_db was given.
#
# Returns: the DSN as a string. Always over TCP on 127.0.0.1 rather than the
# socket, so it matches how the code under test connects.
#
#     $pg->dsn_for('postgres');
sub dsn_for { "dbi:Pg:dbname=$_[1];host=127.0.0.1;port=$_[0]{port}" }

# Create an additional database and return its dsn (for tests that need a
# second, independently-migrated database, e.g. proving a deploy and an upgrade
# land at the same schema).
#
# The name is interpolated into the CREATE DATABASE rather than bound, since
# Postgres takes no placeholder there. It comes from the test itself, never from
# input, so that is safe here in a way it would not be in the code under test.
#
# Args:
#
#   - $name :: the database to create, e.g. 'lilith_upgrade'. Must be a plain
#     identifier.
#
# Returns: the new database's DSN as a string, ready to hand to dbh or to the
# code under test. Dies when the database already exists or cannot be created.
#
#     my $second = $pg->create_db('lilith_upgrade');
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
#
# Fresh rather than cached on purpose: a test that wants to see what another
# connection committed, or that has just had one die under it, needs a new
# handle rather than a shared one.
#
# Args:
#
#   - $dsn :: the database to connect to. Optional; the application database is
#     used when it is left off. Normally one create_db handed back.
#
# Returns: a DBI database handle with RaiseError on, PrintError off, and
# AutoCommit on -- so a failed statement dies in the test rather than warning
# and carrying on. Dies when the connection cannot be made.
#
#     my $dbh = $pg->dbh;
#     my $dbh = $pg->dbh( $pg->dsn_for('lilith_upgrade') );
sub dbh {
	my ( $self, $dsn ) = @_;
	return DBI->connect( $dsn // $self->dsn,
		$self->user, $self->pass, { RaiseError => 1, PrintError => 0, AutoCommit => 1 } );
}

# Stop the cluster, if it is still running. Idempotent: the data directory is
# forgotten once stopped, so the DESTROY and END handlers can both call it
# without the second doing anything.
#
# Shuts down in immediate mode, since a throwaway cluster has nothing worth
# waiting for a clean checkpoint over.
#
# Args: none.
#
# Returns: nothing meaningful. The temp directory itself goes when File::Temp
# cleans up at exit.
sub stop {
	my ($self) = @_;
	return unless $self->{data} && -d $self->{data};
	_run( $self->{log}, File::Spec->catfile( $self->{bindir}, 'pg_ctl' ),
		'-D', $self->{data}, '-m', 'immediate', '-w', 'stop' );
	delete $self->{data};
	return;
}

# Stop the cluster when the object goes away. $? and $@ are localized because
# this can run during global destruction, where clobbering either would change
# the exit status or swallow an error the test was about to report.
#
# Args: none.
#
# Returns: nothing meaningful.
sub DESTROY { local ( $?, $@ ); $_[0]->stop }
END { local ( $?, $@ ); $_->stop for @LIVE }

# Run a command with stdout/stderr redirected to $log. True on success.
#
# The redirect is done by saving and restoring the real handles rather than with
# a shell redirection, so the command is run without a shell and initdb's and
# pg_ctl's chatter stays out of the TAP stream, where it would look like test
# output. Plain function, not a method.
#
# Args:
#
#   - $log :: path to append the command's output to.
#   - @cmd :: the command and its arguments, as a list -- passed to system
#     directly, so no quoting is needed or wanted.
#
# Returns: 1 when the command exited 0, and '' otherwise. The output itself is
# in $log; _tail is what fishes it out for an error message.
#
#     _run( $log, $pg_ctl, '-D', $data, '-w', 'stop' ) or die _tail($log);
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

# The last few lines of the log, for putting in a die message when initdb or
# pg_ctl fails. Plain function, not a method.
#
# Args:
#
#   - $file :: path to the log to read.
#
# Returns: up to the last 20 lines joined into one string, newlines included,
# or '' when the file cannot be read -- a failure to read the log should not
# mask the failure being reported.
sub _tail {
	my ($file) = @_;
	open( my $fh, '<', $file ) or return '';
	my @lines = <$fh>;
	close($fh);
	@lines = splice( @lines, -20 ) if @lines > 20;
	return join( '', @lines );
}

1;
