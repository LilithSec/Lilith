#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use Lilith::Schema         ();
use DBIx::Class::Migration ();

# The deploy / migrate / schema_version commands wrap DBIx::Class::Migration.
# The rest of the suite mocks Lilith::Schema->connect so nothing touches a real
# PostgreSQL database; here we do the same one level up, swapping
# DBIx::Class::Migration->new for a fake that records install/upgrade calls and
# serves a configurable installed version.

use_ok('Lilith::CLI')                         or BAIL_OUT('Lilith::CLI failed to load');
use_ok('Lilith::CLI::Command::Deploy')        or BAIL_OUT('Deploy failed to load');
use_ok('Lilith::CLI::Command::Migrate')       or BAIL_OUT('Migrate failed to load');
use_ok('Lilith::CLI::Command::SchemaVersion') or BAIL_OUT('SchemaVersion failed to load');

# ---------------------------------------------------------------------------
# Fakes standing in for DBIx::Class::Migration and its DeploymentHandler.
# ---------------------------------------------------------------------------
{

	package FakeDH;
	sub new { return bless {}, shift }

	sub database_version {
		die "no version storage\n" if $FakeMigration::DIE_ON_VERSION;
		return $FakeMigration::DB_VERSION;
	}

	package FakeMigration;
	our @CALLS;
	our @NEW_ARGS;
	our $DB_VERSION;
	our $DIE_ON_VERSION = 0;

	sub new {
		my ( $class, %args ) = @_;
		push( @NEW_ARGS, \%args );
		return bless {}, $class;
	}
	sub install { push( @CALLS, 'install' ); return 1 }
	sub upgrade { push( @CALLS, 'upgrade' ); return 1 }
	sub dbic_dh { return FakeDH->new }
}

no warnings qw(redefine once);
*DBIx::Class::Migration::new = sub { shift; return FakeMigration->new(@_) };

# Every command reads dsn/user/pass through the base class config(); stub it so
# no config file is needed.
my %toml = ( dsn => 'dbi:Pg:dbname=lilith', user => 'lilith', pass => 'secret' );
*Lilith::CLI::Command::config = sub { return \%toml };
use warnings qw(redefine once);

# Run a command's execute() capturing what it prints.
sub run_cmd {
	my ($class) = @_;
	my $cmd = bless {}, $class;
	my $out = '';
	open( my $fh, '>', \$out ) or die $!;
	my $old = select($fh);
	eval { $cmd->execute( {}, [] ) };
	my $err = $@;
	select($old);
	close($fh);
	return ( $out, $err );
}

my $code = $Lilith::Schema::VERSION;

# ---------------------------------------------------------------------------
# The three commands register with the app.
# ---------------------------------------------------------------------------
{
	my %names = map { $_ => 1 } Lilith::CLI->new->command_names;
	ok( $names{deploy},         'deploy registers with the app' );
	ok( $names{migrate},        'migrate registers with the app' );
	ok( $names{schema_version}, 'schema_version registers with the app' );
}

# ---------------------------------------------------------------------------
# deploy -> install, with dsn/user/pass from the config.
# ---------------------------------------------------------------------------
{
	@FakeMigration::CALLS    = ();
	@FakeMigration::NEW_ARGS = ();
	my ( $out, $err ) = run_cmd('Lilith::CLI::Command::Deploy');
	is( $err, '', 'deploy execute lives' );
	is_deeply( \@FakeMigration::CALLS, ['install'], 'deploy calls ->install' );
	is( $FakeMigration::NEW_ARGS[0]{schema_class},
		'Lilith::Schema', 'deploy builds the migration for Lilith::Schema' );
	is_deeply(
		$FakeMigration::NEW_ARGS[0]{schema_args},
		[ $toml{dsn}, $toml{user}, $toml{pass} ],
		'deploy passes dsn/user/pass from the config'
	);
	like( $out, qr/deployed schema version \Q$code\E/, 'deploy reports the version' );
}

# ---------------------------------------------------------------------------
# migrate -> upgrade.
# ---------------------------------------------------------------------------
{
	@FakeMigration::CALLS = ();
	my ( $out, $err ) = run_cmd('Lilith::CLI::Command::Migrate');
	is( $err, '', 'migrate execute lives' );
	is_deeply( \@FakeMigration::CALLS, ['upgrade'], 'migrate calls ->upgrade' );
	like( $out, qr/schema is now at version \Q$code\E/, 'migrate reports the version' );
}

# ---------------------------------------------------------------------------
# schema_version across the four states.
# ---------------------------------------------------------------------------
{
	my $prev = $code - 1;
	local $FakeMigration::DB_VERSION = $prev;
	my ($out) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $out, qr/this release:\s+\Q$code\E/, 'schema_version reports the release version' );
	like( $out, qr/deployed:\s+\Q$prev\E/,     'schema_version reports the deployed version' );
	like( $out, qr/upgrade pending/,           'schema_version flags a pending upgrade' );
}
{
	local $FakeMigration::DB_VERSION = $code;
	my ($out) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $out, qr/status:\s+current/, 'schema_version flags a current database' );
}
{
	local $FakeMigration::DB_VERSION = $code + 1;
	my ($out) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $out, qr/database is newer/, 'schema_version flags a database newer than the release' );
}
{
	local $FakeMigration::DIE_ON_VERSION = 1;
	my ($out) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $out, qr/deployed:\s+none/, 'schema_version reports none when nothing is deployed' );
}

done_testing;
