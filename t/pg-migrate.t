#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use Lilith::Schema         ();
use DBIx::Class::Migration ();

# End-to-end migration tests against a real PostgreSQL server: TestPG initdb's a
# throwaway cluster on a random high port, and the deploy / migrate /
# schema_version commands run their real DBIx::Class::Migration work against it.
# Skipped where the server binaries are not installed.
use TestPG ();

plan skip_all => 'PostgreSQL server binaries (initdb/pg_ctl/postgres) not found'
	unless TestPG->bindir;

use_ok('Lilith::CLI::Command::Deploy')        or BAIL_OUT('Deploy failed to load');
use_ok('Lilith::CLI::Command::Migrate')       or BAIL_OUT('Migrate failed to load');
use_ok('Lilith::CLI::Command::SchemaVersion') or BAIL_OUT('SchemaVersion failed to load');

my $pg = eval { TestPG->new };
BAIL_OUT("could not start PostgreSQL: $@") unless $pg;

my $code = $Lilith::Schema::VERSION;

# The 12 indexes the version-5 migration adds.
my @V5_INDEXES = qw(
	suricata_alerts_ts_idx suricata_alerts_class_ts_idx
	suricata_alerts_src_ts_idx suricata_alerts_sid_ts_idx
	sagan_alerts_ts_idx sagan_alerts_class_ts_idx
	sagan_alerts_src_ts_idx sagan_alerts_sid_ts_idx
	cape_alerts_stop_idx cape_alerts_malscore_stop_idx
	cape_alerts_src_stop_idx cape_alerts_target_stop_idx
);

# Every command reads dsn/user/pass through the base class config(); stub it to
# return a hash we point at whichever database a phase uses.
my %cfg = ( user => $pg->user, pass => $pg->pass );
no warnings qw(redefine once);
*Lilith::CLI::Command::config = sub { return \%cfg };
use warnings qw(redefine once);

# Run a command's execute() capturing what it prints.
sub run_cmd {
	my ($class) = @_;
	my $cmd     = bless {}, $class;
	my $out     = '';
	open( my $fh, '>', \$out ) or die $!;
	my $old = select($fh);
	eval { $cmd->execute( {}, [] ) };
	my $err = $@;
	select($old);
	close($fh);
	return ( $out, $err );
} ## end sub run_cmd

sub index_exists {
	my ( $dbh, $name ) = @_;
	my ($hit) = $dbh->selectrow_array( 'select 1 from pg_indexes where indexname = ?', undef, $name );
	return $hit ? 1 : 0;
}

sub table_exists {
	my ( $dbh, $name ) = @_;
	my ($hit) = $dbh->selectrow_array( 'select to_regclass(?)', undef, $name );
	return $hit ? 1 : 0;
}

# ---------------------------------------------------------------------------
# Phase 1: deploy at the current version into a fresh database.
# ---------------------------------------------------------------------------
{
	$cfg{dsn} = $pg->dsn;    # the 'lilith' database TestPG made

	my ( $sv_before, $sv_before_err ) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	is( $sv_before_err, '', 'schema_version before deploy lives' );
	like( $sv_before, qr/deployed:\s+none/, 'schema_version reports none before deploy' );

	my ( $out, $err ) = run_cmd('Lilith::CLI::Command::Deploy');
	is( $err, '', 'deploy lives against a real database' );
	like( $out, qr/deployed schema version \Q$code\E/, 'deploy reports the version' );

	my $dbh = $pg->dbh;
	ok( table_exists( $dbh, 'suricata_alerts' ), 'deploy created suricata_alerts' );
	ok( table_exists( $dbh, 'sagan_alerts' ),    'deploy created sagan_alerts' );
	ok( table_exists( $dbh, 'cape_alerts' ),     'deploy created cape_alerts' );
	ok( index_exists( $dbh, 'escalations_event_idx' ), 'deploy created the pre-existing escalations index' );

	my @missing = grep { !index_exists( $dbh, $_ ) } @V5_INDEXES;
	is_deeply( \@missing, [], 'deploy created all 12 version-5 indexes' )
		or diag( 'missing: ' . join( ', ', @missing ) );

	my ($ver)
		= $dbh->selectrow_array('select version from dbix_class_deploymenthandler_versions order by id desc limit 1');
	is( $ver, $code, 'deployed version storage records the current version' );

	# version 6: the dashboards table plus its seeded default board.
	ok( table_exists( $dbh, 'dashboards' ), 'deploy created the dashboards table' );
	my ($def) = $dbh->selectrow_array("select count(*) from dashboards where name = 'default' and is_default");
	is( $def, 1, 'deploy seeded the default dashboard' );

	# version 7: the Suricata severity expression index.
	ok( index_exists( $dbh, 'suricata_alerts_severity_ts_idx' ), 'deploy created the severity index' );

	# version 8: the MITRE tactic/technique partial expression indexes.
	ok( index_exists( $dbh, 'suricata_alerts_mitre_tactic_idx' ),    'deploy created the MITRE tactic index' );
	ok( index_exists( $dbh, 'suricata_alerts_mitre_technique_idx' ), 'deploy created the MITRE technique index' );
	$dbh->disconnect;

	my ($sv_after) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $sv_after, qr/status:\s+current/, 'schema_version reports current after deploy' );
}

# ---------------------------------------------------------------------------
# Phase 2: the 4 -> 5 upgrade. Seed a second database at version 4 (test setup,
# not something the commands do), then let the migrate command upgrade it.
# ---------------------------------------------------------------------------
{
	my $up_dsn = $pg->create_db('lilith_upgrade');

	# Seed version 4 directly.
	my $seed = DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $up_dsn, $pg->user, $pg->pass ],
	);
	$seed->dbic_dh->install( { version => 4 } );

	my $dbh = $pg->dbh($up_dsn);
	ok( table_exists( $dbh, 'suricata_alerts' ),         'v4 seed created suricata_alerts' );
	ok( !index_exists( $dbh, 'suricata_alerts_ts_idx' ), 'v5 indexes absent at version 4' );

	# Now upgrade through the command.
	$cfg{dsn} = $up_dsn;
	my ( $out, $err ) = run_cmd('Lilith::CLI::Command::Migrate');
	is( $err, '', 'migrate lives against a real database' );
	like( $out, qr/schema is now at version \Q$code\E/, 'migrate reports the version' );

	my @missing = grep { !index_exists( $dbh, $_ ) } @V5_INDEXES;
	is_deeply( \@missing, [], 'the 4 -> 5 upgrade created all 12 version-5 indexes' )
		or diag( 'missing: ' . join( ', ', @missing ) );

	my ($ver)
		= $dbh->selectrow_array('select version from dbix_class_deploymenthandler_versions order by id desc limit 1');
	is( $ver, $code, 'version storage records the current version after the upgrade' );
	ok( table_exists( $dbh, 'dashboards' ), 'the upgrade created the dashboards table' );
	ok( index_exists( $dbh, 'suricata_alerts_severity_ts_idx' ),  'the upgrade created the severity index' );
	ok( index_exists( $dbh, 'suricata_alerts_mitre_tactic_idx' ), 'the upgrade created the MITRE tactic index' );
	$dbh->disconnect;

	my ($sv) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $sv, qr/status:\s+current/, 'schema_version reports current after the upgrade' );
}

$pg->stop;

done_testing;
