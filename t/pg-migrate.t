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

# The 4 indexes the version-10 (baphomet_alerts) migration adds.
my @V10_BAPHOMET_INDEXES = qw(
	baphomet_alerts_ts_idx baphomet_alerts_event_ts_idx
	baphomet_alerts_src_ts_idx baphomet_alerts_kur_ts_idx
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

sub column_exists {
	my ( $dbh, $table, $column ) = @_;
	my ($hit)
		= $dbh->selectrow_array( 'select 1 from information_schema.columns where table_name = ? and column_name = ?',
			undef, $table, $column );
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

	# version 11: malscore is double precision, so CAPE's fractional scores
	# insert instead of aborting with "invalid input syntax for type bigint".
	my $frac_malscore = eval {
		$dbh->do( 'insert into cape_alerts (instance,target,instance_host,task,malscore,raw) values (?,?,?,?,?,?)',
			undef, 'lilith', 't.msi', 'host', 96, 0.2, '{}' );
		my ($got) = $dbh->selectrow_array("select malscore from cape_alerts where target = 't.msi'");
		$got;
	};
	is( $@,             '',  'a fractional cape malscore inserts without error' );
	is( $frac_malscore, 0.2, 'the fractional malscore round-trips' );
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

	# version 9: the per-dashboard settings column.
	ok( column_exists( $dbh, 'dashboards', 'settings' ), 'deploy added the dashboards.settings column' );

	# version 10: the baphomet_alerts table and its indexes.
	ok( table_exists( $dbh, 'baphomet_alerts' ), 'deploy created baphomet_alerts' );
	my @baph_missing = grep { !index_exists( $dbh, $_ ) } @V10_BAPHOMET_INDEXES;
	is_deeply( \@baph_missing, [], 'deploy created all 4 baphomet_alerts indexes' )
		or diag( 'missing: ' . join( ', ', @baph_missing ) );
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
	ok( table_exists( $dbh, 'dashboards' ),                       'the upgrade created the dashboards table' );
	ok( index_exists( $dbh, 'suricata_alerts_severity_ts_idx' ),  'the upgrade created the severity index' );
	ok( index_exists( $dbh, 'suricata_alerts_mitre_tactic_idx' ), 'the upgrade created the MITRE tactic index' );
	ok( column_exists( $dbh, 'dashboards', 'settings' ),          'the upgrade added the dashboards.settings column' );
	ok( table_exists( $dbh, 'baphomet_alerts' ),                  'the upgrade created baphomet_alerts' );
	$dbh->disconnect;

	my ($sv) = run_cmd('Lilith::CLI::Command::SchemaVersion');
	like( $sv, qr/status:\s+current/, 'schema_version reports current after the upgrade' );
}

# ---------------------------------------------------------------------------
# Phase 3: the 9 -> 10 -> 9 round trip. Seed a database at version 9 (before
# baphomet_alerts), upgrade it to 10 and confirm the table and its indexes
# appear, then downgrade back to 9 and confirm the table is dropped -- so the
# upgrade/9-10 and downgrade/10-9 scripts are exercised as a pair.
# ---------------------------------------------------------------------------
{
	my $rt_dsn = $pg->create_db('lilith_roundtrip');

	my $mig = DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $rt_dsn, $pg->user, $pg->pass ],
	);
	$mig->dbic_dh->install( { version => 9 } );

	my $dbh = $pg->dbh($rt_dsn);
	ok( !table_exists( $dbh, 'baphomet_alerts' ), 'baphomet_alerts absent at version 9' );

	$mig->dbic_dh->upgrade;    # 9 -> 10
	ok( table_exists( $dbh, 'baphomet_alerts' ), 'the 9 -> 10 upgrade created baphomet_alerts' );
	my @rt_missing = grep { !index_exists( $dbh, $_ ) } @V10_BAPHOMET_INDEXES;
	is_deeply( \@rt_missing, [], 'the 9 -> 10 upgrade created the baphomet_alerts indexes' )
		or diag( 'missing: ' . join( ', ', @rt_missing ) );

	# DeploymentHandler downgrades toward the schema's own version, so pretend the
	# schema is at 9 to drive the 10 -> 9 step; a fresh handler reads the version
	# at build time.
	{
		no warnings qw(redefine once);
		local $Lilith::Schema::VERSION = 9;
		my $down = DBIx::Class::Migration->new(
			schema_class => 'Lilith::Schema',
			schema_args  => [ $rt_dsn, $pg->user, $pg->pass ],
		);
		$down->dbic_dh->downgrade;    # 10 -> 9
	}
	ok( !table_exists( $dbh, 'baphomet_alerts' ), 'the 10 -> 9 downgrade dropped baphomet_alerts' );
	$dbh->disconnect;
}

$pg->stop;

done_testing;
