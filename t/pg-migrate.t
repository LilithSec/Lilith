#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use Lilith                 ();
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

	# versions 7 and 8 indexed the severity and MITRE fields as expressions over
	# raw; version 13 promoted them to generated columns and reindexed on those,
	# timestamp first so a windowed group-by can be answered from the index.
	ok( column_exists( $dbh, 'suricata_alerts', 'severity' ),           'deploy created the severity column' );
	ok( column_exists( $dbh, 'suricata_alerts', 'mitre_tactic' ),       'deploy created the MITRE tactic column' );
	ok( column_exists( $dbh, 'suricata_alerts', 'mitre_technique' ),    'deploy created the MITRE technique column' );
	ok( index_exists( $dbh, 'suricata_alerts_ts_severity_idx' ),        'deploy created the severity index' );
	ok( index_exists( $dbh, 'suricata_alerts_ts_mitre_tactic_idx' ),    'deploy created the MITRE tactic index' );
	ok( index_exists( $dbh, 'suricata_alerts_ts_mitre_technique_idx' ), 'deploy created the MITRE technique index' );

	# and the expression indexes they replace are gone, not left maintained for
	# nothing -- a query naming the column cannot match an index on the expression
	ok( !index_exists( $dbh, 'suricata_alerts_severity_ts_idx' ), 'deploy left no stale expression index' );

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
	ok( table_exists( $dbh, 'dashboards' ),                          'the upgrade created the dashboards table' );
	ok( column_exists( $dbh, 'suricata_alerts', 'severity' ),        'the upgrade created the severity column' );
	ok( index_exists( $dbh, 'suricata_alerts_ts_severity_idx' ),     'the upgrade created the severity index' );
	ok( index_exists( $dbh, 'suricata_alerts_ts_mitre_tactic_idx' ), 'the upgrade created the MITRE tactic index' );
	ok( !index_exists( $dbh, 'suricata_alerts_severity_ts_idx' ),    'the upgrade dropped the expression index' );
	ok( column_exists( $dbh, 'dashboards', 'settings' ),      'the upgrade added the dashboards.settings column' );
	ok( table_exists( $dbh, 'baphomet_alerts' ),              'the upgrade created baphomet_alerts' );
	ok( column_exists( $dbh, 'baphomet_alerts', 'username' ), 'the 13 -> 14 upgrade added baphomet_alerts.username' );
	ok( column_exists( $dbh, 'baphomet_alerts', 'sid' ),      'the 13 -> 14 upgrade added baphomet_alerts.sid' );
	ok( !column_exists( $dbh, 'baphomet_alerts', 'subject' ), 'the 13 -> 14 upgrade dropped baphomet_alerts.subject' );
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

# ---------------------------------------------------------------------------
# Phase 4: the 14 -> 15 -> 14 round trip (shodan_cache), and the cache methods
# against the table the migration actually creates -- the SQL in
# shodan_cache_put is the only place the column list, the casts, and the upsert
# have to agree with the DDL, and nothing else would catch a disagreement.
# ---------------------------------------------------------------------------
{
	my $sc_dsn = $pg->create_db('lilith_shodan_cache');

	my $mig = DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $sc_dsn, $pg->user, $pg->pass ],
	);
	$mig->dbic_dh->install( { version => 14 } );

	my $dbh = $pg->dbh($sc_dsn);
	ok( !table_exists( $dbh, 'shodan_cache' ), 'shodan_cache absent at version 14' );

	$mig->dbic_dh->upgrade;    # 14 -> 15
	ok( table_exists( $dbh, 'shodan_cache' ), 'the 14 -> 15 upgrade created shodan_cache' );
	for my $column (qw( ip source found fetched last_update ports tags cpes vulns max_cvss hostnames raw )) {
		ok( column_exists( $dbh, 'shodan_cache', $column ), "shodan_cache has the $column column" );
	}

	# A live round trip through the methods the web UI uses.
	my $lilith = Lilith->new( dsn => $sc_dsn, user => $pg->user, pass => $pg->pass );

	is( $lilith->shodan_cache_get( '192.0.2.10', 'api', 3600 ), undef, 'an address never cached is a miss' );

	my $raw  = { ports => [ 22, 443 ], tags => ['cloud'], last_update => '2026-06-14T02:11:33.123456' };
	my $info = {
		ports       => [ 22, 443 ],
		tags        => ['cloud'],
		cpes        => ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'],
		hostnames   => ['gate1.example.org'],
		last_update => '2026-06-14T02:11:33.123456',
		vulns       => [ { cve => 'CVE-2021-40438', cvss => 9.8 }, { cve => 'CVE-2019-0217', cvss => '' } ],
	};
	$lilith->shodan_cache_put( ip => '192.0.2.10', source => 'api', raw => $raw, info => $info, ttl => 3600 );

	is_deeply( $lilith->shodan_cache_get( '192.0.2.10', 'api', 3600 ), $raw, 'the response comes back as it went in' );
	is( $lilith->shodan_cache_get( '192.0.2.10', 'internetdb', 3600 ),
		undef, 'a row from the keyed tier is not served to the keyless one' );
	is( $lilith->shodan_cache_get( '192.0.2.10', 'api', 0 ), undef, 'a zero ttl never hits' );

	my $row = $dbh->selectrow_hashref(q{select * from shodan_cache where ip = '192.0.2.10'});
	is( $row->{found},    1,   'a response with content is recorded as found' );
	is( $row->{max_cvss}, 9.8, 'max_cvss is the worst score of the scored CVEs' );
	is_deeply( $row->{ports}, [ 22, 443 ],                                    'ports round trip as an integer array' );
	is_deeply( $row->{cpes},  ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'], 'cpes round trip as a text array' );
	is_deeply(
		[ sort @{ $row->{vulns} } ],
		[ 'CVE-2019-0217', 'CVE-2021-40438' ],
		'vulns are stored as the bare CVE ids'
	);
	# Read back in UTC: Shodan reports a naive stamp that is UTC, and the value
	# is only right if it was taken as UTC rather than as the server's own zone.
	my ($utc)
		= $dbh->selectrow_array(q{select last_update at time zone 'UTC' from shodan_cache where ip = '192.0.2.10'});
	like( $utc, qr/^2026-06-14 02:11:33/, 'shodan last_update is stored as the UTC instant it names' );

	# The bulk read behind the results tables' IP cell badges: one statement for
	# every address on a page, and only what is already cached.
	my $badges = $lilith->shodan_cache_badges(
		ips    => [ '192.0.2.10', '198.51.100.4' ],
		source => 'api',
		ttl    => 3600
	);
	is( scalar keys %{$badges}, 1, 'only addresses with a fresh entry come back' );
	ok( !exists $badges->{'198.51.100.4'}, 'an uncached address is absent rather than empty' );
	is_deeply( $badges->{'192.0.2.10'}{ports}, [ 22, 443 ], 'the badge read carries the ports' );
	is_deeply( $badges->{'192.0.2.10'}{tags},  ['cloud'],   'the badge read carries the tags' );
	is( $badges->{'192.0.2.10'}{vulns},    2,   'the badge read counts the CVEs rather than listing them' );
	is( $badges->{'192.0.2.10'}{max_cvss}, 9.8, 'the badge read carries the worst score' );
	is_deeply( $lilith->shodan_cache_badges( ips => [], source => 'api', ttl => 3600 ),
		{}, 'no addresses means no badges' );

	# An address Shodan has never crawled is cached too, as an empty response.
	$lilith->shodan_cache_put( ip => '192.0.2.11', source => 'api', raw => {}, info => {}, ttl => 3600 );
	is_deeply( $lilith->shodan_cache_get( '192.0.2.11', 'api', 3600 ),
		{}, 'a cached "nothing known" is a hit, not a miss' );
	my ($found) = $dbh->selectrow_array(q{select found from shodan_cache where ip = '192.0.2.11'});
	is( $found, 0, 'an empty response is recorded as not found' );

	# The upsert replaces rather than duplicating, and re-reads as the new value.
	$lilith->shodan_cache_put(
		ip     => '192.0.2.10',
		source => 'internetdb',
		raw    => { ports => [80] },
		info   => { ports => [80] },
		ttl    => 3600
	);
	my ($rows) = $dbh->selectrow_array(q{select count(*) from shodan_cache where ip = '192.0.2.10'});
	is( $rows, 1, 'a second write for an address replaces the first' );
	is_deeply(
		$lilith->shodan_cache_get( '192.0.2.10', 'internetdb', 3600 ),
		{ ports => [80] },
		'the replacement is what is served'
	);

	# The prune on write clears anything already past the ttl.
	$dbh->do(q{update shodan_cache set fetched = now() - interval '2 hours' where ip = '192.0.2.11'});
	$lilith->shodan_cache_put( ip => '192.0.2.12', source => 'api', raw => {}, info => {}, ttl => 3600 );
	my ($left) = $dbh->selectrow_array(q{select count(*) from shodan_cache where ip = '192.0.2.11'});
	is( $left, 0, 'writing prunes the entries that have expired' );

	# alert_ips -- what `lilith shodan_cache` reads. Distinct across both ends of
	# every table, windowed on each table's own time column.
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now(),?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', '1', '198.51.100.1', '10.0.0.5', 'Misc Attack', 'sig', '{}'
	);

	# the same pair again, to prove one address is one entry however many alerts
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now(),?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', '2', '198.51.100.1', '10.0.0.5', 'Misc Attack', 'sig', '{}'
	);

	# CAPE is windowed on stop rather than timestamp
	$dbh->do(
		q{insert into cape_alerts (instance,instance_host,target,task,malscore,stop,src_ip,raw)
		  values (?,?,?,?,?,now(),?,?)},
		undef, 's1', 's1.example.org', 't.msi', 7, 0.2, '198.51.100.2', '{}'
	);

	# and one outside any sane window, to prove the window bounds the read
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now() - interval '2 days',?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', '3', '198.51.100.99', '10.0.0.9', 'Misc Attack', 'sig', '{}'
	);

	is_deeply(
		$lilith->alert_ips( go_back_seconds => 600 ),
		[ '10.0.0.5', '198.51.100.1', '198.51.100.2' ],
		'alert_ips reads both ends of every table, deduped and windowed'
	);
	is_deeply( $lilith->alert_ips( go_back_seconds => 600, tables => ['cape'] ),
		['198.51.100.2'], 'alert_ips can be scoped to one table, on that table\'s own time column' );
	ok( scalar( grep { $_ eq '198.51.100.99' } @{ $lilith->alert_ips( go_back_seconds => 0 ) } ),
		'a window of 0 reads everything, however old' );
	ok( !scalar( grep { $_ eq '198.51.100.99' } @{ $lilith->alert_ips( go_back_seconds => 600 ) } ),
		'an alert outside the window is not read' );
	eval { $lilith->alert_ips( tables => ['nope'] ) };
	like( $@, qr/not a known table type/, 'alert_ips rejects an unknown table' );
	eval { $lilith->alert_ips( go_back_seconds => 'soon' ) };
	like( $@, qr/not numeric/, 'alert_ips rejects a non-numeric window' );

	# DeploymentHandler downgrades toward the schema's own version; see phase 3.
	{
		no warnings qw(redefine once);
		local $Lilith::Schema::VERSION = 14;
		my $down = DBIx::Class::Migration->new(
			schema_class => 'Lilith::Schema',
			schema_args  => [ $sc_dsn, $pg->user, $pg->pass ],
		);
		$down->dbic_dh->downgrade;    # 15 -> 14
	}
	ok( !table_exists( $dbh, 'shodan_cache' ), 'the 15 -> 14 downgrade dropped shodan_cache' );
	$dbh->disconnect;
}

$pg->stop;

done_testing;
