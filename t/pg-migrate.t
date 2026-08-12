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

	# versions 15 and 16: the two lookup caches.
	ok( table_exists( $dbh, 'shodan_cache' ), 'deploy created shodan_cache' );
	ok( table_exists( $dbh, 'cvedb_cache' ),  'deploy created cvedb_cache' );

	# the version-16 suricata side: the cves generated column and the function
	# behind it
	ok( column_exists( $dbh, 'suricata_alerts', 'cves' ), 'deploy created the cves column' );
	my ($cves_fn) = $dbh->selectrow_array(q{select count(*) from pg_proc where proname = 'suricata_alert_cves'});
	is( $cves_fn, 1, 'deploy created the suricata_alert_cves function' );
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
	ok( table_exists( $dbh, 'cvedb_cache' ),                  'the 15 -> 16 upgrade created cvedb_cache' );
	ok( column_exists( $dbh, 'suricata_alerts', 'cves' ),     'the 15 -> 16 upgrade added the cves column' );
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
	ok( !table_exists( $dbh, 'cvedb_cache' ),  'cvedb_cache absent at version 14' );

	$mig->dbic_dh->upgrade;    # 14 -> 16, through 15
	ok( table_exists( $dbh, 'shodan_cache' ), 'the 14 -> 15 upgrade created shodan_cache' );
	for my $column (qw( ip source found fetched last_update ports tags cpes vulns max_cvss hostnames raw )) {
		ok( column_exists( $dbh, 'shodan_cache', $column ), "shodan_cache has the $column column" );
	}

	# and the 15 -> 16 step in the same chain: the CVEDB cache, and the cves
	# generated column beside it.
	ok( table_exists( $dbh, 'cvedb_cache' ), 'the 15 -> 16 upgrade created cvedb_cache' );
	for my $column (qw( cve found fetched cvss epss kev ransomware raw )) {
		ok( column_exists( $dbh, 'cvedb_cache', $column ), "cvedb_cache has the $column column" );
	}
	ok( column_exists( $dbh, 'suricata_alerts', 'cves' ), 'the 15 -> 16 upgrade added the cves column' );

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

	# The CVEDB cache methods against the table the migration actually creates
	# -- as with shodan_cache_put above, the SQL in cvedb_cache_put is the only
	# place its column list and upsert have to agree with the DDL.
	is_deeply(
		$lilith->cvedb_cache_stale( cves => [ 'CVE-2021-40438', 'CVE-2019-0217' ], ttl => 3600 ),
		[ 'CVE-2021-40438', 'CVE-2019-0217' ],
		'ids never cached are all due, in input order'
	);

	$lilith->cvedb_cache_put(
		cve  => 'CVE-2021-40438',
		raw  => { cvss => 9.8, epss => 0.97, kev => 1, ransomware_campaign => 'Known', summary => 'mod_proxy SSRF' },
		info => { cvss => 9.8, epss => 0.97, kev => 1, ransomware => 1 },
	);
	my $notes = $lilith->cvedb_cache_annotations( cves => [ 'CVE-2021-40438', 'CVE-2019-0217' ] );
	is( scalar keys %{$notes}, 1, 'only ids with a row come back' );
	ok( !exists $notes->{'CVE-2019-0217'}, 'an id never asked about is absent rather than empty' );
	is( $notes->{'CVE-2021-40438'}{cvss} + 0,   9.8,              'the annotation carries the score' );
	is( $notes->{'CVE-2021-40438'}{epss} + 0,   0.97,             'the annotation carries the EPSS' );
	is( $notes->{'CVE-2021-40438'}{kev},        1,                'the annotation carries the KEV flag' );
	is( $notes->{'CVE-2021-40438'}{ransomware}, 1,                'the annotation carries the ransomware flag' );
	is( $notes->{'CVE-2021-40438'}{summary},    'mod_proxy SSRF', 'the summary is read out of the stored response' );
	is( $notes->{'CVE-2021-40438'}{found},      1,                'a real answer is found' );

	# An id CVEDB has nothing on is cached too, as an empty response, and is a
	# row marked not found rather than a miss.
	$lilith->cvedb_cache_put( cve => 'CVE-2019-0217', raw => {}, info => {} );
	is( $lilith->cvedb_cache_annotations( cves => ['CVE-2019-0217'] )->{'CVE-2019-0217'}{found},
		0, 'a cached "nothing known" is a row, marked not found' );

	# Freshness: nothing fresh is due, and what is due comes never-seen first,
	# then oldest first -- the order a --limit capped run truncates.
	is_deeply( $lilith->cvedb_cache_stale( cves => [ 'CVE-2021-40438', 'CVE-2019-0217' ], ttl => 3600 ),
		[], 'fresh rows are not due' );
	$dbh->do(q{update cvedb_cache set fetched = now() - interval '3 hours' where cve = 'CVE-2021-40438'});
	$dbh->do(q{update cvedb_cache set fetched = now() - interval '2 hours' where cve = 'CVE-2019-0217'});
	is_deeply(
		$lilith->cvedb_cache_stale( cves => [ 'CVE-2019-0217', 'CVE-2021-40438', 'CVE-2024-99999' ], ttl => 3600 ),
		[ 'CVE-2024-99999', 'CVE-2021-40438', 'CVE-2019-0217' ],
		'never-seen ids lead, then stale rows oldest first'
	);
	eval { $lilith->cvedb_cache_stale( cves => ['CVE-2019-0217'], ttl => 'soon' ) };
	like( $@, qr/not numeric/, 'cvedb_cache_stale rejects a non-numeric ttl' );

	# The upsert replaces rather than duplicating, and re-reads as the new
	# value.
	$lilith->cvedb_cache_put( cve => 'CVE-2019-0217', raw => { cvss => 7.5 }, info => { cvss => 7.5 } );
	my ($cvedb_rows) = $dbh->selectrow_array(q{select count(*) from cvedb_cache where cve = 'CVE-2019-0217'});
	is( $cvedb_rows, 1, 'a second write for an id replaces the first' );
	is( $lilith->cvedb_cache_annotations( cves => ['CVE-2019-0217'] )->{'CVE-2019-0217'}{cvss} + 0,
		7.5, 'the replacement is what is served' );

	# shodan_cache_cves -- what `lilith cvedb_cache` reads: the distinct ids
	# across every row, sorted.
	$lilith->shodan_cache_put(
		ip     => '192.0.2.20',
		source => 'internetdb',
		raw    => { vulns => [ 'CVE-2021-40438',            'CVE-2019-0217' ] },
		info   => { vulns => [ { cve => 'CVE-2021-40438' }, { cve => 'CVE-2019-0217' } ] },
		ttl    => 3600,
	);
	is_deeply(
		$lilith->shodan_cache_cves,
		[ 'CVE-2019-0217', 'CVE-2021-40438' ],
		'shodan_cache_cves reads the distinct ids, sorted'
	);

	# The badge read falls back to the CVEDB cache for rows Shodan itself did
	# not score -- the keyless tier never does -- which is what colors the CVE
	# badge on an InternetDB-only install.
	my $keyless = $lilith->shodan_cache_badges( ips => ['192.0.2.20'], source => 'internetdb', ttl => 3600 );
	is( $keyless->{'192.0.2.20'}{max_cvss} + 0, 9.8, 'a keyless row borrows the worst CVEDB score its CVEs carry' );

	# The window: a row fetched outside it contributes nothing, and 0 reads
	# the whole table.
	$dbh->do(q{update shodan_cache set fetched = now() - interval '2 days' where ip = '192.0.2.20'});
	is_deeply( $lilith->shodan_cache_cves, [], 'a row fetched outside the window contributes nothing' );
	is_deeply(
		$lilith->shodan_cache_cves( go_back_seconds => 0 ),
		[ 'CVE-2019-0217', 'CVE-2021-40438' ],
		'a window of 0 reads the whole table'
	);
	eval { $lilith->shodan_cache_cves( go_back_seconds => 'soon' ) };
	like( $@, qr/not numeric/, 'shodan_cache_cves rejects a non-numeric window' );

	# The version-16 suricata side, live: the cves generated column computes
	# from raw on insert (the upgrade-created function at work), and everything
	# comparing it against the cache runs against the real DDL -- the badges'
	# vuln_ids, the whole-row read the event view strip renders from, the
	# enrichment search filters, and the cve_match dashboard dimension.
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now(),?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', 'cve1', '203.0.113.60', '198.51.100.60', 'Attempted Admin',
		'ET EXPLOIT log4j', '{"alert":{"metadata":{"cve":["CVE_2021_44228"]},"signature":"ET EXPLOIT log4j"}}'
	);
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now(),?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', 'cve2', '203.0.113.61', '198.51.100.60', 'Attempted Admin',
		'ET EXPLOIT shellshock',
		'{"alert":{"metadata":{"cve":["CVE-2014-6271"]},"signature":"ET EXPLOIT shellshock"}}'
	);
	is_deeply( $dbh->selectrow_arrayref(q{select cves from suricata_alerts where event_id = 'cve1'})->[0],
		['CVE-2021-44228'], 'the cves generated column normalizes what the rule named' );

	$lilith->shodan_cache_put(
		ip     => '198.51.100.60',
		source => 'internetdb',
		raw    => { ports => [80], tags => ['tor'], vulns => ['CVE-2021-44228'] },
		info   => { ports => [80], tags => ['tor'], vulns => [ { cve => 'CVE-2021-44228' } ] },
		ttl    => 3600,
	);

	# the badges carry the ids themselves, for the CVE-match comparison
	my $match_badges = $lilith->shodan_cache_badges( ips => ['198.51.100.60'], source => 'internetdb', ttl => 3600 );
	is_deeply( $match_badges->{'198.51.100.60'}{vuln_ids},
		['CVE-2021-44228'], 'the badge read carries the ids themselves as vuln_ids' );

	# the whole-row read the event view strip renders from
	my $strip_info = $lilith->shodan_cache_info( ips => ['198.51.100.60'], source => 'internetdb', ttl => 3600 );
	is( $strip_info->{'198.51.100.60'}{found}, 1, 'shodan_cache_info reads the row back' );
	ok( $strip_info->{'198.51.100.60'}{age_seconds} < 60, 'age_seconds carries the age of the fetch' );
	is_deeply( $strip_info->{'198.51.100.60'}{raw}{tags}, ['tor'], 'and the response as it arrived' );
	is_deeply( $lilith->shodan_cache_info( ips => ['198.51.100.61'], source => 'internetdb', ttl => 3600 ),
		{}, 'an address never cached is absent from the info read' );

	# the enrichment search filters against the real tables
	is_deeply(
		[
			sort map { $_->{event_id} }
				@{ $lilith->search( table => 'suricata', go_back_minutes => 60, shodan_dest_tag => 'tor' ) }
		],
		[ 'cve1', 'cve2' ],
		'shodan_dest_tag finds the alerts against the tagged host'
	);
	is_deeply(
		[
			map { $_->{event_id} }
				@{ $lilith->search( table => 'suricata', go_back_minutes => 60, cve => 'cve_2021_44228' ) }
		],
		['cve1'],
		'the cve filter normalizes its value and matches the generated column'
	);

	# and the dimension correlating the two: cve1 is the exploit thrown at a
	# host actually vulnerable to it
	require Lilith::Stats;
	my $stats         = Lilith::Stats->new( lilith => $lilith );
	my %match_buckets = map { $_->{value} => $_->{count} }
		@{ $stats->top( table => 'suricata', column => 'shodan_dest_cve_match', go_back_minutes => 60 ) };
	is( $match_buckets{'Matched'},     1, 'the cve_match dimension counts the matched alert' );
	is( $match_buckets{'Not matched'}, 1, 'and buckets the rule whose CVE the host does not carry' );

	# DeploymentHandler downgrades toward the schema's own version; see phase 3.
	{
		no warnings qw(redefine once);
		local $Lilith::Schema::VERSION = 14;
		my $down = DBIx::Class::Migration->new(
			schema_class => 'Lilith::Schema',
			schema_args  => [ $sc_dsn, $pg->user, $pg->pass ],
		);
		$down->dbic_dh->downgrade;    # 16 -> 14, through 15
	}
	ok( !table_exists( $dbh, 'cvedb_cache' ),  'the 16 -> 15 downgrade dropped cvedb_cache' );
	ok( !table_exists( $dbh, 'shodan_cache' ), 'the 15 -> 14 downgrade dropped shodan_cache' );
	ok( !column_exists( $dbh, 'suricata_alerts', 'cves' ), 'the 16 -> 15 downgrade dropped the cves column' );
	my ($cves_fn_after) = $dbh->selectrow_array(q{select count(*) from pg_proc where proname = 'suricata_alert_cves'});
	is( $cves_fn_after, 0, 'and the function behind it' );
	$dbh->disconnect;
}

$pg->stop;

done_testing;
