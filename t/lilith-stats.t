#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use_ok('Lilith::Stats') or BAIL_OUT('Lilith::Stats failed to load');

# ---------------------------------------------------------------------------
# Validation: every table/column/bucket/window is checked before any SQL runs,
# so these die without a database connection.
# ---------------------------------------------------------------------------
{
	my $s = Lilith::Stats->new(
		dsn  => 'dbi:Pg:dbname=none;host=127.0.0.1;port=1',
		user => 'x',
		pass => 'y',
	);

	eval { $s->total( table => 'bogus' ) };
	like( $@, qr/not a known table/, 'unknown table dies' );

	eval { $s->top( table => 'suricata' ) };
	like( $@, qr/a column is required/, 'top without a column dies' );

	eval { $s->top( table => 'suricata', column => 'raw' ) };
	like( $@, qr/not an aggregatable column/, 'a column not in the accepted set dies' );

	eval { $s->timeseries( table => 'suricata', bucket => 'century' ) };
	like( $@, qr/not a valid bucket/, 'bad bucket dies' );

	eval { $s->total( table => 'suricata', go_back_minutes => 'abc' ) };
	like( $@, qr/go_back_minutes/, 'non-numeric window dies' );

	eval { $s->top( table => 'suricata', column => 'classification', limit => '0' ) };
	like( $@, qr/positive integer limit/, 'non-positive limit dies' );

	# columns() exposes the accepted columns and needs no database.
	my %sc = map { $_ => 1 } @{ $s->columns('suricata') };
	ok( $sc{classification} && $sc{src_ip} && $sc{signature}, 'columns(suricata) lists the dimensions' );
	ok( !$sc{raw},                                            'columns omits non-dimension columns' );
	my %cc = map { $_ => 1 } @{ $s->columns('cape') };
	ok( $cc{target} && $cc{malscore} && !$cc{classification}, 'columns(cape) reflects the accepted cape columns' );
	my %sg = map { $_ => 1 } @{ $s->columns('sagan') };
	ok( $sc{severity}, 'severity is a (virtual) suricata dimension' );
	ok( $sc{mitre_tactic} && $sc{mitre_technique}, 'MITRE tactic/technique are suricata dimensions' );
	ok( !$sg{severity} && $sg{priority} && $sg{level},
		'sagan has no virtual severity (it uses the priority/level columns)' );
	ok( !$sg{mitre_tactic}, 'sagan has no MITRE dimension' );
	ok( !$cc{severity},     'severity is not offered for cape' );
	eval { $s->columns('bogus') };
	like( $@, qr/not a known table/, 'columns on an unknown table dies' );

	# baphomet exposes its own dimensions to the dashboard pickers.
	my %bc = map { $_ => 1 } @{ $s->columns('baphomet') };
	ok( $bc{event_type} && $bc{username} && $bc{kur} && $bc{severity} && $bc{country},
		'columns(baphomet) lists its distinctive dimensions' );
	ok( $bc{src_ip} && $bc{src_port} && $bc{dest_ip} && $bc{dest_port} && $bc{classification} && $bc{signature} && $bc{gid} && $bc{sid},
		'columns(baphomet) lists the reused dimensions' );
	ok( !$bc{raw}, 'columns(baphomet) omits non-dimension columns' );

	# Shodan enrichment. cape is not enriched, so shodan_src_tag is simply not one of
	# its columns and is refused before anything reaches the database. On the
	# tables that are enriched, whether the columns are offered depends on the
	# shodan_cache table being there, which cannot be checked with the database
	# down -- so they are left out rather than offered and then failing.
	eval { $s->top( table => 'cape', column => 'shodan_src_tag' ) };
	like( $@, qr/not an aggregatable column/, 'an enrichment column is refused for cape' );
	ok( !$sc{shodan_src_tag}, 'enrichment columns are omitted when the database cannot be asked about shodan_cache' );
	eval { $s->shodan_coverage( table => 'cape' ) };
	like( $@, qr/no Shodan enrichment/, 'shodan_coverage is refused for cape' );

	# measures() catalog (no database).
	my %sm = map { $_->{name} => $_->{label} } @{ $s->measures('suricata') };
	ok( $sm{count} && $sm{bytes} && $sm{distinct_dest_port}, 'suricata measures include count/bytes/fan-out' );
	is( $s->measures('suricata')->[0]{name}, 'count', 'count is the first measure' );
	my %cm = map { $_->{name} => 1 } @{ $s->measures('cape') };
	ok( $cm{avg_malscore} && !$cm{bytes}, 'cape measures reflect its columns' );
	my %bm = map { $_->{name} => 1 } @{ $s->measures('baphomet') };
	ok(
		$bm{avg_score} && $bm{max_score} && $bm{distinct_src_ip} && $bm{distinct_dest_ip},
		'baphomet measures include score aggregates and distinct-IP fan-out'
	);
	is( $s->measures('baphomet')->[0]{name}, 'count', 'baphomet count is the first measure' );

	# The time-window fragment: an absolute start/end range (quoted, cast) takes
	# precedence over the now-relative go_back_minutes. Uses a mock quote so no
	# database is needed.
	my $mock_dbh = bless {}, 'Lilith::Test::MockQuote';
	no warnings 'once';
	*Lilith::Test::MockQuote::quote = sub { my ( undef, $v ) = @_; return "'" . $v . "'"; };
	use warnings 'once';

	is(
		$s->_window_frag( $mock_dbh, 'timestamp', {}, 1440 ),
		"timestamp >= CURRENT_TIMESTAMP - interval '1440 minutes'",
		'no range -> now-relative window'
	);
	is(
		$s->_window_frag(
			$mock_dbh, 'timestamp', { start => '2026-07-18 00:00', end => '2026-07-18 12:00' }, 1440
		),
		"timestamp >= '2026-07-18 00:00'::timestamptz and timestamp <= '2026-07-18 12:00'::timestamptz",
		'start+end -> a quoted, cast absolute range'
	);
	is(
		$s->_window_frag( $mock_dbh, 'stop', { start => '2026-07-18 00:00' }, 1440 ),
		"stop >= '2026-07-18 00:00'::timestamptz",
		'start alone -> lower bound on the cape stop column'
	);
}

# ---------------------------------------------------------------------------
# Real aggregation against PostgreSQL. Skipped where the server binaries are
# absent.
# ---------------------------------------------------------------------------
SKIP: {
	require TestPG;
	skip 'PostgreSQL server binaries not found', 1 unless TestPG->bindir;

	require DBIx::Class::Migration;
	require Lilith::Schema;

	my $pg = TestPG->new;
	DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $pg->dsn, $pg->user, $pg->pass ],
	)->install;

	my $dbh = $pg->dbh;

	# Six recent Suricata alerts: classification A x4 (three from 1.1.1.1, one
	# from 2.2.2.2), B x2 (both from 1.1.1.1); plus one 3-day-old row.
	my @recent = (
		[ 'A', '1.1.1.1' ],
		[ 'A', '1.1.1.1' ],
		[ 'A', '1.1.1.1' ],
		[ 'A', '2.2.2.2' ],
		[ 'B', '1.1.1.1' ],
		[ 'B', '1.1.1.1' ],
	);
	for my $r (@recent) {
		$dbh->do(
			"insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,classification)"
				. " values ('i','h', now(), 'e', ?, ?)",
			undef, $r->[1], $r->[0]
		);
	}
	$dbh->do( "insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,classification)"
			. " values ('i','h', now() - interval '3 days', 'e', '9.9.9.9', 'C')" );

	# One recent CAPE detonation (windowed on 'stop', not 'timestamp').
	$dbh->do( "insert into cape_alerts (instance,target,instance_host,task,malscore,stop,raw)"
			. " values ('i','t','h', 1, 5, now(), '{}')" );

	my $s = Lilith::Stats->new( dsn => $pg->dsn, user => $pg->user, pass => $pg->pass );

	# total + windowing
	is( $s->total( table => 'suricata' ), 6, 'total counts the 6 recent rows (default 1440m window)' );
	is( $s->total( table => 'suricata', go_back_minutes => 100000 ), 7, 'a wide window also counts the old row' );

	# distinct
	is( $s->distinct( table => 'suricata', column => 'src_ip' ), 2, 'distinct src_ip over the recent rows' );

	# top
	is_deeply(
		$s->top( table => 'suricata', column => 'classification' ),
		[ { value => 'A', count => 4 }, { value => 'B', count => 2 } ],
		'top classification is ordered by count'
	);
	is_deeply(
		$s->top( table => 'suricata', column => 'src_ip' ),
		[ { value => '1.1.1.1', count => 5 }, { value => '2.2.2.2', count => 1 } ],
		'top src_ip casts inet to text and orders by count'
	);

	# timeseries (all recent rows land in one bucket within the test run)
	my $line       = $s->timeseries( table => 'suricata', bucket => 'hour' );
	my $line_total = 0;
	$line_total += $_->{count} for @$line;
	is( $line_total, 6, 'timeseries bucket counts sum to the recent total' );
	ok( $line->[0]{bucket} =~ /^[0-9]+$/, 'timeseries bucket is epoch seconds' );

	# grouped timeseries restricted to the single busiest classification (A)
	my $stack = $s->timeseries(
		table      => 'suricata',
		bucket     => 'hour',
		group_by   => 'classification',
		top_groups => 1,
	);
	my %groups = map { $_->{group} => 1 } @$stack;
	is_deeply( [ sort keys %groups ], ['A'], 'top_groups=1 keeps only the busiest group' );
	my $stack_total = 0;
	$stack_total += $_->{count} for @$stack;
	is( $stack_total, 4, 'grouped counts sum to that group\'s total' );

	# escalated counts rows with a non-empty escalations array
	is( $s->escalated( table => 'suricata' ), 0, 'nothing escalated yet' );
	$dbh->do("update suricata_alerts set escalations = '{1}' where classification = 'B'");
	is( $s->escalated( table => 'suricata' ), 2, 'escalated counts the two B rows once escalated' );

	# CAPE windows on stop
	is( $s->total( table => 'cape' ), 1, 'cape total windows on stop' );

	# exclude_classification: the dashboard's hide-GPCD toggle.
	$dbh->do( "insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,classification)"
			. " values ('i','h', now(), 'e', '3.3.3.3', 'Generic Protocol Command Decode')" );
	is( $s->total( table => 'suricata' ), 7, 'the GPCD row is counted by default' );
	is( $s->total( table => 'suricata', exclude_classification => 'Generic Protocol Command Decode' ),
		6, 'exclude_classification drops the GPCD row' );
	my %by_class = map { $_->{value} => $_->{count} } @{
		$s->top(
			table                  => 'suricata',
			column                 => 'classification',
			exclude_classification => 'Generic Protocol Command Decode'
		)
	};
	ok( !exists $by_class{'Generic Protocol Command Decode'}, 'excluded classification is absent from top' );
	is( $s->total( table => 'cape', exclude_classification => 'Generic Protocol Command Decode' ),
		1, 'exclude_classification is ignored for cape (no classification column)' );

	# severity: a virtual dimension read out of the raw EVE (raw->alert->severity),
	# with the numbers mapped to names and ordered by severity rank (High->Low)
	# rather than by count. One High and three Medium rows -- so if it ordered by
	# count, Medium would come first; ordered by rank, High comes first.
	# (The suricata rows above have no raw, so only these carry a severity.)
	for my $sev ( 1, 2, 2, 2 ) {
		$dbh->do(
			"insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,raw)"
				. " values ('i','h', now(), 'e', '4.4.4.4', ?::jsonb)",
			undef, "{\"alert\":{\"severity\":$sev}}"
		);
	}
	is_deeply(
		$s->top( table => 'suricata', column => 'severity' ),
		[ { value => 'High', count => 1 }, { value => 'Medium', count => 3 } ],
		'severity is named and ordered by rank (High before the more numerous Medium)'
	);
	is( $s->distinct( table => 'suricata', column => 'severity' ), 2, 'distinct severity' );

	# the severity timeseries orders its series by rank as well (High before the
	# more numerous Medium), not alphabetically or by count.
	my $sev_ts = $s->timeseries( table => 'suricata', bucket => 'hour', group_by => 'severity' );
	my ( @order, %seen );
	for my $r (@$sev_ts) { push( @order, $r->{group} ) unless $seen{ $r->{group} }++; }
	is_deeply( \@order, [ 'High', 'Medium' ], 'severity timeseries series are ordered by rank' );

	# MITRE: read from alert.metadata (single-element arrays of underscored names);
	# the label spaces them out. Two Command_And_Control, one Discovery.
	for my $tac ( 'Command_And_Control', 'Command_And_Control', 'Discovery' ) {
		$dbh->do(
			"insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,raw)"
				. " values ('i','h', now(), 'e', '5.5.5.5', ?::jsonb)",
			undef, "{\"alert\":{\"metadata\":{\"mitre_tactic_name\":[\"$tac\"]}}}"
		);
	}
	is_deeply(
		$s->top( table => 'suricata', column => 'mitre_tactic' ),
		[ { value => 'Command And Control', count => 2 }, { value => 'Discovery', count => 1 } ],
		'top mitre_tactic reads alert.metadata and spaces the underscored names'
	);

	# measures: two flows from 1.1.1.1 (300 + 100 bytes, dest ports 22/80) and one
	# from 2.2.2.2 (1000 bytes, port 443), in a fresh window/table for clean sums.
	my $mdsn = $pg->create_db('lilith_measures');
	my $md   = $pg->dbh($mdsn);
	DBIx::Class::Migration->new( schema_class => 'Lilith::Schema', schema_args => [ $mdsn, $pg->user, $pg->pass ] )
		->install;
	my @flows = ( [ '1.1.1.1', 22, 100, 200 ], [ '1.1.1.1', 80, 50, 50 ], [ '2.2.2.2', 443, 600, 400 ] );
	for my $f (@flows) {
		$md->do(
			"insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_port,flow_bytes_toserver,flow_bytes_toclient)"
				. " values ('i','h', now(), 'e', ?, ?, ?, ?)",
			undef, @$f
		);
	}
	my $ms = Lilith::Stats->new( dsn => $mdsn, user => $pg->user, pass => $pg->pass );
	is_deeply(
		$ms->top( table => 'suricata', column => 'src_ip', measure => 'bytes' ),
		[ { value => '2.2.2.2', count => 1000 }, { value => '1.1.1.1', count => 400 } ],
		'top by sum(bytes) is the top talker, ordered by the measure'
	);
	is_deeply(
		$ms->top( table => 'suricata', column => 'src_ip', measure => 'distinct_dest_port' ),
		[ { value => '1.1.1.1', count => 2 }, { value => '2.2.2.2', count => 1 } ],
		'top by distinct dest ports finds the fan-out'
	);
	my $bts    = $ms->timeseries( table => 'suricata', bucket => 'hour', measure => 'bytes' );
	my $btotal = 0;
	$btotal += $_->{count} for @$bts;
	is( $btotal, 1400, 'bytes timeseries sums the flow bytes' );
	eval { $ms->top( table => 'suricata', column => 'src_ip', measure => 'nope' ) };
	like( $@, qr/not a known measure/, 'an unknown measure dies' );
	$md->disconnect;

	# ---- baphomet: the same aggregation surface backs its dashboard --------
	# three banishes from 1.1.1.1 (scores 9/5/7), two sightings of a username
	# with no ip (scores 2/4), one found from 2.2.2.2 (score 3).
	my @baph = (
		[ 'banish',  '1.1.1.1', undef,     9 ],
		[ 'banish',  '1.1.1.1', undef,     5 ],
		[ 'banish',  '1.1.1.1', undef,     7 ],
		[ 'sighted', undef,     'baduser', 2 ],
		[ 'sighted', undef,     'baduser', 4 ],
		[ 'found',   '2.2.2.2', undef,     3 ],
	);
	for my $b (@baph) {
		$dbh->do(
			"insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,src_ip,username,score,raw)"
				. " values ('k','h', now(), 'e', ?, ?, ?, ?, '{}')",
			undef, @$b
		);
	}

	is( $s->total( table => 'baphomet' ), 6, 'baphomet total counts the judgment rows' );
	is( $s->distinct( table => 'baphomet', column => 'src_ip' ),   2, 'baphomet distinct src_ip (nulls excluded)' );
	is( $s->distinct( table => 'baphomet', column => 'username' ), 1, 'baphomet distinct username' );
	is_deeply(
		$s->top( table => 'baphomet', column => 'event_type' ),
		[ { value => 'banish', count => 3 }, { value => 'sighted', count => 2 }, { value => 'found', count => 1 } ],
		'baphomet top event_type ordered by count'
	);
	is_deeply(
		$s->top( table => 'baphomet', column => 'src_ip', measure => 'max_score' ),
		[ { value => '1.1.1.1', count => 9 }, { value => '2.2.2.2', count => 3 } ],
		'baphomet top offenders by max score'
	);

	# an offender whose judgments all carry a NULL score: max(score) is NULL in
	# SQL, which must surface as 0 rather than an uninitialized-value warning
	$dbh->do( "insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,src_ip,username,score,raw)"
			. " values ('k','h', now(), 'e', 'banish', '3.3.3.3', NULL, NULL, '{}')" );
	{
		my @warnings;
		local $SIG{__WARN__} = sub { push @warnings, $_[0] };
		is_deeply(
			$s->top( table => 'baphomet', column => 'src_ip', measure => 'max_score' ),
			[
				{ value => '1.1.1.1', count => 9 },
				{ value => '2.2.2.2', count => 3 },
				{ value => '3.3.3.3', count => 0 }
			],
			'a null-score offender surfaces as max_score 0'
		);
		is( scalar(@warnings), 0, 'no uninitialized-value warning from a null aggregate' );
	}

	# escalated() reads the baphomet_alerts escalations array like the others
	is( $s->escalated( table => 'baphomet' ), 0, 'no baphomet rows escalated yet' );
	$dbh->do("update baphomet_alerts set escalations = '{1}' where event_type = 'found'");
	is( $s->escalated( table => 'baphomet' ), 1, 'escalated counts the flagged baphomet row' );

	# ---- shodan enrichment ------------------------------------------------
	# Alerts cut by what shodan_cache holds about the addresses at either end. A
	# fresh database keeps the counts clean.
	#
	# sources:
	#   203.0.113.1  3 alerts, cached: tags compromised + scanner, one CVE at 9.5
	#   203.0.113.2  2 alerts, cached: tag vpn, no vulns
	#   203.0.113.3  1 alert,  cached as never crawled (found false)
	#   198.51.100.9 1 alert,  no cache row at all
	#
	# destinations: 192.0.2.50 on the first five, cached; 192.0.2.51 on the
	# sixth, uncached; and the seventh names none at all.
	my $edsn = $pg->create_db('lilith_enrich');
	my $ed   = $pg->dbh($edsn);
	DBIx::Class::Migration->new( schema_class => 'Lilith::Schema', schema_args => [ $edsn, $pg->user, $pg->pass ] )
		->install;

	my @ends = (
		( [ '203.0.113.1', '192.0.2.50' ] ) x 3,
		( [ '203.0.113.2', '192.0.2.50' ] ) x 2,
		[ '203.0.113.3',  '192.0.2.51' ],
		[ '198.51.100.9', undef ],
	);
	for my $end (@ends) {
		$ed->do(
			"insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification)"
				. " values ('i','h', now(), 'e', ?, ?, 'A')",
			undef, @{$end}
		);
	}
	my @cache = (
		[ '203.0.113.1', 1, '{compromised,scanner}', '{CVE-2021-1}', '{22,80}', '{cpe:/a:vendor:thing}', '9.5' ],
		[ '203.0.113.2', 1, '{vpn}',                 '{}',           '{443}',   '{}',                    undef ],
		[ '203.0.113.3', 0, undef,                   undef,          undef,     undef,                   undef ],
		[ '192.0.2.50',  1, '{cloud}',               '{}',           '{443}',   '{cpe:/a:vendor:web}',   undef ],
	);
	for my $c (@cache) {
		$ed->do(
			"insert into shodan_cache (ip,source,found,fetched,tags,vulns,ports,cpes,max_cvss)"
				. " values (?, 'api', ?, now(), ?, ?, ?, ?, ?)",
			undef, @$c
		);
	}

	my $es = Lilith::Stats->new( dsn => $edsn, user => $pg->user, pass => $pg->pass );

	my %ec = map { $_ => 1 } @{ $es->columns('suricata') };
	ok(
		$ec{shodan_src_tag}
			&& $ec{shodan_src_vuln}
			&& $ec{shodan_src_cpe}
			&& $ec{shodan_src_port}
			&& $ec{shodan_src_known}
			&& $ec{shodan_src_cvss},
		'enrichment columns are offered once the database has shodan_cache'
	);
	ok(
		$ec{shodan_dest_tag}
			&& $ec{shodan_dest_vuln}
			&& $ec{shodan_dest_cpe}
			&& $ec{shodan_dest_port}
			&& $ec{shodan_dest_known}
			&& $ec{shodan_dest_cvss},
		'and the same set for the far end'
	);
	my %ecc = map { $_ => 1 } @{ $es->columns('cape') };
	ok( !$ecc{shodan_src_tag} && !$ecc{shodan_dest_tag}, 'cape is not offered enrichment columns even so' );

	# An array dimension counts an alert once per element, so the three alerts
	# from a doubly tagged address land under both of its tags.
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_src_tag' ),
		[
			{ value => 'compromised', count => 3 },
			{ value => 'scanner',     count => 3 },
			{ value => 'vpn',         count => 2 }
		],
		'top shodan_src_tag unnests the tags of each alert\'s source'
	);
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_src_port' ),
		[ { value => '22', count => 3 }, { value => '80', count => 3 }, { value => '443', count => 2 } ],
		'top shodan_src_port renders the integer array as text'
	);
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_src_cpe' ),
		[ { value => 'cpe:/a:vendor:thing', count => 3 } ],
		'top shodan_src_cpe covers only the sources that have one'
	);
	is( $es->distinct( table => 'suricata', column => 'shodan_src_vuln' ),
		1, 'distinct shodan_src_vuln counts the CVEs seen' );
	is( $es->distinct( table => 'suricata', column => 'shodan_src_tag' ),
		3, 'distinct shodan_src_tag counts the tags seen' );

	# A scalar dimension joins outward, so every alert lands somewhere -- and
	# orders by its own rank rather than by count.
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_src_known' ),
		[
			{ value => 'Known to Shodan', count => 5 },
			{ value => 'Not on Shodan',   count => 1 },
			{ value => 'Not looked up',   count => 1 }
		],
		'top shodan_src_known accounts for every alert, ordered by rank'
	);
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_src_cvss' ),
		[
			{ value => 'Critical (9+)', count => 3 },
			{ value => 'None known',    count => 3 },
			{ value => 'Not looked up', count => 1 }
		],
		'top shodan_src_cvss bands the worst CVSS of each source, worst first'
	);

	# The far end is enriched from the same cache by its own join, so the two
	# sides of one alert answer differently -- and an alert naming no
	# destination drops out of a destination panel the way a source-less one
	# does out of a source panel.
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_dest_tag' ),
		[ { value => 'cloud', count => 5 } ],
		'top shodan_dest_tag reads the tags of what the alerts reached'
	);
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_dest_known' ),
		[ { value => 'Known to Shodan', count => 5 }, { value => 'Not looked up', count => 1 } ],
		'top shodan_dest_known leaves out the alert that names no destination'
	);
	is_deeply(
		$es->top( table => 'suricata', column => 'shodan_dest_cpe' ),
		[ { value => 'cpe:/a:vendor:web', count => 5 } ],
		'the two sides of the same alert resolve to different hosts'
	);

	# coverage: three of the four distinct sources have a cache row, and all
	# three were just written, so none of them has gone off yet
	is_deeply(
		$es->shodan_coverage( table => 'suricata' ),
		{ addresses => 4, enriched => 3, percent => 75, stale => 0, stale_percent => 0 },
		'shodan_coverage counts the enriched share of the window\'s sources'
	);
	is_deeply(
		$es->shodan_coverage( table => 'suricata', side => 'dest' ),
		{ addresses => 2, enriched => 1, percent => 50, stale => 0, stale_percent => 0 },
		'side => dest counts the same for the far end'
	);
	eval { $es->shodan_coverage( table => 'suricata', side => 'either' ) };
	like( $@, qr/is not a known side/, 'an unknown side dies' );

	# staleness follows the same rule the reads do: past the TTL, or from the
	# other tier than the one now configured.
	$ed->do("update shodan_cache set fetched = now() - interval '40 days' where ip = '203.0.113.1'");
	my $aged = $es->shodan_coverage( table => 'suricata', ttl => 2592000 );
	is( $aged->{stale},         1,  'an answer past the TTL is stale' );
	is( $aged->{stale_percent}, 33, 'stale_percent is of the answers held, not of the sources' );
	is( $es->shodan_coverage( table => 'suricata', ttl => 5184000 )->{stale},
		0, 'a longer TTL leaves the same answer standing' );
	is( $es->shodan_coverage( table => 'suricata', ttl => 0 )->{stale_percent},
		100, 'caching turned off leaves every answer stale' );
	is( $es->shodan_coverage( table => 'suricata', source => 'internetdb' )->{stale},
		3, 'every answer is stale against the tier it was not written by' );
	is( $es->shodan_coverage( table => 'suricata', source => 'api' )->{stale},
		1, 'and only the aged one against the tier it was' );
	eval { $es->shodan_coverage( table => 'suricata', ttl => 'soon' ) };
	like( $@, qr/for ttl is not a non-negative integer/, 'a non-numeric ttl dies' );
	$ed->do("update shodan_cache set fetched = now() where ip = '203.0.113.1'");

	# the timeseries splits the same way, and the array split is the one that
	# sums past the alert total
	my $known_ts    = $es->timeseries( table => 'suricata', bucket => 'hour', group_by => 'shodan_src_known' );
	my $known_total = 0;
	$known_total += $_->{count} for @$known_ts;
	is( $known_total, 7, 'a shodan_src_known timeseries covers every alert' );
	my $tag_ts    = $es->timeseries( table => 'suricata', bucket => 'hour', group_by => 'shodan_src_tag' );
	my $tag_total = 0;
	$tag_total += $_->{count} for @$tag_ts;
	is( $tag_total, 8, 'a shodan_src_tag timeseries counts an alert once per tag' );

	# a judgment naming no address has nothing for Shodan to describe, so it is
	# left out rather than counted as one that was never looked up
	$ed->do(  "insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,src_ip,username,score,raw)"
			. " values ('k','h', now(), 'e', 'banish', '203.0.113.1', NULL, 5, '{}')" );
	$ed->do(  "insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,src_ip,username,score,raw)"
			. " values ('k','h', now(), 'e', 'sighted', NULL, 'baduser', 2, '{}')" );
	is_deeply(
		$es->top( table => 'baphomet', column => 'shodan_src_known' ),
		[ { value => 'Known to Shodan', count => 1 } ],
		'a judgment with no source address is left out of an enrichment panel'
	);
	is_deeply(
		$es->shodan_coverage( table => 'baphomet' ),
		{ addresses => 1, enriched => 1, percent => 100, stale => 0, stale_percent => 0 },
		'shodan_coverage counts only the judgments that name an address'
	);
	$ed->disconnect;

	$dbh->disconnect;
	$pg->stop;
} ## end SKIP:

done_testing;
