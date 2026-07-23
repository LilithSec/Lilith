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
	ok( $bc{event_type} && $bc{subject} && $bc{kur} && $bc{severity} && $bc{country},
		'columns(baphomet) lists its distinctive dimensions' );
	ok( $bc{src_ip} && $bc{dest_ip} && $bc{classification} && $bc{signature},
		'columns(baphomet) lists the reused dimensions' );
	ok( !$bc{raw}, 'columns(baphomet) omits non-dimension columns' );

	# measures() catalog (no database).
	my %sm = map { $_->{name} => $_->{label} } @{ $s->measures('suricata') };
	ok( $sm{count} && $sm{bytes} && $sm{distinct_dest_port}, 'suricata measures include count/bytes/fan-out' );
	is( $s->measures('suricata')->[0]{name}, 'count', 'count is the first measure' );
	my %cm = map { $_->{name} => 1 } @{ $s->measures('cape') };
	ok( $cm{avg_malscore} && !$cm{bytes}, 'cape measures reflect its columns' );
	my %bm = map { $_->{name} => 1 } @{ $s->measures('baphomet') };
	ok( $bm{avg_score} && $bm{max_score} && $bm{distinct_src_ip} && $bm{distinct_dest_ip},
		'baphomet measures include score aggregates and distinct-IP fan-out' );
	is( $s->measures('baphomet')->[0]{name}, 'count', 'baphomet count is the first measure' );

	# The time-window fragment: an absolute start/end range (quoted, cast) takes
	# precedence over the now-relative go_back_minutes. Uses a mock quote so no
	# database is needed.
	my $mock_dbh = bless {}, 'Lilith::Test::MockQuote';
	no warnings 'once';
	*Lilith::Test::MockQuote::quote = sub { my ( undef, $v ) = @_; return "'" . $v . "'"; };
	use warnings 'once';

	is( $s->_window_frag( $mock_dbh, 'timestamp', {}, 1440 ),
		"timestamp >= CURRENT_TIMESTAMP - interval '1440 minutes'", 'no range -> now-relative window' );
	is(
		$s->_window_frag( $mock_dbh, 'timestamp', { start => '2026-07-18 00:00', end => '2026-07-18 12:00' }, 1440 ),
		"timestamp >= '2026-07-18 00:00'::timestamptz and timestamp <= '2026-07-18 12:00'::timestamptz",
		'start+end -> a quoted, cast absolute range'
	);
	is( $s->_window_frag( $mock_dbh, 'stop', { start => '2026-07-18 00:00' }, 1440 ),
		"stop >= '2026-07-18 00:00'::timestamptz", 'start alone -> lower bound on the cape stop column' );
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
	# three banishes from 1.1.1.1 (scores 9/5/7), two sightings of a subject with
	# no ip (scores 2/4), one found from 2.2.2.2 (score 3).
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
			"insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,src_ip,subject,score,raw)"
				. " values ('k','h', now(), 'e', ?, ?, ?, ?, '{}')",
			undef, @$b
		);
	}

	is( $s->total( table => 'baphomet' ), 6, 'baphomet total counts the judgment rows' );
	is( $s->distinct( table => 'baphomet', column => 'src_ip' ),  2, 'baphomet distinct src_ip (nulls excluded)' );
	is( $s->distinct( table => 'baphomet', column => 'subject' ), 1, 'baphomet distinct subject' );
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
	$dbh->do( "insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,src_ip,subject,score,raw)"
			. " values ('k','h', now(), 'e', 'banish', '3.3.3.3', NULL, NULL, '{}')" );
	{
		my @warnings;
		local $SIG{__WARN__} = sub { push @warnings, $_[0] };
		is_deeply(
			$s->top( table => 'baphomet', column => 'src_ip', measure => 'max_score' ),
			[ { value => '1.1.1.1', count => 9 }, { value => '2.2.2.2', count => 3 }, { value => '3.3.3.3', count => 0 } ],
			'a null-score offender surfaces as max_score 0'
		);
		is( scalar(@warnings), 0, 'no uninitialized-value warning from a null aggregate' );
	}

	# escalated() reads the baphomet_alerts escalations array like the others
	is( $s->escalated( table => 'baphomet' ), 0, 'no baphomet rows escalated yet' );
	$dbh->do("update baphomet_alerts set escalations = '{1}' where event_type = 'found'");
	is( $s->escalated( table => 'baphomet' ), 1, 'escalated counts the flagged baphomet row' );

	$dbh->disconnect;
	$pg->stop;
} ## end SKIP:

done_testing;
