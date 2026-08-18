#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith::Allani') or BAIL_OUT('Lilith::Allani failed to load');

# The reader reuses Allani::Sources for its accepted columns/filters; without Allani installed
# there is nothing to exercise, so skip the query-building assertions.
plan skip_all => 'Allani (Allani::Sources) is not installed'
	unless eval { require Allani::Sources; 1 };

# A mock DB handle that records the SQL it is asked to prepare and hands back a
# canned row, so search()/row() can be exercised without a live database.
#
# distinct() first asks the catalog whether a (column, timestamp) index exists,
# and takes a different path for each answer. $MockDbh::HAS_COMPOSITE decides
# what that probe returns, so both branches are reachable.
{

	package MockSth;
	sub new { return bless { sql => $_[1], drained => 0 }, $_[0] }

	sub execute { 1 }

	# Rows are handed back once and then exhausted: _run reads with
	# "while ( my $row = $sth->fetchrow_arrayref )", so a statement that always
	# had a row would never finish.
	sub fetchrow_arrayref {
		my $self = shift;
		return undef if $self->{drained}++;

		return ( $MockDbh::HAS_COMPOSITE ? [1] : undef ) if $self->{sql} =~ /FROM pg_index/;

		# the skip scan asks for ( values walked, values in window )
		return [ 3, 3 ] if $self->{sql} =~ /WITH RECURSIVE walk/;

		return undef;
	} ## end sub fetchrow_arrayref
	sub fetchrow_hashref  { return { id => 5, host => 'w1' } }
	sub fetchall_arrayref { return [] }
	sub finish            { 1 }

	package MockDbh;
	our @SQL;
	our $HAS_COMPOSITE = 0;

	# how many distinct values pg_stats claims for the column, which
	# skip_scan_viable checks after the index probe
	our $N_DISTINCT = 9;

	sub prepare {
		my ( $self, $sql ) = @_;
		push( @SQL, $sql );
		return MockSth->new($sql);
	}

	sub selectrow_array {
		my ( $self, $sql ) = @_;
		push( @SQL, $sql );
		return $sql =~ /n_distinct/ ? $N_DISTINCT : undef;
	}

	sub selectall_arrayref {
		my ( $self, $sql ) = @_;
		push( @SQL, $sql );
		return [];
	}
}
no warnings qw(redefine once);
local *Lilith::Allani::_dbh = sub { bless {}, 'MockDbh' };
use warnings qw(redefine once);

my $reader = Lilith::Allani->new( dsn => 'dbi:Pg:dbname=bogus' );

# ---------------------------------------------------------------------------
# http_all: the interleaved view's 'source' discriminator must be the selector
# keys (http / http_error), NOT the raw table names, so a result row's id links
# to a record view the reader understands.
# ---------------------------------------------------------------------------

{
	@MockDbh::SQL = ();
	$reader->search( source => 'http_all', filters => {} );
	my $sql = $MockDbh::SQL[0];

	like( $sql, qr/'http' AS source/,       "http_all tags http_access rows with the 'http' key" );
	like( $sql, qr/'http_error' AS source/, "http_all tags http_error rows with the 'http_error' key" );
	unlike( $sql, qr/'http_access' AS source/, 'the raw table name never leaks as the source discriminator' );
	like( $sql, qr/FROM http_access WHERE/, 'the http half still reads from http_access' );
	like( $sql, qr/UNION ALL/,              'the two halves are unioned' );
}

# ---------------------------------------------------------------------------
# The id-link path: a row() lookup for each key a result row can carry resolves
# to the right underlying table, and http_all is rejected (it has no record).
# ---------------------------------------------------------------------------

{
	@MockDbh::SQL = ();
	ok( $reader->row( 'http', 5 ), "row('http', 5) succeeds" );
	like( $MockDbh::SQL[-1], qr/FROM http_access WHERE id = \?/, "row('http') reads http_access" );

	ok( $reader->row( 'http_error', 5 ), "row('http_error', 5) succeeds" );
	like( $MockDbh::SQL[-1], qr/FROM http_error WHERE id = \?/, "row('http_error') reads http_error" );

	ok( $reader->row( 'syslog', 5 ), "row('syslog', 5) succeeds" );
	like( $MockDbh::SQL[-1], qr/FROM syslog WHERE id = \?/, "row('syslog') reads syslog" );

	eval { $reader->row( 'http_all', 5 ) };
	like( $@, qr/no single record view/, 'row(http_all) is rejected' );

	eval { $reader->row( 'bogus', 5 ) };
	like( $@, qr/not a known log source/, 'row() rejects an unknown source' );

	eval { $reader->row( 'syslog', 'abc' ) };
	like( $@, qr/invalid id/, 'row() rejects a non-numeric id' );
}

# ---------------------------------------------------------------------------
# filters() forwards only source-valid names, and every real-source query binds
# its filter values rather than interpolating them.
# ---------------------------------------------------------------------------

{
	is_deeply(
		$reader->filters('syslog'),
		[qw( facility host message priority program )],
		'syslog filters come from the Allani::Sources definitions plus message'
	);

	# message maps to raw->>'MESSAGE' (only syslog populates it), so the free-text
	# filter is offered for syslog and http_all but not the individual http tabs.
	ok( ( grep { $_ eq 'message' } @{ $reader->filters('http_all') } ), 'http_all offers the message filter' );
	ok( !( grep { $_ eq 'message' } @{ $reader->filters('http') } ),    'http does not offer the message filter' );
	ok( !( grep { $_ eq 'message' } @{ $reader->filters('http_error') } ),
		'http_error does not offer the message filter' );

	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', filters => { host => 'db1', program => 'sshd' } );
	my $sql = $MockDbh::SQL[0];
	like( $sql, qr/host = \?/,    'host filter is a bound placeholder' );
	like( $sql, qr/program = \?/, 'program filter is a bound placeholder' );
	unlike( $sql, qr/db1|sshd/, 'filter values are not interpolated into the SQL' );

	# several values for one filter are ORed in one group, per-value = / LIKE
	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', filters => { host => [ 'db1', 'db%' ] } );
	like(
		$MockDbh::SQL[0],
		qr/\(host = \? OR host LIKE \?\)/,
		'a multi-value filter ORs its values, LIKE per wildcard-carrying value'
	);

	# a value is taken literally: whitespace inside it no longer splits it
	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', filters => { host => 'db1 db2' } );
	unlike( $MockDbh::SQL[0], qr/host = \? OR/, 'whitespace inside a value does not split it' );

	# multi-value message: one ILIKE per value on the raw MESSAGE field, ANDed by
	# default -- each added term narrows the match -- and ORed with
	# message_match => 'OR'
	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', filters => { message => [ 'boom', 'oops' ] } );
	like(
		$MockDbh::SQL[0],
		qr/\(raw->>'MESSAGE' ILIKE \? AND raw->>'MESSAGE' ILIKE \?\)/,
		'multi-value message ANDs per-value substring matches by default'
	);

	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', filters => { message => [ 'boom', 'oops' ] }, message_match => 'OR' );
	like(
		$MockDbh::SQL[0],
		qr/\(raw->>'MESSAGE' ILIKE \? OR raw->>'MESSAGE' ILIKE \?\)/,
		q{message_match 'OR' ORs the message terms instead}
	);

	# an unrecognized message_match falls back to the AND default rather than
	# reaching the SQL
	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', filters => { message => [ 'boom', 'oops' ] }, message_match => 'bogus' );
	like(
		$MockDbh::SQL[0],
		qr/\(raw->>'MESSAGE' ILIKE \? AND raw->>'MESSAGE' ILIKE \?\)/,
		'an unrecognized message_match falls back to AND'
	);

	# a filter the source does not accept dies rather than being ignored
	eval { $reader->search( source => 'syslog', filters => { vhost => 'w1' } ) };
	like( $@, qr/not a valid filter/, 'a filter invalid for the source is rejected' );

	# http_all applies a multi-value filter to both halves of the union
	@MockDbh::SQL = ();
	$reader->search( source => 'http_all', filters => { client_ip => [ '192.0.2.1', '192.0.2.2' ] } );
	my @groups = ( $MockDbh::SQL[0] =~ /\(client_ip = \? OR client_ip = \?\)/g );
	is( scalar @groups, 2, 'http_all ORs a multi-value filter in both halves' );
}

# ---------------------------------------------------------------------------
# Time anchor: around + window_minutes give a BETWEEN window (binding the
# timestamp, not interpolating it) instead of the now-relative comparison.
# ---------------------------------------------------------------------------

{
	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', around => '2026-07-17T00:00:00', window_minutes => 30 );
	my $sql = $MockDbh::SQL[0];
	like(
		$sql,
		qr/r_isodate BETWEEN \?::timestamptz - interval '30 minutes' AND \?::timestamptz \+ interval '30 minutes'/,
		'anchored syslog window is a BETWEEN sized by window_minutes, on the aggregator receive time'
	);
	unlike( $sql, qr/now\(\) - interval/, 'anchored window is not now-relative' );
	unlike( $sql, qr/2026-07-17/,         'the anchor timestamp is bound, not interpolated' );

	@MockDbh::SQL = ();
	$reader->search( source => 'http_all', around => '2026-07-17T00:00:00', window_minutes => 15 );
	my @between = ( $MockDbh::SQL[0] =~ /BETWEEN/g );
	is( scalar @between, 2, 'http_all anchors both halves of the union' );
}

# ---------------------------------------------------------------------------
# Dashboard aggregation: dims(), total(), top(), timeseries() build the right
# SQL and check their inputs against Allani::Sources.
# ---------------------------------------------------------------------------

{
	is_deeply(
		$reader->dims('syslog'),
		[qw( program facility host host_from priority )],
		'syslog dims list default_dim first, then the rest sorted'
	);
	is_deeply( $reader->dims('http_all'), [], 'http_all has no aggregate dims' );

	@MockDbh::SQL = ();
	$reader->total( source => 'syslog', go_back_minutes => 60 );
	like( $MockDbh::SQL[0], qr/SELECT count\(\*\) FROM syslog WHERE/, 'total counts the source table' );

	@MockDbh::SQL = ();
	$reader->top( source => 'syslog', column => 'program', limit => 5 );
	like( $MockDbh::SQL[0], qr/GROUP BY program ORDER BY count DESC/, 'top groups by the dimension' );
	like( $MockDbh::SQL[0], qr/LIMIT \?/,                             'top binds the limit' );

	@MockDbh::SQL = ();
	$reader->timeseries( source => 'syslog', bucket => 'day' );
	like(
		$MockDbh::SQL[0],
		qr/date_trunc\('day', r_isodate\)/,
		'timeseries buckets by the chosen unit, on the aggregator receive time'
	);

	eval { $reader->top( source => 'syslog', column => 'raw' ) };
	like( $@, qr/not an aggregatable column/, 'top rejects a non-dimension column' );
	eval { $reader->timeseries( source => 'syslog', bucket => 'century' ) };
	like( $@, qr/not a valid bucket/, 'timeseries rejects a bad bucket' );
	eval { $reader->total( source => 'http_all' ) };
	like( $@, qr/no aggregate view/, 'aggregation rejects http_all' );

	# distinct() has two paths. Without a (column, timestamp) index it counts the
	# rows; with one it walks the index instead. The wrong index is worse than
	# none -- a (column, id) index makes the walk slower than the count it
	# replaces -- so what is really being guarded here is that the probe asks for
	# the timestamp as the second key, and that a "no" means falling back.
	{
		local $MockDbh::HAS_COMPOSITE = 0;
		@MockDbh::SQL = ();
		$reader->distinct( source => 'syslog', column => 'host' );
		like( $MockDbh::SQL[0], qr/FROM pg_index/, 'distinct asks whether a usable index exists' );
		like(
			$MockDbh::SQL[0],
			qr/first\.attname = \?.*second\.attname = \?/s,
			'the probe pins both the column and the timestamp position'
		);
		like(
			$MockDbh::SQL[-1],
			qr/SELECT count\(distinct host\) FROM syslog WHERE/,
			'distinct counts the rows when no such index exists'
		);
		is( scalar @MockDbh::SQL, 2, 'and issues nothing else -- no pg_stats lookup once the index rules it out' );
	}

	{
		# a fresh reader, because the probe's answer is cached per object for its
		# lifetime and the block above has already cached "no" for syslog/host
		local $MockDbh::HAS_COMPOSITE = 1;
		my $indexed = Lilith::Allani->new( dsn => 'dbi:Pg:dbname=bogus' );

		@MockDbh::SQL = ();
		my $count = $indexed->distinct( source => 'syslog', column => 'host' );
		like( $MockDbh::SQL[-1], qr/WITH RECURSIVE walk/, 'distinct walks the index when one exists' );
		unlike( $MockDbh::SQL[-1], qr/count\(distinct/, 'and does not count the rows as well' );
		is( $count, 3, 'the walked value count is what comes back' );

		# the catalog answer is cached: a second call must not probe again
		@MockDbh::SQL = ();
		$indexed->distinct( source => 'syslog', column => 'host' );
		is( scalar( grep { /FROM pg_index/ } @MockDbh::SQL ), 0, 'the index probe is cached, not repeated' );
	}

	# auto bucket sizes to the window; an explicit unit passes through
	is( $reader->bucket( 'auto', 60 ),      'minute', 'auto: <=3h window -> minute' );
	is( $reader->bucket( 'auto', 1440 ),    'hour',   'auto: day window -> hour' );
	is( $reader->bucket( 'auto', 10000 ),   'day',    'auto: ~7d window -> day' );
	is( $reader->bucket( 'auto', 2000000 ), 'month',  'auto: multi-year window -> month' );
	is( $reader->bucket( 'day',  60 ),      'day',    'an explicit bucket passes through' );

	@MockDbh::SQL = ();
	$reader->timeseries( source => 'syslog', bucket => 'auto', go_back_minutes => 60 );
	like( $MockDbh::SQL[0], qr/date_trunc\('minute', r_isodate\)/, 'auto bucket is applied to the query' );
}

# ---------------------------------------------------------------------------
# Measures, stacked split, and source-IP aggregation.
# ---------------------------------------------------------------------------

{
	is_deeply(
		$reader->measures('http'),
		[ { name => 'count', label => 'Count' }, { name => 'bytes', label => 'Total bytes' } ],
		'http_access offers count + bytes measures'
	);
	is_deeply( $reader->measures('syslog'),   [ { name => 'count', label => 'Count' } ], 'syslog offers count only' );
	is_deeply( $reader->measures('http_all'), [],                                        'http_all has no measures' );

	# bytes measure sums the column instead of counting rows; the shared
	# measure_expr helper coalesces the sum to 0 so an all-null/empty group
	# reads as 0 rather than NULL.
	@MockDbh::SQL = ();
	$reader->top( source => 'http', column => 'vhost', measure => 'bytes' );
	like( $MockDbh::SQL[0], qr/coalesce\(sum\(bytes\), 0\) AS count/, 'bytes measure sums the column' );
	like( $MockDbh::SQL[0], qr/FROM http_access/,                     'http source reads http_access' );

	eval { $reader->top( source => 'http', column => 'vhost', measure => 'nope' ) };
	like( $@, qr/not a known measure/, 'an unknown measure is rejected' );
	eval { $reader->top( source => 'syslog', column => 'program', measure => 'bytes' ) };
	like( $@, qr/not a known measure/, 'bytes is not a measure for syslog' );

	# Stacked split: bucket every group once, then keep the busiest k. The
	# busiest are ranked from the bucketed counts rather than by a second look at
	# the table, so the window is only walked once -- the whole point of the
	# shape, and what these assertions are really guarding.
	@MockDbh::SQL = ();
	$reader->timeseries( source => 'syslog', group_by => 'program', top_groups => 3 );
	my $sql = $MockDbh::SQL[0];
	like( $sql, qr/\(program\)::text AS grp/,   'grouped timeseries carries the group value' );
	like( $sql, qr/AS "group"/,                 'grouped timeseries projects it as group' );
	like( $sql, qr/GROUP BY 1, 2/,              'grouped timeseries groups by bucket and group' );
	like( $sql, qr/ORDER BY sum\(count\) DESC/, 'grouped timeseries ranks groups by their totals' );
	like( $sql, qr/JOIN busiest USING \(grp\)/, 'grouped timeseries restricts to top-k groups' );

	# the window clause must appear once: twice would mean the table is being
	# read a second time just to find the busiest groups
	my $window_count = () = $sql =~ /r_isodate >= now\(\)/g;
	is( $window_count, 1, 'grouped timeseries walks the window once, not twice' );

	# top_ips reads the source's IP column, not a dimension
	@MockDbh::SQL = ();
	$reader->top_ips( source => 'syslog' );
	like( $MockDbh::SQL[0], qr/host\(sourceip\) AS value.*FROM syslog/, 'top_ips uses host(sourceip) for syslog' );
	@MockDbh::SQL = ();
	$reader->top_ips( source => 'http' );
	like( $MockDbh::SQL[0], qr/host\(client_ip\) AS value.*FROM http_access/, 'top_ips uses host(client_ip) for http' );
}

# ---------------------------------------------------------------------------
# Absolute range: start/end bind bounds (server-local cast) and take precedence
# over an anchor and the now-relative window.
# ---------------------------------------------------------------------------

{
	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', start => '2026-07-18 00:00', end => '2026-07-18 12:00' );
	my $sql = $MockDbh::SQL[0];
	like(
		$sql,
		qr/r_isodate >= \?::timestamptz AND r_isodate <= \?::timestamptz/,
		'start+end bind an absolute range on the aggregator receive time column'
	);
	unlike( $sql, qr/now\(\) - interval/, 'an absolute range is not now-relative' );
	unlike( $sql, qr/2026-07-18/,         'the bounds are bound, not interpolated' );

	@MockDbh::SQL = ();
	$reader->search( source => 'syslog', start => '2026-07-18 00:00' );
	like( $MockDbh::SQL[0], qr/r_isodate >= \?::timestamptz/, 'start alone is a lower bound' );
	unlike( $MockDbh::SQL[0], qr/<= \?::timestamptz/, 'and adds no upper bound' );

	@MockDbh::SQL = ();
	$reader->search(
		source         => 'syslog',
		start          => '2026-07-18 00:00',
		around         => '2026-07-18 06:00',
		window_minutes => 30
	);
	unlike( $MockDbh::SQL[0], qr/BETWEEN/, 'start/end take precedence over an anchor' );
}

done_testing();
