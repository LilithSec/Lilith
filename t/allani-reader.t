#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith::Allani') or BAIL_OUT('Lilith::Allani failed to load');

# The reader reuses Allani::Sources for its whitelist; without Allani installed
# there is nothing to exercise, so skip the query-building assertions.
plan skip_all => 'Allani (Allani::Sources) is not installed'
    unless eval { require Allani::Sources; 1 };

# A mock DB handle that records the SQL it is asked to prepare and hands back a
# canned row, so search()/row() can be exercised without a live database.
{
    package MockSth;
    sub execute           { 1 }
    sub fetchrow_arrayref { undef }
    sub fetchrow_hashref  { return { id => 5, host => 'w1' } }
    sub fetchall_arrayref { return [] }
    sub finish            { 1 }

    package MockDbh;
    our @SQL;
    sub prepare { push @SQL, $_[1]; return bless {}, 'MockSth' }
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
    ok( $reader->row( 'http', 5 ),       "row('http', 5) succeeds" );
    like( $MockDbh::SQL[-1], qr/FROM http_access WHERE id = \?/, "row('http') reads http_access" );

    ok( $reader->row( 'http_error', 5 ), "row('http_error', 5) succeeds" );
    like( $MockDbh::SQL[-1], qr/FROM http_error WHERE id = \?/, "row('http_error') reads http_error" );

    ok( $reader->row( 'syslog', 5 ),     "row('syslog', 5) succeeds" );
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
    is_deeply( $reader->filters('syslog'), [qw( facility host message priority program )],
        'syslog filters come from the Allani::Sources whitelist plus message' );

    # message maps to raw->>'MESSAGE' (only syslog populates it), so the free-text
    # filter is offered for syslog and http_all but not the individual http tabs.
    ok( ( grep { $_ eq 'message' } @{ $reader->filters('http_all') } ), 'http_all offers the message filter' );
    ok( !( grep { $_ eq 'message' } @{ $reader->filters('http') } ), 'http does not offer the message filter' );
    ok( !( grep { $_ eq 'message' } @{ $reader->filters('http_error') } ),
        'http_error does not offer the message filter' );

    @MockDbh::SQL = ();
    $reader->search( source => 'syslog', filters => { host => 'db1', program => 'sshd' } );
    my $sql = $MockDbh::SQL[0];
    like( $sql, qr/host = \?/,      'host filter is a bound placeholder' );
    like( $sql, qr/program = \?/,   'program filter is a bound placeholder' );
    unlike( $sql, qr/db1|sshd/,     'filter values are not interpolated into the SQL' );
}

# ---------------------------------------------------------------------------
# Time anchor: around + window_minutes give a BETWEEN window (binding the
# timestamp, not interpolating it) instead of the now-relative comparison.
# ---------------------------------------------------------------------------

{
    @MockDbh::SQL = ();
    $reader->search( source => 'syslog', around => '2026-07-17T00:00:00', window_minutes => 30 );
    my $sql = $MockDbh::SQL[0];
    like( $sql,
        qr/s_isodate BETWEEN \?::timestamptz - interval '30 minutes' AND \?::timestamptz \+ interval '30 minutes'/,
        'anchored syslog window is a BETWEEN sized by window_minutes' );
    unlike( $sql, qr/now\(\) - interval/, 'anchored window is not now-relative' );
    unlike( $sql, qr/2026-07-17/,         'the anchor timestamp is bound, not interpolated' );

    @MockDbh::SQL = ();
    $reader->search( source => 'http_all', around => '2026-07-17T00:00:00', window_minutes => 15 );
    my @between = ( $MockDbh::SQL[0] =~ /BETWEEN/g );
    is( scalar @between, 2, 'http_all anchors both halves of the union' );
}

# ---------------------------------------------------------------------------
# Dashboard aggregation: dims(), total(), top(), timeseries() build the right
# SQL and whitelist their inputs against Allani::Sources.
# ---------------------------------------------------------------------------

{
    is_deeply( $reader->dims('syslog'), [qw( program facility host host_from priority )],
        'syslog dims list default_dim first, then the rest sorted' );
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
    like( $MockDbh::SQL[0], qr/date_trunc\('day', s_isodate\)/, 'timeseries buckets by the chosen unit' );

    eval { $reader->top( source => 'syslog', column => 'raw' ) };
    like( $@, qr/not an aggregatable column/, 'top rejects a non-dimension column' );
    eval { $reader->timeseries( source => 'syslog', bucket => 'century' ) };
    like( $@, qr/not a valid bucket/, 'timeseries rejects a bad bucket' );
    eval { $reader->total( source => 'http_all' ) };
    like( $@, qr/no aggregate view/, 'aggregation rejects http_all' );

    @MockDbh::SQL = ();
    $reader->distinct( source => 'syslog', column => 'host' );
    like( $MockDbh::SQL[0], qr/SELECT count\(distinct host\) FROM syslog WHERE/,
        'distinct counts distinct dimension values' );

    # auto bucket sizes to the window; an explicit unit passes through
    is( $reader->bucket( 'auto', 60 ),      'minute', 'auto: <=3h window -> minute' );
    is( $reader->bucket( 'auto', 1440 ),    'hour',   'auto: day window -> hour' );
    is( $reader->bucket( 'auto', 10000 ),   'day',    'auto: ~7d window -> day' );
    is( $reader->bucket( 'auto', 2000000 ), 'month',  'auto: multi-year window -> month' );
    is( $reader->bucket( 'day',  60 ),      'day',    'an explicit bucket passes through' );

    @MockDbh::SQL = ();
    $reader->timeseries( source => 'syslog', bucket => 'auto', go_back_minutes => 60 );
    like( $MockDbh::SQL[0], qr/date_trunc\('minute', s_isodate\)/, 'auto bucket is applied to the query' );
}

# ---------------------------------------------------------------------------
# Measures, stacked split, and source-IP aggregation.
# ---------------------------------------------------------------------------

{
    is_deeply( $reader->measures('http'), [ { name => 'count', label => 'Count' }, { name => 'bytes', label => 'Total bytes' } ],
        'http_access offers count + bytes measures' );
    is_deeply( $reader->measures('syslog'), [ { name => 'count', label => 'Count' } ], 'syslog offers count only' );
    is_deeply( $reader->measures('http_all'), [], 'http_all has no measures' );

    # bytes measure sums the column instead of counting rows
    @MockDbh::SQL = ();
    $reader->top( source => 'http', column => 'vhost', measure => 'bytes' );
    like( $MockDbh::SQL[0], qr/sum\(bytes\) AS count/, 'bytes measure sums the column' );
    like( $MockDbh::SQL[0], qr/FROM http_access/,      'http source reads http_access' );

    eval { $reader->top( source => 'http', column => 'vhost', measure => 'nope' ) };
    like( $@, qr/not a known measure/, 'an unknown measure is rejected' );
    eval { $reader->top( source => 'syslog', column => 'program', measure => 'bytes' ) };
    like( $@, qr/not a known measure/, 'bytes is not a measure for syslog' );

    # stacked split: a per-group query restricted to the top-k groups
    @MockDbh::SQL = ();
    $reader->timeseries( source => 'syslog', group_by => 'program', top_groups => 3 );
    my $sql = $MockDbh::SQL[0];
    like( $sql, qr/\(program\)::text AS "group"/,          'grouped timeseries carries the group value' );
    like( $sql, qr/program IN \(SELECT program FROM syslog/, 'grouped timeseries restricts to top-k groups' );
    like( $sql, qr/GROUP BY 1, 2/,                          'grouped timeseries groups by bucket and group' );

    # top_ips reads the source's IP column, not a dimension
    @MockDbh::SQL = ();
    $reader->top_ips( source => 'syslog' );
    like( $MockDbh::SQL[0], qr/host\(sourceip\) AS value.*FROM syslog/, 'top_ips uses host(sourceip) for syslog' );
    @MockDbh::SQL = ();
    $reader->top_ips( source => 'http' );
    like( $MockDbh::SQL[0], qr/host\(client_ip\) AS value.*FROM http_access/, 'top_ips uses host(client_ip) for http' );
}

done_testing();
