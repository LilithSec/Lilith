#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith')         or BAIL_OUT('Lilith failed to load');
use_ok('Lilith::Schema') or BAIL_OUT('Lilith::Schema failed to load');

# ---------------------------------------------------------------------------
# Mock out Lilith::Schema->connect so search() never touches a real DB and
# we can capture the search hash it builds.
# ---------------------------------------------------------------------------

my $captured_search;

{

	package Lilith::Test::MockRS;

	sub search {
		my ( $self, $search, $attrs ) = @_;
		$captured_search = $search;
		return $self;
	}

	sub all {
		return ();
	}

	package Lilith::Test::MockSchema;

	sub resultset {
		return bless {}, 'Lilith::Test::MockRS';
	}
}

no warnings qw(redefine once);
*Lilith::Schema::connect = sub { return bless {}, 'Lilith::Test::MockSchema' };
use warnings qw(redefine once);

my $lilith = Lilith->new( dsn => 'dbi:Pg:dbname=test' );

sub class_search {
	my ($class) = @_;
	$captured_search = undef;
	$lilith->search( table => 'suricata', class => $class );
	return $captured_search;
}

# ---------------------------------------------------------------------------
# scalar forms
# ---------------------------------------------------------------------------

my $search = class_search('Misc Attack');
is_deeply( $search->{'-and'}, [ { classification => { '=' => 'Misc Attack' } } ], 'scalar class becomes an equality' );

$search = class_search('!Misc Attack');
is_deeply( $search->{'-and'}, [ { classification => { '!=' => 'Misc Attack' } } ],
	'negated scalar class becomes a !=' );

$search = class_search('Misc%');
is_deeply( $search->{'-and'}, [ { classification => { 'like' => 'Misc%' } } ], 'scalar class with % becomes a like' );

$search = class_search('!Misc%');
is_deeply(
	$search->{'-and'},
	[ { classification => { '-not_like' => 'Misc%' } } ],
	'negated scalar class with % becomes a not like'
);

# ---------------------------------------------------------------------------
# array forms
# ---------------------------------------------------------------------------

$search = class_search( [] );
ok( !defined( $search->{'-and'} ), 'empty array adds no class clauses' );

$search = class_search( [ '', 'Misc Attack' ] );
is_deeply(
	$search->{'-and'},
	[ { classification => { '=' => 'Misc Attack' } } ],
	'empty items are skipped and a single item is an equality'
);

$search = class_search( [ 'Misc Attack', 'Exploit Attempt' ] );
is_deeply(
	$search->{'-and'},
	[ { classification => { '-in' => [ 'Misc Attack', 'Exploit Attempt' ] } } ],
	'multiple plain items become an in'
);

$search = class_search( [ 'Misc Attack', 'Exploit Attempt', 'Generic%' ] );
is_deeply(
	$search->{'-and'},
	[
		{
			'-or' => [
				{ classification => { '-in'  => [ 'Misc Attack', 'Exploit Attempt' ] } },
				{ classification => { 'like' => 'Generic%' } },
			]
		}
	],
	'plain items and like items are ORed together'
);

$search = class_search( [ '!Misc Attack', '!Generic%' ] );
is_deeply(
	$search->{'-and'},
	[ { classification => { '!=' => 'Misc Attack' } }, { classification => { '-not_like' => 'Generic%' } }, ],
	'negated items are ANDed together'
);

$search = class_search( [ 'Misc Attack', '!Generic%' ] );
is_deeply(
	$search->{'-and'},
	[ { classification => { '=' => 'Misc Attack' } }, { classification => { '-not_like' => 'Generic%' } }, ],
	'positive and negated items are ANDed together'
);

# ---------------------------------------------------------------------------
# class clauses coexist with the port -and usage
# ---------------------------------------------------------------------------

$captured_search = undef;
$lilith->search( table => 'suricata', class => [ 'Misc Attack', 'Exploit Attempt' ], port => '22' );
is( scalar( @{ $captured_search->{'-and'} } ), 2, 'class clauses are pushed alongside the port -and clause' );

# ---------------------------------------------------------------------------
# cape has no classification column, so a class filter must be ignored for it
# rather than producing a "column classification does not exist" error. The web
# UI injects a default "!Generic Protocol Command Decode" on fresh loads, which
# previously broke every cape search.
# ---------------------------------------------------------------------------

$captured_search = undef;
$lilith->search( table => 'cape', class => ['!Generic Protocol Command Decode'] );
ok( !exists( $captured_search->{'-and'} ), 'cape search adds no classification clause' );

$captured_search = undef;
$lilith->search( table => 'cape', class => [ 'Misc Attack', '!Generic Protocol Command Decode' ] );
ok( !exists( $captured_search->{'-and'} ), 'cape search ignores positive and negated class items alike' );

# ---------------------------------------------------------------------------
# numeric items (dest_port / src_port / ...)
# ---------------------------------------------------------------------------

sub port_search {
	my ($dest_port) = @_;
	$captured_search = undef;
	$lilith->search( table => 'suricata', dest_port => $dest_port );
	return $captured_search;
}

$search = port_search( ['22'] );
is_deeply( $search->{dest_port}, { '=' => '22' }, 'single dest_port becomes an equality' );

$search = port_search( ['!22'] );
is_deeply( $search->{dest_port}, { '!=' => '22' }, 'single negated dest_port becomes a !=' );

# The regression: multiple negated ports must be ANDed, not ORed. "!22, !443"
# ORed is true for every row (a 443 row still satisfies "!= 22"), so nothing
# was filtered.
$search = port_search( [ '!22', '!443' ] );
is_deeply(
	$search->{dest_port},
	[ '-and' => { '!=' => '22' }, { '!=' => '443' } ],
	'multiple negated dest_ports are ANDed together (not ORed)'
);

$search = port_search( [ '22', '!443' ] );
is_deeply(
	$search->{dest_port},
	[ '-and' => { '=' => '22' }, { '!=' => '443' } ],
	'positive and negated dest_ports are ANDed together'
);

# Confirm the generated SQL actually excludes a negated port, end to end.
{
	require SQL::Abstract;
	my $sa = SQL::Abstract->new;
	my ( $sql, @bind ) = $sa->where( { dest_port => port_search( [ '!22', '!443' ] )->{dest_port} } );
	like( $sql, qr/dest_port\s*!=\s*\?\s+AND\s+dest_port\s*!=\s*\?/i, 'negated ports render as ANDed !=' );
	is_deeply( \@bind, [ '22', '443' ], 'both negated port values are bound' );
}

# ---------------------------------------------------------------------------
# the complex "port" item (matches src_port or dest_port)
# ---------------------------------------------------------------------------

sub complex_port_search {
	my ($port) = @_;
	$captured_search = undef;
	$lilith->search( table => 'suricata', port => $port );
	return $captured_search->{'-and'};
}

is_deeply(
	complex_port_search('22'),
	[ { '-or' => [ { src_port => { '=' => '22' } }, { dest_port => { '=' => '22' } } ] } ],
	'plain port is ORed across src_port and dest_port'
);

# The regression: "!22" used to be passed straight through as an integer,
# blowing up Postgres. It must parse the '!' and, because it is a negation,
# AND across both columns so a match on either side is excluded.
is_deeply(
	complex_port_search('!22'),
	[ { '-and' => [ { src_port => { '!=' => '22' } }, { dest_port => { '!=' => '22' } } ] } ],
	'negated port is ANDed across src_port and dest_port with a !='
);

is_deeply(
	complex_port_search('>=1024'),
	[ { '-or' => [ { src_port => { '>=' => '1024' } }, { dest_port => { '>=' => '1024' } } ] } ],
	'port accepts numeric comparison operators'
);

# The regression: several comma separated ports used to die ("22,80" is not a
# valid single port). Positive items are ORed across both columns and items.
is_deeply(
	complex_port_search('22,80'),
	[
		{
			'-or' => [
				{ src_port  => { '=' => '22' } },
				{ dest_port => { '=' => '22' } },
				{ src_port  => { '=' => '80' } },
				{ dest_port => { '=' => '80' } },
			]
		}
	],
	'multiple ports are ORed across src_port and dest_port'
);

# Mixed positive and negated: positives ORed as a group, each negation ANDed in.
is_deeply(
	complex_port_search('80,!22'),
	[
		{ '-or'  => [ { src_port => { '='  => '80' } }, { dest_port => { '='  => '80' } } ] },
		{ '-and' => [ { src_port => { '!=' => '22' } }, { dest_port => { '!=' => '22' } } ] },
	],
	'a mix of positive and negated ports ORs the positives and ANDs the negation'
);

# And end to end: the negated port really renders as ANDed != in SQL.
{
	my $sa = SQL::Abstract->new;
	my ( $sql, @bind ) = $sa->where( { '-and' => complex_port_search('!22') } );
	like(
		$sql,
		qr/src_port\s*!=\s*\?\s+AND\s+dest_port\s*!=\s*\?/i,
		'negated port renders as ( src_port != ? AND dest_port != ? )'
	);
	is_deeply( \@bind, [ '22', '22' ], 'negated port value is bound for both columns' );
}

# ---------------------------------------------------------------------------
# the complex "ip" item (matches src_ip or dest_ip)
# ---------------------------------------------------------------------------

sub complex_ip_search {
	my ($ip) = @_;
	$captured_search = undef;
	$lilith->search( table => 'suricata', ip => $ip );
	return $captured_search->{'-and'};
}

is_deeply(
	complex_ip_search('192.168.1.2'),
	[ { '-or' => [ { src_ip => { '=' => '192.168.1.2' } }, { dest_ip => { '=' => '192.168.1.2' } } ] } ],
	'plain ip is ORed across src_ip and dest_ip'
);

is_deeply(
	complex_ip_search('!192.168.1.2'),
	[ { '-and' => [ { src_ip => { '!=' => '192.168.1.2' } }, { dest_ip => { '!=' => '192.168.1.2' } } ] } ],
	'negated ip is ANDed across src_ip and dest_ip with a !='
);

is_deeply(
	complex_ip_search('10.0.0.1,10.0.0.2'),
	[
		{
			'-or' => [
				{ src_ip  => { '=' => '10.0.0.1' } },
				{ dest_ip => { '=' => '10.0.0.1' } },
				{ src_ip  => { '=' => '10.0.0.2' } },
				{ dest_ip => { '=' => '10.0.0.2' } },
			]
		}
	],
	'multiple ips are ORed across src_ip and dest_ip'
);

# ---------------------------------------------------------------------------
# time window: relative (go_back_minutes) vs an explicit start/end range
# ---------------------------------------------------------------------------

# default is the now-relative window as literal SQL on the timestamp column
$captured_search = undef;
$lilith->search( table => 'suricata' );
is( ref $captured_search->{timestamp}{'>='}, 'SCALAR', 'default window is a now-relative literal on timestamp' );
like( ${ $captured_search->{timestamp}{'>='} }, qr/CURRENT_TIMESTAMP - interval/, 'and uses go_back_minutes' );

# an explicit start+end becomes a bound range (values, not literal SQL),
# normalized to a canonical timestamp; the datetime-local 'T' is accepted
$captured_search = undef;
$lilith->search( table => 'suricata', start => '2026-07-18T00:00', end => '2026-07-18T12:00' );
is_deeply(
	$captured_search->{timestamp},
	{ '>=' => '2026-07-18 00:00:00', '<=' => '2026-07-18 12:00:00' },
	'start+end become a bound >= / <= range on timestamp'
);

# start alone is just a lower bound
$captured_search = undef;
$lilith->search( table => 'suricata', start => '2026-07-18 06:30:00' );
is_deeply( $captured_search->{timestamp}, { '>=' => '2026-07-18 06:30:00' }, 'start alone is a lower bound' );

# cape windows on its 'stop' column
$captured_search = undef;
$lilith->search( table => 'cape', start => '2026-07-18T00:00' );
is_deeply( $captured_search->{stop}, { '>=' => '2026-07-18 00:00:00' }, 'cape ranges on the stop column' );
ok( !exists $captured_search->{timestamp}, 'cape does not window on timestamp' );

# an unparseable bound is rejected with a clear error
eval { $lilith->search( table => 'suricata', start => 'not-a-time' ); };
like( $@, qr/is not a parseable time/, 'an unparseable start is rejected' );

# ---------------------------------------------------------------------------
# order_by is concatenated into the ORDER BY clause, so anything that is not a
# real column of the table must be rejected (SQL injection guard)
# ---------------------------------------------------------------------------

eval { $lilith->search( table => 'suricata', order_by => 'timestamp; select pg_sleep(10)' ); };
like( $@, qr/is not a column of the suricata table/, 'a non-column order_by is rejected' );

eval { $lilith->search( table => 'suricata', order_by => 'malscore' ); };
like( $@, qr/is not a column of the suricata table/, "another table's column is rejected too" );

eval { $lilith->search( table => 'suricata', order_by => 'src_ip' ); };
is( $@, '', 'a real column is accepted as order_by' );

eval { $lilith->search( table => 'cape', order_by => 'id' ); };
is( $@, '', 'the id column is accepted as order_by' );

# ---------------------------------------------------------------------------
# regression: the >N numeric operator used to strip with s/^\>\=// (which never
# matches a bare >N), leaving the > on the bound value and breaking the cast
# ---------------------------------------------------------------------------

$search = port_search( ['>1024'] );
is_deeply( $search->{dest_port}, { '>' => '1024' }, 'a >N numeric item strips the > from the bound value' );

$search = port_search( ['<1024'] );
is_deeply( $search->{dest_port}, { '<' => '1024' }, 'a <N numeric item strips the < from the bound value' );

# ---------------------------------------------------------------------------
# no_time skips the window entirely (used for lookups by id, where the row may
# be arbitrarily old or, for cape, have a NULL stop)
# ---------------------------------------------------------------------------

$captured_search = undef;
$lilith->search( table => 'cape', no_time => 1, id => ['42'] );
ok( !exists( $captured_search->{stop} ) && !exists( $captured_search->{timestamp} ), 'no_time applies no time window' );
is_deeply( $captured_search->{id}, { '=' => '42' }, 'and the id filter still applies' );

# ---------------------------------------------------------------------------
# filters on columns the table lacks are skipped rather than generating SQL
# that errors on a nonexistent column
# ---------------------------------------------------------------------------

$captured_search = undef;
$lilith->search( table => 'baphomet', sid => ['123'], port => '22', src_port => ['22'] );
ok( !exists( $captured_search->{sid} ),      'sid filter is skipped for a table without a sid column' );
ok( !exists( $captured_search->{src_port} ), 'src_port filter is skipped for a table without ports' );
ok( !exists( $captured_search->{'-and'} ),   'the complex port filter is skipped too' );

$captured_search = undef;
$lilith->search( table => 'cape', target => 'somehost' );
is_deeply( $captured_search->{target}, { '=' => 'somehost' }, 'the target filter applies to cape' );

$captured_search = undef;
$lilith->search( table => 'suricata', target => 'somehost' );
ok( !exists( $captured_search->{target} ), 'the target filter is skipped for tables without the column' );

# table may be omitted entirely (defaults to suricata) without warnings
{
	my @warnings;
	local $SIG{__WARN__} = sub { push( @warnings, $_[0] ) };
	eval { $lilith->search( order_by => 'timestamp' ); };
	is( $@,                '', 'search without a table defaults to suricata' );
	is( scalar(@warnings), 0,  'and emits no warnings' ) or diag( join( '', @warnings ) );
}

done_testing();
