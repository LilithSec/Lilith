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

# Run a search with one filter set and hand back the clauses it produced.
sub filter_clauses {
	my ( $filter, $value ) = @_;
	$captured_search = undef;
	$lilith->search( table => 'suricata', $filter => $value );
	return $captured_search->{'-and'};
}

# ---------------------------------------------------------------------------
# a string filter given a single value, which is what the rest of the code base
# passes and what the web UI sends for a filter with one chip
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( instance => 'inari-pie' ),
	[ { instance => { '=' => 'inari-pie' } } ],
	'a scalar string filter becomes an equality'
);

is_deeply(
	filter_clauses( instance => '!inari-pie' ),
	[ { instance => { '!=' => 'inari-pie' } } ],
	'a negated scalar becomes a !='
);

is_deeply(
	filter_clauses( instance => 'nibbles0%' ),
	[ { instance => { 'like' => 'nibbles0%' } } ],
	'a value holding a % becomes a LIKE'
);

is_deeply(
	filter_clauses( instance => '!nibbles0%' ),
	[ { instance => { '-not_like' => 'nibbles0%' } } ],
	'a negated % value becomes a NOT LIKE'
);

is_deeply(
	filter_clauses( instance => ['inari-pie'] ),
	[ { instance => { '=' => 'inari-pie' } } ],
	'a one element array is the same as the scalar'
);

# ---------------------------------------------------------------------------
# several values: positives ORed, negatives ANDed
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( instance => [ 'inari-pie', 'kitsune-pie' ] ),
	[ { instance => { '-in' => [ 'inari-pie', 'kitsune-pie' ] } } ],
	'plain positives collapse into a single -in'
);

is_deeply(
	filter_clauses( instance => [ 'nibbles0%', 'inari-pie' ] ),
	[ { '-or' => [ { instance => { '=' => 'inari-pie' } }, { instance => { 'like' => 'nibbles0%' } } ] } ],
	'a LIKE alongside a plain value is ORed with it'
);

is_deeply(
	filter_clauses( instance => [ 'nibbles0%', 'inari-pie', 'kitsune-pie' ] ),
	[
		{
			'-or' => [
				{ instance => { '-in'  => [ 'inari-pie', 'kitsune-pie' ] } },
				{ instance => { 'like' => 'nibbles0%' } }
			]
		}
	],
	'the -in and the LIKEs are ORed together'
);

is_deeply(
	filter_clauses( instance => [ '!inari-pie', '!nibbles0%' ] ),
	[ { instance => { '!=' => 'inari-pie' } }, { instance => { '-not_like' => 'nibbles0%' } } ],
	'negated values each become their own ANDed clause'
);

is_deeply(
	filter_clauses( instance => [ 'nibbles0%', '!nibbles04' ] ),
	[ { instance => { 'like' => 'nibbles0%' } }, { instance => { '!=' => 'nibbles04' } } ],
	'positives and negatives mix, so a pattern can be narrowed by an exclusion'
);

# ---------------------------------------------------------------------------
# blank values, which is what an empty filter field submits
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( instance => [ 'inari-pie', '', undef ] ),
	[ { instance => { '=' => 'inari-pie' } } ],
	'blank and undef values are skipped'
);

ok( !exists( $captured_search->{'-and'} ), 'a filter of nothing but blanks adds no clause' )
	if is_deeply( filter_clauses( instance => [ '', undef ] ), undef, 'an all blank filter produces no clauses' );

# ---------------------------------------------------------------------------
# the columns moved over from the old simple/equality-only list, which now take
# the same negation and LIKE handling as the rest of the strings
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( proto => [ 'tcp', 'udp' ] ),
	[ { proto => { '-in' => [ 'tcp', 'udp' ] } } ],
	'proto takes several values'
);

# md5 is a cape column rather than a suricata one
$captured_search = undef;
$lilith->search( table => 'cape', md5 => '!d41d8cd98f00b204e9800998ecf8427e' );
is_deeply(
	$captured_search->{'-and'},
	[ { md5 => { '!=' => 'd41d8cd98f00b204e9800998ecf8427e' } } ],
	'md5 can be negated'
);

# ---------------------------------------------------------------------------
# address filters: same multi value handling, but no LIKE -- the columns are
# inet, which LIKE does not apply to, so a % stays part of the value
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( src_ip => [ '192.168.1.2', '192.168.1.3' ] ),
	[ { src_ip => { '-in' => [ '192.168.1.2', '192.168.1.3' ] } } ],
	'src_ip takes several addresses'
);

is_deeply(
	filter_clauses( dest_ip => '!192.168.1.2' ),
	[ { dest_ip => { '!=' => '192.168.1.2' } } ],
	'an address can be negated'
);

is_deeply(
	filter_clauses( src_ip => '192.168.1.%' ),
	[ { src_ip => { '=' => '192.168.1.%' } } ],
	'a % in an address is matched literally rather than as a LIKE'
);

# ---------------------------------------------------------------------------
# filters on columns the table lacks are still skipped
# ---------------------------------------------------------------------------

$captured_search = undef;
$lilith->search( table => 'cape', instance => [ 'inari-pie', 'kitsune-pie' ] );
is_deeply(
	$captured_search->{'-and'},
	[ { instance => { '-in' => [ 'inari-pie', 'kitsune-pie' ] } } ],
	'the instance filter applies to cape'
);

$captured_search = undef;
$lilith->search( table => 'cape', in_iface => [ 'eth0', 'eth1' ] );
ok( !exists( $captured_search->{'-and'} ), 'a multi valued filter on a column the table lacks is skipped' );

done_testing();
