#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith') or BAIL_OUT('Lilith failed to load');
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

no warnings 'redefine';
*Lilith::Schema::connect = sub { return bless {}, 'Lilith::Test::MockSchema' };
use warnings 'redefine';

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
is_deeply(
	$search->{'-and'},
	[ { classification => { '=' => 'Misc Attack' } } ],
	'scalar class becomes an equality'
);

$search = class_search('!Misc Attack');
is_deeply(
	$search->{'-and'},
	[ { classification => { '!=' => 'Misc Attack' } } ],
	'negated scalar class becomes a !='
);

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

done_testing();
