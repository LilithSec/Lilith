#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use JSON qw( encode_json );

use_ok('Lilith::AutoEscalate') or BAIL_OUT('Lilith::AutoEscalate failed to load');

# ---------------------------------------------------------------------------
# 1.  check_rule validation
# ---------------------------------------------------------------------------

{
	my $ok = {
		match   => { field => 'malscore', op => '>=', value => 8 },
		actions => [ { escalate_to => ['soc'] } ],
	};
	ok( eval { Lilith::AutoEscalate->check_rule($ok); 1 }, 'a well formed rule validates' );

	my %bad = (
		'not a hash'          => 'nope',
		'no match'            => { actions => [ { escalate_to => ['soc'] } ] },
		'no actions'          => { match   => { field => 'x', op => '==', value => 1 } },
		'empty actions'       => { match   => { field => 'x', op => '==', value => 1 }, actions => [] },
		'no escalate_to'      => { match => { field => 'x', op => '==', value => 1 }, actions => [ {} ] },
		'unknown op'          => { match => { field => 'x', op => 'bogus', value => 1 }, actions => [ { escalate_to => ['soc'] } ] },
		'in without array'    => { match => { field => 'x', op => 'in', value => 1 }, actions => [ { escalate_to => ['soc'] } ] },
		'bad regex'           => { match => { field => 'x', op => 'regex', value => '(' }, actions => [ { escalate_to => ['soc'] } ] },
		'two combinators'     => { match => { all => [], any => [] }, actions => [ { escalate_to => ['soc'] } ] },
		'leaf missing field'  => { match => { op => '==', value => 1 }, actions => [ { escalate_to => ['soc'] } ] },
	);
	foreach my $why ( sort keys %bad ) {
		ok( !eval { Lilith::AutoEscalate->check_rule( $bad{$why} ); 1 }, "rejected: $why" );
	}
}

# ---------------------------------------------------------------------------
# 2.  compile — leaf operators against a single event
# ---------------------------------------------------------------------------

{
	my $event = {
		malscore  => 9,
		signature => 'ET Cobalt Strike Beacon',
		src_ip    => '1.2.3.4',
		raw       => encode_json( { alert => { severity => 2 }, tags => [ 'c2', 'beacon' ] } ),
	};

	my %cases = (
		'numeric >='       => { field => 'malscore', op => '>=', value => 8 },
		'numeric <'        => { field => 'malscore', op => '<',  value => 20 },
		'string =='        => { field => 'signature', op => '==', value => 'ET Cobalt Strike Beacon' },
		'regex ci'         => { field => 'signature', op => 'regex', value => '(?i)cobalt' },
		'in list'          => { field => 'src_ip', op => 'in', value => [ '5.5.5.5', '1.2.3.4' ] },
		'contains substr'  => { field => 'signature', op => 'contains', value => 'Strike' },
		'exists'           => { field => 'malscore', op => 'exists', value => 1 },
		'raw dotted path'  => { field => 'raw.alert.severity', op => '<=', value => 2 },
		'raw array member' => { field => 'raw.tags', op => 'contains', value => 'beacon' },
	);
	foreach my $why ( sort keys %cases ) {
		my $sub = Lilith::AutoEscalate->compile( { match => $cases{$why} } );
		ok( $sub->($event), "match: $why" );
	}

	my %misses = (
		'numeric >= miss'  => { field => 'malscore', op => '>=', value => 10 },
		'regex miss'       => { field => 'signature', op => 'regex', value => 'zeus' },
		'in miss'          => { field => 'src_ip', op => 'in', value => ['9.9.9.9'] },
		'exists false'     => { field => 'nonexistent', op => 'exists', value => 1 },
		'raw path miss'    => { field => 'raw.alert.severity', op => '>', value => 5 },
	);
	foreach my $why ( sort keys %misses ) {
		my $sub = Lilith::AutoEscalate->compile( { match => $misses{$why} } );
		ok( !$sub->($event), "no match: $why" );
	}
}

# ---------------------------------------------------------------------------
# 3.  compile — all / any / not combinators
# ---------------------------------------------------------------------------

{
	my $event = { malscore => 9, src_ip => '1.2.3.4' };

	my $all = Lilith::AutoEscalate->compile(
		{ match => { all => [ { field => 'malscore', op => '>=', value => 8 }, { field => 'src_ip', op => '==', value => '1.2.3.4' } ] } } );
	ok( $all->($event), 'all: both true' );

	my $all_fail = Lilith::AutoEscalate->compile(
		{ match => { all => [ { field => 'malscore', op => '>=', value => 8 }, { field => 'src_ip', op => '==', value => '9.9.9.9' } ] } } );
	ok( !$all_fail->($event), 'all: one false fails' );

	my $any = Lilith::AutoEscalate->compile(
		{ match => { any => [ { field => 'malscore', op => '>=', value => 99 }, { field => 'src_ip', op => '==', value => '1.2.3.4' } ] } } );
	ok( $any->($event), 'any: one true passes' );

	my $not = Lilith::AutoEscalate->compile( { match => { not => { field => 'src_ip', op => 'in', value => ['1.2.3.4'] } } } );
	ok( !$not->($event), 'not: negates a match' );
}

# ---------------------------------------------------------------------------
# 4.  evaluate — ordering, stop_on_match, and per-event matches
# ---------------------------------------------------------------------------

{
	my $high = {
		id => 1, name => 'high', priority => 10, stop_on_match => 1,
		rule => { match => { field => 'malscore', op => '>=', value => 8 }, actions => [ { escalate_to => ['soc'] } ] },
	};
	my $any_cape = {
		id => 2, name => 'any', priority => 20, stop_on_match => 0,
		rule => { match => { field => 'malscore', op => '>=', value => 1 }, actions => [ { escalate_to => ['ir'] } ] },
	};

	my @events = (
		{ id => 100, malscore => 9 },    # matches high (stops) => only 'high'
		{ id => 101, malscore => 3 },    # matches any only
	);

	my $matches = Lilith::AutoEscalate->evaluate( rules => [ $high, $any_cape ], events => \@events );

	my %by_event;
	foreach my $m ( @{$matches} ) {
		push( @{ $by_event{ $m->{event}{id} } }, $m->{rule}{name} );
	}

	is_deeply( $by_event{100}, ['high'], 'stop_on_match keeps later rules from firing on the same alert' );
	is_deeply( $by_event{101}, ['any'],  'a lower-malscore alert only matches the broad rule' );
}

done_testing();
