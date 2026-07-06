#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

# The escalation CLI helpers live in the src_bin/lilith script (not a
# module), so pull the subs out and eval them here to test their behavior
# in isolation.
my $script = do {
    local $/;
    open( my $fh, '<', 'src_bin/lilith' ) or BAIL_OUT("cannot read src_bin/lilith: $!");
    <$fh>;
};

foreach my $name (qw( esc_parse_set esc_lookup_target esc_resolve_targets )) {
    my ($sub_src) = $script =~ /(sub $name \{.*?\n\} \#\# end sub $name)/s;
    ok( $sub_src, "found $name in src_bin/lilith" ) or BAIL_OUT("$name not found");

    ## no critic (ProhibitStringyEval)
    eval $sub_src;
    ## use critic
    is( $@, '', "$name compiles" );
}

# A minimal stand-in for the Lilith object; only the methods the helpers
# call are implemented.
{

    package MockLilith;

    sub new { return bless {}, shift }

    sub escalation_targets {
        return [
            { id => 1, name => 'soc-hook', type => 'Webhook', enabled => 1 },
            { id => 2, name => 'mail',     type => 'Email',   enabled => 1 },
        ];
    }

    sub escalation_target_get {
        my ( $self, $id ) = @_;
        die( 'no escalation target with the id "' . $id . '"' ) unless $id == 1;
        return { id => 1, name => 'soc-hook', type => 'Webhook', enabled => 1 };
    }
}

my $mock = MockLilith->new;

# ---------------------------------------------------------------------------
# 1.  esc_parse_set
# ---------------------------------------------------------------------------

{
    is_deeply( esc_parse_set(), {}, 'no --set items gives an empty config' );
    is_deeply(
        esc_parse_set( 'url=https://e/x', 'timeout=10', 'apikey=' ),
        { url => 'https://e/x', timeout => '10', apikey => '' },
        'key=value items parse, including an empty value'
    );
    is_deeply(
        esc_parse_set('note=a=b=c'),
        { note => 'a=b=c' },
        'only the first = splits key from value'
    );

    eval { esc_parse_set('justakey') };
    like( $@, qr/key=value/, 'a --set item without = dies' );
    eval { esc_parse_set('bad key=x') };
    like( $@, qr/key=value/, 'a --set item with a bad key dies' );
}

# ---------------------------------------------------------------------------
# 2.  esc_lookup_target
# ---------------------------------------------------------------------------

{
    my $by_id = esc_lookup_target( $mock, 1, undef );
    is( $by_id->{name}, 'soc-hook', 'lookup by --tid works' );

    my $by_name = esc_lookup_target( $mock, undef, 'mail' );
    is( $by_name->{id}, 2, 'lookup by --name works' );

    # --tid wins when both are given (--name is then the rename value)
    my $both = esc_lookup_target( $mock, 1, 'mail' );
    is( $both->{id}, 1, '--tid takes precedence over --name' );

    eval { esc_lookup_target( $mock, 'abc', undef ) };
    like( $@, qr/not numeric/, 'non-numeric --tid dies' );

    eval { esc_lookup_target( $mock, undef, 'nope' ) };
    like( $@, qr/known: mail, soc-hook|known: soc-hook, mail/, 'unknown --name dies listing known names' );

    eval { esc_lookup_target( $mock, undef, undef ) };
    like( $@, qr/--tid or --name/, 'neither --tid nor --name dies' );
}

# ---------------------------------------------------------------------------
# 3.  esc_resolve_targets
# ---------------------------------------------------------------------------

{
    is_deeply( esc_resolve_targets( $mock, '1,2' ), [ 1, 2 ], 'numeric items pass through as IDs' );
    is_deeply(
        esc_resolve_targets( $mock, 'soc-hook, mail' ),
        [ 1, 2 ],
        'names resolve to IDs, with whitespace tolerated'
    );
    is_deeply( esc_resolve_targets( $mock, '7,mail' ), [ 7, 2 ], 'IDs and names mix' );

    eval { esc_resolve_targets( $mock, 'nope' ) };
    like( $@, qr/no escalation target named "nope"/, 'unknown name dies' );

    eval { esc_resolve_targets( $mock, '' ) };
    like( $@, qr/--to is required/, 'empty --to dies' );
    eval { esc_resolve_targets( $mock, undef ) };
    like( $@, qr/--to is required/, 'undef --to dies' );
}

done_testing();
