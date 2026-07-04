#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub _make_app {
    my ($extra_toml) = @_;
    $extra_toml //= '';

    my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh $extra_toml;
    close $fh;

    local $ENV{LILITH_CONFIG} = $config_file;
    return Test::Mojo->new('Lilith::Web');
}

# ---------------------------------------------------------------------------
# 1.  Root redirect
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok('/')->status_is( 302, 'GET / returns 302' )
        ->header_is( Location => '/search', 'GET / redirects to /search' );
}

# ---------------------------------------------------------------------------
# 2.  Search form — GET /search
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # No params — renders the search form without hitting the DB
    $t->get_ok('/search')->status_is( 200, 'GET /search renders search form' );

    # search param triggers a DB query; no real DB so it stashes an error but
    # still renders 200
    $t->get_ok('/search?search=1&table=suricata')
        ->status_is( 200, 'GET /search?search=1 renders 200 (error stashed)' );

    # Invalid table value is sanitized to "suricata"
    $t->get_ok('/search?search=1&table=badtable')
        ->status_is( 200, 'invalid table is sanitized; page still renders 200' );

    # Invalid order_dir is sanitized to "DESC"
    $t->get_ok('/search?search=1&order_dir=INVALID')
        ->status_is( 200, 'invalid order_dir is sanitized; page still renders 200' );

    # POST is not routed — only GET /search is defined
    $t->post_ok('/search')->status_is( 404, 'POST /search is not routed (404)' );

    # the classification select allows multiple selections
    $t->get_ok('/search')
        ->element_exists( 'select[name="class"][multiple]', 'class select is a multi-select' );

    # multiple class params render and are marked selected on the way back out
    $t->get_ok('/search?search=1&class=Misc+activity&class=Not+Suspicious+Traffic')
        ->status_is( 200, 'multiple class params render 200' )
        ->element_exists( 'option[value="Misc activity"][selected]',
        'first class param is selected in the form' )
        ->element_exists( 'option[value="Not Suspicious Traffic"][selected]',
        'second class param is selected in the form' );
}

# ---------------------------------------------------------------------------
# 3.  Event view — GET /event/:table/:id
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # All valid table values render without a 500 (DB error is stashed)
    $t->get_ok('/event/suricata/1')->status_is( 200, 'GET /event/suricata/1 renders 200' );
    $t->get_ok('/event/sagan/1')   ->status_is( 200, 'GET /event/sagan/1 renders 200' );
    $t->get_ok('/event/cape/1')    ->status_is( 200, 'GET /event/cape/1 renders 200' );

    # Invalid table is sanitized to "suricata" and the page still renders
    $t->get_ok('/event/badtable/1')
        ->status_is( 200, 'invalid table in /event is sanitized; page still renders 200' );
}

done_testing();
