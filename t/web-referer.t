#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Write a minimal TOML config to a temp file, set LILITH_CONFIG, and return
# a fresh Test::Mojo instance wrapping Lilith::Web.
sub _make_app {
    my ($extra_toml) = @_;
    $extra_toml //= '';

    my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "user = \"lilith\"\n";
    print $fh $extra_toml;
    close $fh;

    local $ENV{LILITH_CONFIG} = $config_file;
    # Test::Mojo instantiates the app immediately, so the env var must be set
    # before the constructor runs.  We return both the app handle and a guard
    # that keeps $config_file alive for the duration of the test.
    return Test::Mojo->new('Lilith::Web');
}

# ---------------------------------------------------------------------------
# Load check
# ---------------------------------------------------------------------------

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# ---------------------------------------------------------------------------
# 1.  No allowed_referers configured → referer checking is skipped entirely
# ---------------------------------------------------------------------------

{
    my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $config_file;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok('/')->status_isnt( 403, 'no referer config: request without Referer is not rejected' );
    $t->get_ok( '/', { Referer => 'http://anything.example.com/' } )
        ->status_isnt( 403, 'no referer config: any Referer is not rejected' );
}

# ---------------------------------------------------------------------------
# 2.  allowed_referers configured — enforce prefix matching
# ---------------------------------------------------------------------------

{
    my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "allowed_referers = [\"http://allowed.example.com\"]\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $config_file;
    my $t = Test::Mojo->new('Lilith::Web');

    # No Referer header → 403
    $t->get_ok('/')->status_is( 403, 'missing Referer returns 403' )
        ->json_is( '/error', 'Forbidden: invalid or missing Referer' );

    # Completely wrong Referer → 403
    $t->get_ok( '/', { Referer => 'http://evil.example.com/' } )
        ->status_is( 403, 'wrong Referer returns 403' );

    # Referer that only partially overlaps (doesn't start with the allowed prefix) → 403
    $t->get_ok( '/', { Referer => 'http://notallowed.example.com/http://allowed.example.com' } )
        ->status_is( 403, 'Referer that embeds allowed origin but does not start with it returns 403' );

    # Exact prefix match → passes (/ redirects to /search → 302)
    $t->get_ok( '/', { Referer => 'http://allowed.example.com' } )
        ->status_is( 302, 'exact prefix Referer passes and gets redirect' );

    # Referer with path under allowed origin → passes
    $t->get_ok( '/', { Referer => 'http://allowed.example.com/search?foo=1' } )
        ->status_is( 302, 'Referer with path under allowed origin passes' );
}

# ---------------------------------------------------------------------------
# 3.  Multiple allowed_referers — any matching prefix is sufficient
# ---------------------------------------------------------------------------

{
    my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "allowed_referers = [\"http://first.example.com\", \"http://second.example.com\"]\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $config_file;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok( '/', { Referer => 'http://first.example.com/' } )
        ->status_is( 302, 'first allowed origin passes' );

    $t->get_ok( '/', { Referer => 'http://second.example.com/page' } )
        ->status_is( 302, 'second allowed origin passes' );

    $t->get_ok( '/', { Referer => 'http://third.example.com/' } )
        ->status_is( 403, 'unlisted origin still rejected' );
}

done_testing();
