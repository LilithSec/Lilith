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
# 1.  GET /api/ipinfo — input validation
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # Characters outside [0-9a-fA-F:.] are rejected
    $t->get_ok('/api/ipinfo/not-an-ip')
        ->status_is( 400, 'invalid IP (letters/hyphens) returns 400' )
        ->json_has( '/error', '400 response has error key' );

    $t->get_ok('/api/ipinfo/192.168.1.999%20evil')
        ->status_is( 400, 'IP with space/injection chars returns 400' );

    $t->get_ok('/api/ipinfo/1.2.3.4.5.6.7.8%3Bcommand')
        ->status_is( 400, 'URL-encoded injection in IP returns 400' );
}

# ---------------------------------------------------------------------------
# 2.  GET /api/ipinfo — valid IPv4
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # Response has all expected top-level keys
    $t->get_ok('/api/ipinfo/127.0.0.1')->status_is( 200, 'valid IPv4 returns 200' )
        ->json_has( '/ip',         'response has ip key' )
        ->json_has( '/ptr_name',   'response has ptr_name key' )
        ->json_has( '/rdns',       'response has rdns key' )
        ->json_has( '/rdns_error', 'response has rdns_error key' )
        ->json_has( '/whois',      'response has whois key' );

    # The ip field echoes back the input
    $t->get_ok('/api/ipinfo/127.0.0.1')
        ->json_is( '/ip', '127.0.0.1', 'ip field echoes input' );

    # ptr_name for 127.0.0.1 reverses octets and appends .in-addr.arpa
    $t->get_ok('/api/ipinfo/127.0.0.1')
        ->json_is( '/ptr_name', '1.0.0.127.in-addr.arpa', 'ptr_name for 127.0.0.1 is correct' );

    # ptr_name for another IPv4
    $t->get_ok('/api/ipinfo/10.20.30.40')
        ->json_is( '/ptr_name', '40.30.20.10.in-addr.arpa', 'ptr_name for 10.20.30.40 is correct' );

    # ptr_name for all-zero IPv4
    $t->get_ok('/api/ipinfo/0.0.0.0')
        ->json_is( '/ptr_name', '0.0.0.0.in-addr.arpa', 'ptr_name for 0.0.0.0 is correct' );
}

# ---------------------------------------------------------------------------
# 3.  GET /api/ipinfo — valid IPv6
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    SKIP: {
        eval { require Net::IP };
        skip 'Net::IP not installed', 4 if $@;

        $t->get_ok('/api/ipinfo/2001:db8::1')
            ->status_is( 200, 'valid IPv6 returns 200' )
            ->json_has( '/ptr_name', 'IPv6 response has ptr_name' );

        my $ptr = $t->tx->res->json->{ptr_name};
        like( $ptr, qr/\.ip6\.arpa$/, 'IPv6 ptr_name ends in .ip6.arpa' );

        # ::1 (loopback)
        $t->get_ok('/api/ipinfo/::1')
            ->status_is( 200, 'IPv6 loopback returns 200' );

        $ptr = $t->tx->res->json->{ptr_name};
        like( $ptr, qr/\.ip6\.arpa$/, 'IPv6 loopback ptr_name ends in .ip6.arpa' );
    }
}

# ---------------------------------------------------------------------------
# 4.  GET /api/domaininfo — input validation
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # Characters outside [A-Za-z0-9._-] are rejected
    $t->get_ok('/api/domaininfo/bad!domain')
        ->status_is( 400, 'domain with ! returns 400' )
        ->json_has( '/error', '400 response has error key' );

    $t->get_ok('/api/domaininfo/has%20space')
        ->status_is( 400, 'domain with space (url-encoded) returns 400' );

    $t->get_ok('/api/domaininfo/semi%3Bcolon')
        ->status_is( 400, 'domain with semicolon (url-encoded) returns 400' );
}

# ---------------------------------------------------------------------------
# 5.  GET /api/domaininfo — valid domain response structure
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok('/api/domaininfo/example.com')
        ->status_is( 200, 'valid domain returns 200' )
        ->json_has( '/domain',          'response has domain key' )
        ->json_has( '/whois_domain',    'response has whois_domain key' )
        ->json_has( '/dns',             'response has dns key' )
        ->json_has( '/dns_error',       'response has dns_error key' )
        ->json_has( '/whois',           'response has whois key' )
        ->json_has( '/dnstracer',       'response has dnstracer key' )
        ->json_has( '/dnstracer_error', 'response has dnstracer_error key' );

    # domain field echoes input
    $t->get_ok('/api/domaininfo/example.com')
        ->json_is( '/domain', 'example.com', 'domain field echoes input' );
}

# ---------------------------------------------------------------------------
# 6.  GET /api/domaininfo — whois_domain extraction
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # Two-label domain stays as-is
    $t->get_ok('/api/domaininfo/example.com')
        ->json_is( '/whois_domain', 'example.com', 'two-label domain: whois_domain is unchanged' );

    # Three-label domain: strip the leftmost label
    $t->get_ok('/api/domaininfo/sub.example.com')
        ->json_is( '/whois_domain', 'example.com', 'three-label domain: whois_domain strips subdomain' );

    # Four-label domain: still resolves to registrable domain
    $t->get_ok('/api/domaininfo/deep.sub.example.com')
        ->json_is( '/whois_domain', 'example.com', 'four-label domain: whois_domain resolves to registrable domain' );
}

# ---------------------------------------------------------------------------
# 7.  GET /api/domaininfo — dnstracer disabled by default
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok('/api/domaininfo/example.com')
        ->json_is( '/dnstracer', '', 'dnstracer output is empty string when dnstracer_enable is false' );
}

done_testing();
