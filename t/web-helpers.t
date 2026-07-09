#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# ---------------------------------------------------------------------------
# 1.  Default helper values (no optional keys in config)
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->dns_bg_timeout(), 3, 'dns_bg_timeout defaults to 3' );
    is( $app->dnstracer_enable(), 0, 'dnstracer_enable defaults to 0 (false)' );
    is_deeply( $app->dnstracer_flags(), [], 'dnstracer_flags defaults to empty arrayref' );
}

# ---------------------------------------------------------------------------
# 2.  dns_bg_timeout reads from config
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dns_bg_timeout = 10\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->dns_bg_timeout(), 10, 'dns_bg_timeout reads custom value from config' );
}

# ---------------------------------------------------------------------------
# 3.  dnstracer_enable reads from config
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dnstracer_enable = true\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->dnstracer_enable(), 1, 'dnstracer_enable is 1 when set to true in config' );
}

# Note: the TOML module (not TOML::Tiny) parses the bare word `false` as the
# string "false", which is truthy in Perl.  Omitting dnstracer_enable from the
# config is therefore the correct way to disable it; the default-value test
# above covers that case.

# ---------------------------------------------------------------------------
# 4.  dnstracer_flags reads from config
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dnstracer_flags = [\"-q\", \"-s\", \"8.8.8.8\"]\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is_deeply(
        $app->dnstracer_flags(),
        [ '-q', '-s', '8.8.8.8' ],
        'dnstracer_flags reads array from config'
    );
}

# ---------------------------------------------------------------------------
# 5.  Non-array dnstracer_flags is silently ignored (defaults to [])
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dnstracer_flags = \"-q\"\n";    # scalar, not array
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is_deeply(
        $app->dnstracer_flags(),
        [],
        'non-array dnstracer_flags in config is ignored; helper returns []'
    );
}

# ---------------------------------------------------------------------------
# 5b.  domaininfo cache config helpers
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->domaininfo_cache_enabled(), 0,   'domaininfo cache is disabled by default' );
    is( $app->domaininfo_cache_ttl(),     300, 'domaininfo cache ttl defaults to 300' );
    is_deeply( $app->domaininfo_cache(), {}, 'domaininfo cache store starts empty' );
}

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "domaininfo_cache = true\n";
    print $fh "domaininfo_cache_ttl = 900\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->domaininfo_cache_enabled(), 1,   'domaininfo_cache = true enables the cache' );
    is( $app->domaininfo_cache_ttl(),     900, 'domaininfo_cache_ttl is read from config' );
}

# ---------------------------------------------------------------------------
# 5c.  virani config helpers
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->virani_enabled(),        0, 'virani disabled when no [virani.*] configured' );
    is( $app->virani_search_enable(),  0, 'virani search disabled by default' );
    is_deeply( $app->virani_remotes(), {}, 'no virani remotes by default' );
}

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "virani_search_enable = true\n";
    print $fh qq{[virani.r1]\nurl = "https://v.example/"\n};
    print $fh qq{[virani.bad]\napikey = "k"\n};    # no url => skipped
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->virani_enabled(),       1, 'virani enabled with a configured remote' );
    is( $app->virani_search_enable(), 1, 'virani_search_enable read from config' );
    is_deeply( [ keys %{ $app->virani_remotes() } ], ['r1'], 'url-less remote is skipped' );
}

# ---------------------------------------------------------------------------
# 6.  country_flag helper — code to regional-indicator emoji
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->country_flag('US'), "\x{1F1FA}\x{1F1F8}", 'US maps to the regional-indicator flag' );
    is( $app->country_flag('de'), "\x{1F1E9}\x{1F1EA}", 'lowercase code is upcased before mapping' );
    is( $app->country_flag(''),      '', 'empty code yields empty string' );
    is( $app->country_flag(undef),   '', 'undef code yields empty string' );
    is( $app->country_flag('USA'),   '', 'non two-letter code yields empty string' );
    is( $app->country_flag('1.2'),   '', 'non-alpha code yields empty string' );
}

# ---------------------------------------------------------------------------
# 7.  ip_country helper — empty when no country-aware database is loaded
# ---------------------------------------------------------------------------

{
    # Force every geoip key to a missing path so the platform defaults (which
    # may be installed on the test host) are overridden and no DB loads. The
    # missing paths warn by design; capture them to keep the output clean.
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh qq{geoip_ip_city    = "/nonexistent/city.mmdb"\n};
    print $fh qq{geoip_ip_country = "/nonexistent/country.mmdb"\n};
    print $fh qq{geoip_ip_asn     = "/nonexistent/asn.mmdb"\n};
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    local $SIG{__WARN__} = sub { };
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->ip_country('8.8.8.8'),   '', 'ip_country is empty when no MMDB is loaded' );
    is( $app->ip_country('not-an-ip'), '', 'ip_country rejects malformed input' );
    is( $app->ip_country(undef),       '', 'ip_country handles undef' );
    is( $app->ip_country('10.0.0.1'),  '', 'ip_country is empty for a private IP' );
}

# ---------------------------------------------------------------------------
# 8.  ip_country helper — real lookup when a default database is present
#     (host-dependent; skipped when no country DB is installed)
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    my $cc = $app->ip_country('8.8.8.8');
  SKIP: {
        skip 'no country-aware MMDB installed on this host', 2 unless $cc ne '';
        like( $cc, qr/^[A-Z]{2}$/, 'ip_country returns a two-letter uppercase code' );
        is( length( $app->country_flag($cc) ), 2, 'the code renders as a two-codepoint emoji flag' );
    }
}

# ---------------------------------------------------------------------------
# 9.  ip_country helper — field fallback (country -> registered_country ->
#     represented_country). Needs a loaded DB to iterate; record lookups are
#     mocked so the assertions do not depend on any specific IP's real data.
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

  SKIP: {
        skip 'no MMDB installed on this host to iterate over', 4
            unless @{ $app->geoip_mmdbs };

        my $record;
        no warnings qw(redefine once);
        local *IP::Geolocation::MMDB::record_for_address = sub { return $record };
        use warnings qw(redefine once);

        $record = { country => { iso_code => 'de' } };
        is( $app->ip_country('1.2.3.4'), 'DE', 'physical country is used and upcased' );

        # anycast / hosting IPs (e.g. Cloudflare) expose only registered_country
        $record = { registered_country => { iso_code => 'US' } };
        is( $app->ip_country('1.2.3.4'), 'US', 'falls back to registered_country' );

        $record = { represented_country => { iso_code => 'GB' } };
        is( $app->ip_country('1.2.3.4'), 'GB', 'falls back to represented_country' );

        $record = { city => { names => { en => 'Nowhere' } } };
        is( $app->ip_country('1.2.3.4'), '', 'no country field of any kind yields empty' );
    }
}

# ---------------------------------------------------------------------------
# 10.  ip_subdivision helper — top subdivision (state/province) code
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->ip_subdivision('not-an-ip'), '', 'ip_subdivision rejects malformed input' );
    is( $app->ip_subdivision(undef),       '', 'ip_subdivision handles undef' );

  SKIP: {
        skip 'no MMDB installed on this host to iterate over', 3
            unless @{ $app->geoip_mmdbs };

        my $record;
        no warnings qw(redefine once);
        local *IP::Geolocation::MMDB::record_for_address = sub { return $record };
        use warnings qw(redefine once);

        $record = { subdivisions => [ { iso_code => 'tx' }, { iso_code => 'zz' } ] };
        is( $app->ip_subdivision('1.2.3.4'), 'TX', 'returns the first subdivision code, upcased' );

        $record = { country => { iso_code => 'US' } };
        is( $app->ip_subdivision('1.2.3.4'), '', 'empty when the record has no subdivisions' );

        $record = { subdivisions => [] };
        is( $app->ip_subdivision('1.2.3.4'), '', 'empty when the subdivisions list is empty' );
    }
}

# ---------------------------------------------------------------------------
# 10b. ip_city helper — English city name from the City database
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->ip_city('not-an-ip'), '', 'ip_city rejects malformed input' );
    is( $app->ip_city(undef),       '', 'ip_city handles undef' );

  SKIP: {
        skip 'no MMDB installed on this host to iterate over', 3
            unless @{ $app->geoip_mmdbs };

        my $record;
        no warnings qw(redefine once);
        local *IP::Geolocation::MMDB::record_for_address = sub { return $record };
        use warnings qw(redefine once);

        $record = { city => { names => { en => 'Austin' } } };
        is( $app->ip_city('1.2.3.4'), 'Austin', 'returns the English city name' );

        $record = { country => { iso_code => 'US' } };
        is( $app->ip_city('1.2.3.4'), '', 'empty when the record has no city' );

        $record = { city => { names => {} } };
        is( $app->ip_city('1.2.3.4'), '', 'empty when the city has no English name' );
    }
}

# ---------------------------------------------------------------------------
# 11.  ip_geo helper — combined country + subdivision, with per-request memoization
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is_deeply( $app->ip_geo('not-an-ip'), { country => '', subdivision => '', city => '' },
        'ip_geo returns empty triple for malformed input' );

  SKIP: {
        skip 'no MMDB installed on this host to iterate over', 3
            unless @{ $app->geoip_mmdbs };

        my $record = {
            country      => { iso_code => 'us' },
            subdivisions => [ { iso_code => 'ca' } ],
            city         => { names => { en => 'Mountain View' } },
        };
        my $calls = 0;
        my $orig  = IP::Geolocation::MMDB->can('record_for_address');
        no warnings qw(redefine once);
        local *IP::Geolocation::MMDB::record_for_address = sub { $calls++; return $record };
        use warnings qw(redefine once);

        is_deeply( $app->ip_geo('1.2.3.4'),
            { country => 'US', subdivision => 'CA', city => 'Mountain View' },
            'ip_geo returns country, subdivision, and city from one pass, upcased where applicable' );

        # per-request memoization: repeated IPs on the same controller only hit
        # the databases on the first lookup
        my $c = $app->build_controller;
        $calls = 0;
        $c->ip_geo('9.9.9.9');
        my $first = $calls;
        $c->ip_geo('9.9.9.9');
        $c->ip_geo('9.9.9.9');
        ok( $first >= 1, 'first ip_geo performs at least one database lookup' );
        is( $calls, $first, 'repeated ip_geo for the same IP adds no further lookups (memoized)' );
    }
}

done_testing();
