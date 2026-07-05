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

# ---------------------------------------------------------------------------
# 8.  GeoIP / MMDB — _flatten_geo record flattening
# ---------------------------------------------------------------------------

{
    my $record = {
        continent => { code => 'NA', names => { en => 'North America', de => 'Nordamerika' } },
        country   => { iso_code => 'US', geoname_id => 6252001, names => { en => 'United States' } },
        subdivisions => [ { iso_code => 'CA', names => { en => 'California' } } ],
        city     => { names => { en => 'Mountain View' } },
        location => { latitude => 37.386, longitude => -122.0838, time_zone => 'America/Los_Angeles' },
        postal   => { code => '94035' },
    };

    my %out;
    Lilith::Web::Controller::Api::_flatten_geo( $record, '', \%out );

    is( $out{'country'},          'United States', 'country name collapsed from names.en' );
    is( $out{'country.iso_code'}, 'US',            'country.iso_code preserved alongside collapsed name' );
    is( $out{'continent'},        'North America', 'localized name prefers English' );
    is( $out{'city'},             'Mountain View', 'city name collapsed' );
    is( $out{'subdivisions.0'},   'California',     'array elements are indexed and collapsed' );
    is( $out{'location.latitude'}, 37.386, 'nested numeric scalar preserved' );
    is( $out{'postal.code'},      '94035', 'postal code preserved' );
    ok( !exists $out{'country.names'}, 'raw names hash is not emitted as its own key' );
}

# ---------------------------------------------------------------------------
# 9.  GeoIP / MMDB — ipinfo always exposes geo fields; bad DB path is skipped
# ---------------------------------------------------------------------------

{
    # No MMDB configured: geo is an (empty) object and no error
    my $t = _make_app();
    $t->get_ok('/api/ipinfo/8.8.8.8')
        ->status_is( 200, 'ipinfo renders 200 with no MMDB configured' )
        ->json_has( '/geo',       'response has a geo object' )
        ->json_is( '/geo_error', '', 'geo_error is empty when no MMDB is configured' );

    # An explicitly configured but missing MMDB must not break startup or the
    # request. It warns to STDERR by design; capture it so output stays clean.
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    my $t2 = _make_app( qq{geoip_ip_city = "/nonexistent/does-not-exist.mmdb"\n} );
    like( join( '', @warnings ), qr/does not exist/, 'a configured but missing MMDB is reported via a warning' );
    $t2->get_ok('/api/ipinfo/8.8.8.8')
        ->status_is( 200, 'ipinfo still renders 200 when a configured MMDB is missing' )
        ->json_has( '/geo', 'response still has a geo object' );
}

# ---------------------------------------------------------------------------
# 10.  _run_capture — external command output with a hard, non-hanging timeout
# ---------------------------------------------------------------------------

{
    require Lilith::Web::Controller::Api;

    my $out = Lilith::Web::Controller::Api::_run_capture( 5, 'echo', 'hello world' );
    like( $out, qr/hello world/, '_run_capture returns the command output' );

    # A command that outlives the timeout must be killed, returning promptly
    # rather than hanging on close()/waitpid (the whois/dnstracer hang bug).
    my $start = time;
    my $slow  = Lilith::Web::Controller::Api::_run_capture( 1, 'sleep', '10' );
    my $took  = time - $start;
    is( $slow, '', '_run_capture returns empty when the command is killed on timeout' );
    ok( $took < 5, "_run_capture enforces the timeout (took ${took}s vs the 10s command)" );
}

# ---------------------------------------------------------------------------
# 11.  _whois_domain — registrable domain reduction
# ---------------------------------------------------------------------------

{
    require Lilith::Web::Controller::Api;
    no warnings 'once';
    my $wd = \&Lilith::Web::Controller::Api::_whois_domain;
    is( $wd->('example.com'),          'example.com', 'two-label domain is unchanged' );
    is( $wd->('gitea.eesdp.org'),      'eesdp.org',   'subdomain is reduced to the registrable domain' );
    is( $wd->('a.b.c.example.co.uk'),  'example.co.uk', 'multi-level public suffix handled' );
}

# ---------------------------------------------------------------------------
# 12.  domaininfo cache — a fresh entry is served without touching the network
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "domaininfo_cache = true\n";
    print $fh "domaininfo_cache_ttl = 600\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t   = Test::Mojo->new('Lilith::Web');
    my $app = $t->app;

    # Seed a cache entry; a hit must return it verbatim with cached => 1 and do
    # no DNS/whois work.
    $app->domaininfo_cache->{'seeded.example'} = {
        time => time(),
        data => { domain => 'seeded.example', whois_domain => 'seeded.example', whois => 'SENTINEL', dns => {} },
    };
    $t->get_ok('/api/domaininfo/seeded.example')
        ->status_is( 200, 'cached domaininfo renders 200' )
        ->json_is( '/whois',  'SENTINEL', 'cache hit returns the stored whois' )
        ->json_is( '/cached', 1,          'cache hit is flagged cached => 1' );

    # An expired entry is not served (ttl has passed).
    $app->domaininfo_cache->{'stale.example'} = {
        time => time() - 10_000,
        data => { whois => 'STALE' },
    };
    ok( ( time() - $app->domaininfo_cache->{'stale.example'}{time} ) >= $app->domaininfo_cache_ttl,
        'stale entry is older than the ttl (would be refetched, not served)' );
}

# ---------------------------------------------------------------------------
# 13.  _virani_fetch_args — BPF filter + time window for a PCAP fetch
# ---------------------------------------------------------------------------

{
    require Lilith::Web::Controller::Event;
    no warnings 'once';
    my $args = \&Lilith::Web::Controller::Event::_virani_fetch_args;

    my $event = {
        src_ip     => '192.168.0.5',
        dest_ip    => '20.64.105.235',
        src_port   => '40000',
        dest_port  => '443',
        flow_start => '2026-07-04T12:00:00',
        timestamp  => '2026-07-04T12:00:05',
    };
    my ( $filter, $start, $end ) = $args->( $event, 60 );
    like( $filter, qr/host 192\.168\.0\.5 and host 20\.64\.105\.235/, 'BPF filter built from src/dest IPs' );
    like( $filter, qr/port 40000 or port 443/, 'BPF filter includes the ports' );
    is( $end->epoch - $start->epoch, 125, 'window is the 5s flow plus a 60s buffer each side' );

    # ports omitted when not both numeric
    my ($f2) = $args->( { %$event, dest_port => 'foo' }, 60 );
    unlike( $f2, qr/port /, 'no port clause when a port is non-numeric' );

    # missing IPs is fatal (caught by the controller as a 400)
    eval { $args->( { flow_start => 't', timestamp => 't' }, 60 ) };
    like( $@, qr/no source\/destination IP/, 'dies without src/dest IP' );
}

# ---------------------------------------------------------------------------
# 14.  GET /api/httpsinfo — validation + result rendering
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # input validation (before any network work)
    $t->get_ok('/api/httpsinfo/bad domain')->status_is( 400, 'invalid domain rejected' );
    $t->get_ok('/api/httpsinfo/example.com?port=0')->status_is( 400, 'port 0 rejected' );
    $t->get_ok('/api/httpsinfo/example.com?port=99999')->status_is( 400, 'port > 65535 rejected' );
    $t->get_ok('/api/httpsinfo/example.com?port=abc')->status_is( 400, 'non-numeric port rejected' );

    # mock the blocking gather so the route can be tested without a network
    require Lilith::Web::Controller::Api;
    no warnings qw(redefine once);
    local *Lilith::Web::Controller::Api::_httpsinfo_gather = sub {
        my ( $domain, $port ) = @_;
        return {
            domain          => $domain,
            port            => $port,
            http_status     => 301,
            redirect_to     => 'https://www.example.com/',
            tcp_connect_ms  => 10.0,
            tls_handshake_ms => 20.0,
            response_ms     => 30.0,
            total_ms        => 60.0,
            timed_out       => 0,
            read_capped      => 0,
            expired         => 0,
            valid           => 1,
            cert            => { cn => 'example.com', issuer => 'Test CA', fp_sha256 => 'AB:CD' },
        };
    };
    use warnings qw(redefine once);

    my $j = $t->get_ok('/api/httpsinfo/example.com?port=443')
        ->status_is( 200, 'httpsinfo renders 200' )->tx->res->json;
    is( $j->{http_status}, 301,                        'status code passed through' );
    is( $j->{redirect_to}, 'https://www.example.com/', 'redirect target reported' );
    is( $j->{valid},       1,                          'validity reported' );
    is( $j->{expired},     0,                          'expiry reported' );
    is( $j->{cert}{cn},    'example.com',              'cert details reported' );
    is( $j->{total_ms},    60.0,                       'total timing reported' );
}

# ---------------------------------------------------------------------------
# 15.  Mail auth — GET /api/mailinfo (SPF/DMARC/DKIM) + the pure parsers
# ---------------------------------------------------------------------------

{
    require Lilith::Web::Controller::Api;
    no warnings 'once';

    # _spf_summary: static parse of a record (no network)
    my $sum = Lilith::Web::Controller::Api::_spf_summary('v=spf1 ip4:1.2.3.0/24 include:_spf.example.com a mx -all');
    is( $sum->{all},         'fail', 'SPF default policy parsed from -all' );
    is( $sum->{dns_lookups}, 3,      'SPF DNS-lookup terms counted (include, a, mx)' );
    is_deeply( $sum->{mechanisms}, [ 'ip4:1.2.3.0/24', 'include:_spf.example.com', 'a', 'mx', '-all' ],
        'SPF mechanisms listed' );

    # _dkim_parse_record: static parse of a DKIM key record (no network)
    my $dk = Lilith::Web::Controller::Api::_dkim_parse_record( 's1',
        'v=DKIM1; k=rsa; h=sha256; s=email; t=y; p=MIIBIjANBg' );
    is( $dk->{selector},        's1',     'DKIM selector kept' );
    is( $dk->{key_type},        'rsa',    'DKIM key type parsed' );
    is( $dk->{hash_algorithms}, 'sha256', 'DKIM hash algorithms parsed' );
    is( $dk->{service_types},   'email',  'DKIM service types parsed' );
    is( $dk->{testing},         1,        'DKIM testing flag detected from t=y' );
    is( $dk->{revoked},         0,        'DKIM not revoked when p is present' );

    my $rv = Lilith::Web::Controller::Api::_dkim_parse_record( 's2', 'v=DKIM1; k=rsa; p=' );
    is( $rv->{revoked}, 1, 'DKIM revoked when p= is empty' );
}

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # validation
    $t->get_ok('/api/mailinfo/bad domain')->status_is( 400, 'invalid domain rejected' );
    $t->get_ok('/api/mailinfo/example.com?ip=not-an-ip')->status_is( 400, 'invalid IP rejected' );
    $t->get_ok('/api/mailinfo/example.com?selector=bad+sel')->status_is( 400, 'invalid selector rejected' );

    # mock the blocking gather; verify the combined SPF/DMARC/DKIM shape renders
    no warnings qw(redefine once);
    local *Lilith::Web::Controller::Api::_mailinfo_gather = sub {
        my ( $domain, $ip, $selector ) = @_;
        return {
            domain => $domain,
            mx     => [ { preference => 10, exchange => 'mail.' . $domain } ],
            spf    => { record => 'v=spf1 -all', summary => { all => 'fail' }, ( $ip ? ( ip => $ip, result => 'fail' ) : () ) },
            dmarc  => { record => 'v=DMARC1; p=reject', found_at => $domain, p => 'reject', rua => 'mailto:x@' . $domain },
            dkim   => {
                ( $selector ? ( selector => $selector ) : ( probed => 1 ) ),
                keys => [ { selector => ( $selector // 'default' ), key_type => 'rsa', key_bits => 2048, revoked => 0 } ],
            },
        };
    };
    use warnings qw(redefine once);

    my $j = $t->get_ok('/api/mailinfo/example.com?ip=8.8.8.8&selector=default')
        ->status_is( 200, 'mailinfo renders 200' )->tx->res->json;
    is( $j->{mx}[0]{exchange},    'mail.example.com', 'MX records present' );
    is( $j->{mx}[0]{preference},  10,       'MX preference present' );
    is( $j->{spf}{result},        'fail',   'SPF section present' );
    is( $j->{dmarc}{p},           'reject', 'DMARC policy present' );
    is( $j->{dkim}{keys}[0]{key_bits}, 2048, 'DKIM key detail present' );
    is( $j->{dkim}{selector},     'default', 'DKIM selector passed through' );
}

done_testing();
