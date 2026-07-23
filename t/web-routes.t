#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;
use JSON qw(encode_json);
use MIME::Base64 qw(encode_base64);

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

    # No params — still renders the form (a default search runs but there is no
    # real DB, so the error is stashed and the page renders 200)
    $t->get_ok('/search')->status_is( 200, 'GET /search renders search form' )
        ->element_exists( 'input#auto-refresh[type="checkbox"]', 'auto-refresh checkbox is present' )
        ->element_exists( 'input#auto-refresh-secs[type="number"][value="30"]',
        'auto-refresh interval input defaults to 30' )
        ->element_exists( 'div.col-auto.ms-auto input#auto-refresh',
        'auto-refresh control sits in the far-right column' )
        ->element_exists( 'input#auto-fc[type="checkbox"]', 'Auto-FC checkbox is present' )
        ->element_exists( 'div.col-auto.ms-auto input#auto-fc',
        'Auto-FC control sits in the far-right column' )
        ->element_exists( 'span#ar-status', 'auto-refresh status indicator is present' )
        ->element_exists( 'input#nav-https-port[value="443"]', 'HTTPS port input defaults to 443' )
        ->element_exists( 'button#nav-https-btn',  'HTTPS button present in Domain Info' )
        ->element_exists( 'div#httpsinfo-modal',   'HTTPS info modal present' )
        ->element_exists( 'input#nav-mail-ip',       'SPF IP input present in Domain Info' )
        ->element_exists( 'input#nav-mail-selector', 'DKIM selector input present in Domain Info' )
        ->element_exists( 'button#nav-mail-btn',     'Mail button present in Domain Info' )
        ->element_exists( 'div#mailinfo-modal',      'Mail auth modal present' )
        ->element_exists( 'tbody#mailinfo-mx',       'MX section present' )
        ->element_exists( 'tbody#mailinfo-spf',      'SPF section present' )
        ->element_exists( 'tbody#mailinfo-dmarc',    'DMARC section present' )
        ->element_exists( 'div#mailinfo-dkim',       'DKIM section present' );

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

    # the classification selects allow multiple selections
    $t->get_ok('/search')
        ->element_exists( 'select[name="class"][multiple]',     'class select is a multi-select' )
        ->element_exists( 'select[name="class_not"][multiple]', 'class_not select is a multi-select' );

    # multiple class params render and are marked selected on the way back out
    $t->get_ok('/search?search=1&class=Misc+activity&class=Not+Suspicious+Traffic')
        ->status_is( 200, 'multiple class params render 200' )
        ->element_exists( 'option[value="Misc activity"][selected]',
        'first class param is selected in the form' )
        ->element_exists( 'option[value="Not Suspicious Traffic"][selected]',
        'second class param is selected in the form' )
        ->element_exists_not( 'select[name="class_not"] option[selected]',
        'class params do not mark the exclude select' );

    # class_not params round trip via the exclude select
    $t->get_ok('/search?search=1&class_not=Misc+activity')
        ->status_is( 200, 'class_not param renders 200' )
        ->element_exists( 'select[name="class_not"] option[value="Misc activity"][selected]',
        'class_not param is selected in the exclude select' )
        ->element_exists_not( 'select[name="class"] option[selected]',
        'class_not params do not mark the match select' );

    # a fresh form defaults to excluding Generic Protocol Command Decode ...
    $t->get_ok('/search')
        ->element_exists(
        'select[name="class_not"] option[value="Generic Protocol Command Decode"][selected]',
        'fresh form defaults to excluding GPCD' );

    # ... but a submitted search keeps the user's choice, even deselecting it
    $t->get_ok('/search?search=1')
        ->element_exists_not(
        'select[name="class_not"] option[value="Generic Protocol Command Decode"][selected]',
        'submitted search without class_not does not re-select GPCD' );
}

# ---------------------------------------------------------------------------
# 2b.  Search controller merges class/class_not for Lilith::search
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    my %captured;
    no warnings qw(redefine once);
    local *Lilith::search = sub {
        my ( $self, %opts ) = @_;
        %captured = %opts;
        return [];
    };
    use warnings qw(redefine once);

    $t->get_ok('/search?search=1&class=Misc+activity&class_not=Misc+Attack&class_not=Spam')
        ->status_is( 200, 'mixed class/class_not search renders 200' );
    is_deeply(
        $captured{class},
        [ 'Misc activity', '!Misc Attack', '!Spam' ],
        'class_not values reach search() negated after the class values'
    );
}

# ---------------------------------------------------------------------------
# 2d.  Explicit time range — the When toggle and start/end passthrough
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # the search form uses the reusable time-range control: a preset dropdown
    # (relative) plus a Custom range of native date + 24h hour/minute fields
    $t->get_ok('/search')->status_is( 200, 'search form renders' )
        ->element_exists( 'div.time-range',                                'has the reusable time-range control' )
        ->element_exists( 'select[data-role="preset"] option[value="custom"]', 'preset dropdown offers a Custom range' )
        ->element_exists( 'select[data-role="preset"] option[value="43200"]',  'and relative presets (30 days)' )
        ->element_exists( 'input[type="date"][data-role="start-date"]',    'custom range has a From date' )
        ->element_exists( 'input[type="number"][data-role="start-hour"][max="23"]', 'and a 24-hour From hour' )
        ->element_exists( 'input[type="hidden"][name="go_back_minutes"][data-role="minutes"]', 'emits go_back_minutes' )
        ->element_exists( 'input[type="hidden"][name="start"][data-role="start"]', 'emits start' )
        ->element_exists( 'script[src="/js/time-range.js"]',               'loads the shared time-range script' );

    my %captured;
    no warnings qw(redefine once);
    local *Lilith::search = sub { my ( $self, %opts ) = @_; %captured = %opts; return []; };
    use warnings qw(redefine once);

    $t->get_ok('/search?search=1&start=2026-07-18T00:00&end=2026-07-18T12:00')
        ->status_is( 200, 'range search renders 200' );
    is( $captured{start}, '2026-07-18T00:00', 'start reaches search()' );
    is( $captured{end},   '2026-07-18T12:00', 'end reaches search()' );

    # with no range params, start/end are undef (relative window is used)
    $t->get_ok('/search?search=1');
    ok( !defined $captured{start}, 'no start param -> undef' );
    ok( !defined $captured{end},   'no end param -> undef' );
}

# ---------------------------------------------------------------------------
# 2c.  Auto-refresh partial render — GET /search?...&partial=1
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    no warnings qw(redefine once);
    local *Lilith::search = sub {
        return [ { id => 42, timestamp => 't', src_ip => '8.8.8.8', classification => 'Misc Attack' } ];
    };
    use warnings qw(redefine once);

    my $full = $t->get_ok('/search?search=1&table=suricata')->tx->res->body;
    my $part = $t->get_ok('/search?search=1&table=suricata&partial=1')
        ->status_is( 200, 'partial render returns 200' )->tx->res->body;

    # the fragment has the results container and the row ...
    like( $part, qr/id="search-results"/, 'partial contains the results container' );
    like( $part, qr{/event/suricata/42},  'partial contains the result row' );

    # ... but none of the page chrome (layout, navbar, filter form)
    unlike( $part, qr/<html/,        'partial has no layout/html wrapper' );
    unlike( $part, qr/id="filter-panel"/, 'partial has no filter panel' );
    unlike( $part, qr/navbar/,       'partial has no navbar' );

    # and it is dramatically smaller than the full page
    ok( length($part) < length($full) / 2, 'partial is much smaller than the full page' );

    # pagination links must not carry partial=1 (they do full navigation)
    my $paged = $t->get_ok('/search?search=1&table=suricata&limit=1&partial=1')->tx->res->body;
    unlike( $paged, qr/offset=\d+[^"]*partial=1/, 'pagination links drop the partial param' );

    # a bare /search (no params) runs the default search and shows results
    my %opts;
    {
        no warnings qw(redefine once);
        local *Lilith::search = sub {
            my ( $s, %o ) = @_;
            %opts = %o;
            return [ { id => 7, timestamp => 't', src_ip => '8.8.8.8', classification => 'Misc Attack' } ];
        };
        my $bare = $t->get_ok('/search')->status_is( 200, 'bare /search renders 200' )->tx->res->body;
        like( $bare, qr/id="search-results"/,   'bare /search shows the results container' );
        like( $bare, qr{/event/suricata/7},     'bare /search shows default-search results' );
    }
    is( $opts{table},           'suricata', 'default search uses the suricata table' );
    is( $opts{go_back_minutes}, 1440,       'default search uses the 1440-minute window' );
    is( $opts{limit},           100,        'default search uses the default limit' );
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

# ---------------------------------------------------------------------------
# 3-0.  Suricata protocol cards — the top-level EVE drives the card selection
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # a normal Suricata row: app_proto column + http sub-object at the top of raw
    no warnings qw(redefine once);
    local *Lilith::search = sub {
        return [
            {   id        => 1,
                app_proto => 'http',
                raw       => encode_json( { http => { hostname => 'plain.suricata.example', http_method => 'GET' } } ),
            }
        ];
    };
    use warnings qw(redefine once);

    $t->get_ok('/event/suricata/1')->status_is( 200, 'suricata event renders 200' )
        ->content_like( qr/HTTP Details/,          'suricata http card still renders after the refactor' )
        ->content_like( qr/plain\.suricata\.example/, 'and shows the http hostname' );
}

# ---------------------------------------------------------------------------
# 3-1.  Baphomet protocol cards — a verdict that judged a Suricata line carries
#       the original EVE under raw.raw, and the cards render off of it
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # Case A: nested raw is already a hash; app_proto=http picks the HTTP card,
    # and the payload rides along under the embedded EVE.
    {
        no warnings qw(redefine once);
        local *Lilith::search = sub {
            return [
                {   id         => 1,
                    event_type => 'alert',
                    kur        => 'baphomet-ids',
                    raw        => encode_json(
                        {   event_type => 'alert',
                            kur        => 'baphomet-ids',
                            raw        => {
                                app_proto => 'http',
                                http      => { hostname => 'login.evil.example', http_method => 'POST', url => '/steal' },
                                payload   => 'YmFzZTY0cGF5bG9hZA==',
                            },
                        }
                    ),
                }
            ];
        };
        use warnings qw(redefine once);

        $t->get_ok('/event/baphomet/1')->status_is( 200, 'baphomet event renders 200' )
            ->content_like( qr/HTTP Details/,        'embedded suricata http card renders for baphomet' )
            ->content_like( qr/login\.evil\.example/, 'and shows the embedded http hostname' )
            ->element_exists( '#download-payload-btn', 'the embedded payload download button appears' )
            ->content_unlike( qr/TLS Details/, 'only the card matching the embedded app_proto renders' );
    }

    # Case B: nested raw arrives as a JSON *string*; the controller promotes it
    # to a hash so a declarative card (TLS) still renders.
    {
        no warnings qw(redefine once);
        local *Lilith::search = sub {
            return [
                {   id         => 2,
                    event_type => 'alert',
                    raw        => encode_json(
                        {   event_type => 'alert',
                            raw        => encode_json(
                                { app_proto => 'tls', tls => { sni => 'c2.evil.example', version => 'TLS 1.3' } }
                            ),
                        }
                    ),
                }
            ];
        };
        use warnings qw(redefine once);

        $t->get_ok('/event/baphomet/2')->status_is( 200, 'baphomet event with a string-nested raw renders 200' )
            ->content_like( qr/TLS Details/,     'a string-nested embedded EVE is promoted and its card renders' )
            ->content_like( qr/c2\.evil\.example/, 'and shows the embedded tls sni' );
    }

    # Case C: nested raw is a plain, non-JSON string; the defensive ref checks
    # mean no protocol cards render, but the page is still fine.
    {
        no warnings qw(redefine once);
        local *Lilith::search = sub {
            return [
                {   id         => 3,
                    event_type => 'banish',
                    raw        => encode_json( { event_type => 'banish', raw => 'not json, just a log line' } ),
                }
            ];
        };
        use warnings qw(redefine once);

        $t->get_ok('/event/baphomet/3')->status_is( 200, 'baphomet event with a non-JSON raw string renders 200' )
            ->content_unlike( qr/HTTP Details|TLS Details/, 'no protocol cards render when raw is not a decodable EVE' );
    }
}

# ---------------------------------------------------------------------------
# 3a.  Virani PCAP download — GET /event/:t/:id/pcap
# ---------------------------------------------------------------------------

# With no [virani.*] configured the feature is off: no button, route is 404.
{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    no warnings qw(redefine once);
    local *Lilith::search = sub {
        return [ { id => 5, instance => 'inari-pie', src_ip => '1.1.1.1', dest_ip => '2.2.2.2', raw => '{}' } ];
    };
    use warnings qw(redefine once);

    $t->get_ok('/event/suricata/5')->status_is(200)
        ->element_exists_not( 'div#pcap-controls', 'no PCAP controls when no virani configured' );
    $t->get_ok('/event/suricata/5/pcap?remote=inari-pie')
        ->status_is( 404, 'pcap route is 404 when virani is not configured' );
}

# With [virani.*] configured: button appears, and the route streams the PCAP.
{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh qq{[virani.inari-pie]\nurl = "https://v.example/"\napikey = "k"\nset = "default"\n};
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    require Virani::Client;
    no warnings qw(redefine once);
    local *Lilith::search = sub {
        return [
            {   id         => 9,
                instance   => 'inari-pie',
                src_ip     => '192.168.0.5',
                dest_ip    => '20.64.105.235',
                src_port   => '40000',
                dest_port  => '443',
                flow_start => '2026-07-04T12:00:00',
                timestamp  => '2026-07-04T12:00:05',
                raw        => '{}',
            }
        ];
    };
    # The fetch runs in a subprocess, so it (and any capture) happens in a child;
    # the mock just writes the pcap bytes the parent will stream back.
    local *Virani::Client::fetch = sub {
        my ( $self, %o ) = @_;
        open( my $w, '>:raw', $o{file} ); print $w "PCAPBYTES"; close($w);
        return '{}';
    };
    use warnings qw(redefine once);

    # PCAP controls present in the event view (remote hidden input, set select,
    # download button, and the local-command menu item)
    $t->get_ok('/event/suricata/9')->status_is(200)
        ->element_exists( 'div#pcap-controls',    'PCAP controls present when configured' )
        ->element_exists( 'button#pcap-dl',       'download button present' )
        ->element_exists( 'select#pcap-set',      'set selector present' )
        ->element_exists( 'a#pcap-local',         'local-command menu item present' )
        ->element_exists( '#pcap-local-cmd button#pcap-cmd-close', 'local-command area has a close button' );

    # unknown remote is rejected
    $t->get_ok('/event/suricata/9/pcap?remote=nope')
        ->status_is( 400, 'unknown virani remote is 400' );

    # non-suricata table is rejected
    $t->get_ok('/event/cape/9/pcap?remote=inari-pie')
        ->status_is( 400, 'pcap on a non-suricata table is 400' );

    # happy path streams the pcap (fetched in a subprocess, streamed by the parent)
    $t->get_ok('/event/suricata/9/pcap?remote=inari-pie')
        ->status_is( 200, 'pcap download renders 200' )
        ->header_is( 'Content-Type' => 'application/vnd.tcpdump.pcap', 'served as a pcap' )
        ->header_is( 'Content-Disposition' => 'attachment; filename="event-9.pcap"', 'pcap download filename' )
        ->content_is( 'PCAPBYTES', 'the fetched pcap bytes are streamed back' );

    # an explicit set is validated
    $t->get_ok('/event/suricata/9/pcap?remote=inari-pie&set=bad%20set')
        ->status_is( 400, 'a malformed set is rejected' );

    # the sets endpoint returns the remote's available sets
    no warnings qw(redefine once);
    local *Virani::Client::get_sets = sub {
        return '{"sets":{"http":{},"dns":{}},"default_set":"http"}';
    };
    use warnings qw(redefine once);

    $t->get_ok('/api/virani/sets/inari-pie')
        ->status_is( 200, 'sets endpoint renders 200' )
        ->json_is( '/default_set', 'http', 'default_set reported' )
        ->json_is( '/sets',        [ 'dns', 'http' ], 'sets listed (sorted)' );

    $t->get_ok('/api/virani/sets/nope')
        ->status_is( 400, 'sets endpoint rejects an unknown remote' );
}

# ---------------------------------------------------------------------------
# 3a-ii.  Standalone Virani PCAP search — modal gating + GET /api/virani/pcap
# ---------------------------------------------------------------------------

# Search DOWNLOAD disabled (default): navbar modal offers only the command; the
# general pcap route is a 404.
{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh qq{[virani.r1]\nurl = "https://v.example/"\n};
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok('/search')->status_is(200)
        ->element_exists( 'button#nav-virani-toggle', 'Virani navbar dropdown present' )
        ->element_exists( 'a.dropdown-item[data-bs-target="#virani-modal"]', 'PCAP Search dropdown item present' )
        ->element_exists( 'div#virani-modal',       'Virani search modal present' )
        ->element_exists( 'button#virani-show-cmd', 'show-command button present' )
        ->element_exists_not( 'button#virani-download', 'download button hidden when search disabled' )
        ->element_exists_not( 'a.dropdown-item[data-bs-target="#virani-cache-modal"]',
        'Cached Searches item hidden when search disabled' )
        ->element_exists_not( 'div#virani-cache-modal', 'cached modal absent when search disabled' );

    $t->get_ok('/api/virani/pcap?remote=r1&filter=host+1.2.3.4&start=1000&end=2000')
        ->status_is( 404, 'general pcap route is 404 when search is disabled' );
    $t->get_ok('/api/virani/cached/r1')
        ->status_is( 404, 'cached list is 404 when search is disabled' );
}

# Search enabled: download button shown and the route streams.
{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "virani_search_enable = true\n";
    print $fh qq{[virani.r1]\nurl = "https://v.example/"\n};
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    $t->get_ok('/search')->status_is(200)
        ->element_exists( 'button#virani-download', 'download button shown when search enabled' )
        ->element_exists( 'a.dropdown-item[data-bs-target="#virani-cache-modal"]',
        'Cached Searches item shown when search enabled' )
        ->element_exists( 'div#virani-cache-modal',  'cached modal present when search enabled' )
        ->element_exists( 'tbody#virani-cache-rows', 'cached results table present' );

    require Virani::Client;
    no warnings qw(redefine once);
    local *Virani::Client::fetch = sub {
        my ( $self, %o ) = @_;
        open( my $w, '>:raw', $o{file} ); print $w 'SEARCHPCAP'; close($w);
        return '{}';
    };
    my $md5 = 'a' x 32;
    # list_cached without filter/final_size (older Virani); those come from meta.
    local *Virani::Client::list_cached = sub {
        return encode_json(
            [   { id => "setA-tcpdump-1000-2000-$md5", set => 'setA', type => 'tcpdump',
                    start_s => 1000, end_s => 2000, has_pcap => 1 },
                { id => "setA-tcpdump-3000-4000-$md5", set => 'setA', type => 'tcpdump',
                    start_s => 3000, end_s => 4000, has_pcap => 1 },
            ]
        );
    };
    local *Virani::Client::fetch_cached = sub {
        my ( $self, %o ) = @_;
        if ( $o{meta_only} ) {
            my ($end) = $o{id} =~ /-(\d+)-[a-f0-9]{32}\z/;
            return encode_json(
                {   pcap_count    => 10,
                    success_count => 7,
                    filter        => ( $end == 4000 ? 'port 443' : 'host 1.1.1.1' ),
                    final_size    => ( $end == 4000 ? 5678       : 1234 ),
                }
            );
        }
        open( my $w, '>:raw', $o{file} ); print $w 'CACHEDPCAP'; close($w);
        return '{}';
    };
    use warnings qw(redefine once);

    # cached list is newest-first and enriched from metadata (counts, filter, size)
    my $cached = $t->get_ok('/api/virani/cached/r1')->status_is( 200, 'cached list renders 200' )->tx->res->json;
    is( scalar( @{ $cached->{cached} } ), 2, 'two cached searches listed' );
    is( $cached->{cached}[0]{start_s},    3000,       'cached list is newest-first' );
    is( $cached->{cached}[0]{found},      10,         'found count enriched from metadata' );
    is( $cached->{cached}[0]{success},    7,          'success count enriched from metadata' );
    is( $cached->{cached}[0]{filter},     'port 443', 'filter enriched from metadata' );
    is( $cached->{cached}[0]{final_size}, 5678,       'final_size enriched from metadata' );

    # cached pcap streams
    $t->get_ok( '/api/virani/cached/r1/pcap/setA-tcpdump-3000-4000-' . $md5 )
        ->status_is( 200, 'cached pcap streams 200' )
        ->header_is( 'Content-Type' => 'application/vnd.tcpdump.pcap', 'served as a pcap' )
        ->content_is( 'CACHEDPCAP', 'cached pcap bytes streamed' );

    # cached pcap validation
    $t->get_ok('/api/virani/cached/nope/pcap/x')->status_is( 400, 'cached pcap unknown remote rejected' );
    $t->get_ok('/api/virani/cached/r1/pcap/bad%20id')->status_is( 400, 'cached pcap invalid id rejected' );

    # cached metadata JSON download
    $t->get_ok( '/api/virani/cached/r1/meta/setA-tcpdump-3000-4000-' . $md5 )
        ->status_is( 200, 'cached metadata renders 200' )
        ->header_is( 'Content-Type' => 'application/json', 'served as json' )
        ->header_is( 'Content-Disposition' => 'attachment; filename="virani-cached-setA-tcpdump-3000-4000-' . $md5 . '.json"',
        'metadata download filename' )
        ->json_is( '/filter', 'port 443', 'metadata JSON body is the entry metadata' );
    $t->get_ok('/api/virani/cached/r1/meta/bad%20id')->status_is( 400, 'cached meta invalid id rejected' );

    $t->get_ok('/api/virani/pcap?remote=r1&filter=host+1.2.3.4&start=1000&end=2000')
        ->status_is( 200, 'general pcap search streams 200' )
        ->header_is( 'Content-Type' => 'application/vnd.tcpdump.pcap', 'served as a pcap' )
        ->header_is( 'Content-Disposition' => 'attachment; filename="virani-1000-2000.pcap"', 'download filename' )
        ->content_is( 'SEARCHPCAP', 'streamed pcap bytes' );

    # validation
    $t->get_ok('/api/virani/pcap?remote=r1&filter=&start=1000&end=2000')
        ->status_is( 400, 'empty filter rejected' );
    $t->get_ok('/api/virani/pcap?remote=r1&filter=x&start=2000&end=1000')
        ->status_is( 400, 'start after end rejected' );
    $t->get_ok('/api/virani/pcap?remote=nope&filter=x&start=1&end=2')
        ->status_is( 400, 'unknown remote rejected' );
    $t->get_ok('/api/virani/pcap?remote=r1&filter=x&start=notepoch&end=2')
        ->status_is( 400, 'non-epoch times rejected' );
}

# ---------------------------------------------------------------------------
# 3b.  HTTP body password-protected zip download — GET /event/:t/:id/body/:w/zip
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $t = Test::Mojo->new('Lilith::Web');

    # bad "which" and non-numeric id are rejected before any DB access
    $t->get_ok('/event/suricata/1/body/bogus/zip')->status_is( 400, 'invalid body type is 400' );
    $t->get_ok('/event/suricata/abc/body/response/zip')->status_is( 400, 'non-numeric id is 400' );

    my $payload = "GIF89a\x00\x01 this is the fake malicious response body \xDE\xAD\xBE\xEF";

    no warnings qw(redefine once);
    local *Lilith::search = sub {
        my ( $self, %opts ) = @_;
        return [
            {
                id  => $opts{id}[0],
                raw => encode_json(
                    {
                        http => {
                            http_response_body => encode_base64( $payload, '' ),
                        },
                    }
                ),
            }
        ];
    };
    use warnings qw(redefine once);

    # missing body type on the event → 404
    {
        no warnings qw(redefine once);
        local *Lilith::search = sub { return [ { id => 1, raw => encode_json( { http => {} } ) } ] };
        use warnings qw(redefine once);
        $t->get_ok('/event/suricata/1/body/request/zip')->status_is( 404, 'absent body is 404' );
    }

    my $tx = $t->get_ok('/event/suricata/7/body/response/zip')
        ->status_is( 200, 'response body zip download renders 200' )
        ->header_is( 'Content-Type' => 'application/zip', 'served as application/zip' )
        ->header_is(
        'Content-Disposition' => 'attachment; filename="response-body-7.zip"',
        'zip has the expected download filename'
        )->tx;

    my $zipbytes = $tx->res->body;
    like( substr( $zipbytes, 0, 2 ), qr/^PK/, 'download body is a zip archive' );

    # the archive must actually decrypt with the "infected" password and yield
    # the original bytes back under the expected member name
  SKIP: {
        my $unzip = `sh -c 'command -v unzip' 2>/dev/null`;
        chomp $unzip;
        skip 'unzip not available', 1 unless $unzip;

        my ( $zh, $zpath ) = tempfile( SUFFIX => '.zip', UNLINK => 1 );
        binmode $zh;
        print $zh $zipbytes;
        close $zh;

        my $got = `unzip -p -P infected \Q$zpath\E response-body-7 2>/dev/null`;
        is( $got, $payload, 'zip decrypts with password "infected" back to the original body' );
    }
}

# ---------------------------------------------------------------------------
# CAPE submission — off by default (no nav button, routes 404); on when
# cape_enable is set with a [cape_servers.*] configured.
# ---------------------------------------------------------------------------
{
    my $t = _make_app('');
    $t->get_ok('/search')->status_is( 200, 'search renders with cape off' )
        ->element_exists_not( '#nav-cape-submit', 'no CAPE nav button when disabled' );
    $t->get_ok('/cape_submit')->status_is( 404, 'GET /cape_submit is 404 when disabled' );
    $t->post_ok('/api/cape_submit/submit')->status_is( 404, 'submit endpoint is 404 when disabled' );
}

# cape_enable = false (the TOML parser yields the string "false", which is truthy
# in Perl) must still read as off, even with a server configured.
{
    my $t = _make_app( "cape_enable = false\n\n[cape_servers.main]\nurl = \"http://127.0.0.1:9/\"\n" );
    $t->get_ok('/search')->status_is( 200, 'search renders with cape_enable=false' )
        ->element_exists_not( '#nav-cape-submit', 'cape_enable=false leaves the feature off' );
    $t->get_ok('/cape_submit')->status_is( 404, 'GET /cape_submit is 404 with cape_enable=false' );
}

{
    my $extra = "cape_enable = true\n"
        . "cape_slug = \"lil\"\n\n"
        . "[cape_servers.main]\n"
        . "url = \"http://127.0.0.1:9/\"\n"
        . "apikey_needed = false\n";
    my $t = _make_app($extra);

    $t->get_ok('/search')->status_is( 200, 'search renders with cape on' )
        ->element_exists( 'a#nav-cape-submit', 'CAPE nav button present when enabled' );

    $t->get_ok('/cape_submit')->status_is( 200, 'GET /cape_submit renders when enabled' )
        ->element_exists( 'form#cape-submit-form', 'submission form present' )
        ->element_exists( 'input#cape-file',       'file input present' )
        ->content_like( qr/value="lil"/, 'slug defaults to cape_slug' );

    # a submit with no file is rejected before any network call
    $t->post_ok('/api/cape_submit/submit')->status_is( 400, 'submit with no file is 400' )
        ->json_is( '/status' => 'error', 'no-file submit reports an error' );
}

done_testing();
