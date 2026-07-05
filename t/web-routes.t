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
        ->element_exists( 'span#ar-status', 'auto-refresh status indicator is present' );

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

done_testing();
