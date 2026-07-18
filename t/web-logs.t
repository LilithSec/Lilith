#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;

use_ok('Lilith::Web')    or BAIL_OUT('Lilith::Web failed to load');
use_ok('Lilith::Allani') or BAIL_OUT('Lilith::Allani failed to load');

sub _app {
    my ($extra_toml) = @_;
    $extra_toml //= '';

    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh $extra_toml;
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    return Test::Mojo->new('Lilith::Web');
}

# ---------------------------------------------------------------------------
# 1.  No [allani] block: feature off. Nav entry hidden, /logs still renders a
#     200 with a "not configured" notice, and the record view is a 404.
# ---------------------------------------------------------------------------

{
    my $t = _app();

    $t->get_ok('/search')->status_is( 200, 'GET /search renders' )
        ->element_exists_not( 'a#nav-logs', 'no Logs nav entry when Allani is not configured' );

    $t->get_ok('/logs')->status_is( 200, 'GET /logs renders even when not configured' )
        ->element_exists( 'div.alert-danger', 'a not-configured notice is shown' )
        ->element_exists_not( 'a#nav-logs', 'no Logs nav entry on /logs when not configured' );

    $t->get_ok('/logs/syslog/1')->status_is( 404, 'record view is 404 when not configured' );
}

# ---------------------------------------------------------------------------
# 2.  With [allani] configured: the reader is mocked so the test does not need
#     a live Allani database (or Allani installed).
# ---------------------------------------------------------------------------

{
    no warnings qw(redefine once);
    local *Lilith::Allani::new          = sub { return bless {}, 'Lilith::Allani' };
    local *Lilith::Allani::sources      = sub {
        return [ { key => 'syslog', label => 'syslog' }, { key => 'http_all', label => 'http (interleaved)' } ];
    };
    local *Lilith::Allani::valid_source = sub { return ( $_[1] eq 'syslog' || $_[1] eq 'http_all' ) ? 1 : 0 };
    local *Lilith::Allani::filters      = sub { return [qw( host message )] };
    my %search_opts;
    local *Lilith::Allani::search = sub {
        my ( $self, %o ) = @_;
        %search_opts = %o;
        return {
            source  => $o{source},
            headers => [qw( id time host message )],
            rows    => [ { id => 1, time => '2026-07-17T00:00:00Z', host => 'db1', message => 'boom' } ],
        };
    };
    local *Lilith::Allani::row = sub {
        return { id => 1, host => 'db1', program => 'sshd', raw => '{"MESSAGE":"boom"}' };
    };
    use warnings qw(redefine once);

    my $t = _app(qq{[allani]\ndsn = "dbi:Pg:dbname=allani"\nuser = "allani"\n});

    # nav entry + source selector + a result row that links to the record view
    $t->get_ok('/logs')->status_is( 200, 'GET /logs renders when configured' )
        ->element_exists( 'a#nav-logs', 'Logs nav entry present when configured' )
        ->element_exists( 'select#source-sel option[value="syslog"]',   'syslog source option present' )
        ->element_exists( 'select#source-sel option[value="http_all"]', 'http_all source option present' )
        ->element_exists( 'div#log-results',              'results container present' )
        ->element_exists( 'a[href="/logs/syslog/1"]',     'result row links to the record view' );

    # an unknown source is sanitized back to syslog
    $t->get_ok('/logs?source=bogus')->status_is( 200, 'unknown source is sanitized' );
    is( $search_opts{source}, 'syslog', 'unknown source falls back to syslog' );

    # only source-valid filters are forwarded to the reader
    $t->get_ok('/logs?source=syslog&host=db1&message=boom&vhost=nope');
    is( $search_opts{filters}{host},    'db1',  'host filter forwarded' );
    is( $search_opts{filters}{message}, 'boom', 'message filter forwarded' );
    ok( !exists $search_opts{filters}{vhost}, 'a filter not valid for the source is dropped' );

    # partial render returns just the fragment
    my $part = $t->get_ok('/logs?source=syslog&partial=1')
        ->status_is( 200, 'partial render 200' )->tx->res->body;
    like( $part, qr/id="log-results"/, 'partial has the results container' );
    unlike( $part, qr/<html/,  'partial has no layout wrapper' );
    unlike( $part, qr/navbar/, 'partial has no navbar' );

    # the record view renders the row + its raw
    $t->get_ok('/logs/syslog/1')->status_is( 200, 'record view renders' )
        ->content_like( qr/sshd/,  'record view shows a column value' )
        ->content_like( qr/MESSAGE/, 'record view shows the raw JSON' );
}

# ---------------------------------------------------------------------------
# 3.  Event page "logs around this event" deep-links (Phase 2). These need only
#     allani_enabled (not the reader), so the event's host/src_ip drive them.
# ---------------------------------------------------------------------------

{
    no warnings qw(redefine once);
    local *Lilith::search = sub {
        return [
            {   id        => 9,
                host      => 'web1',
                src_ip    => '203.0.113.5',
                timestamp => '2026-07-17T00:00:00',
                raw       => '{}',
            }
        ];
    };
    use warnings qw(redefine once);

    # configured: the Logs dropdown appears with a syslog-by-host and an
    # http_all-by-client link
    {
        my $t = _app(qq{[allani]\ndsn = "dbi:Pg:dbname=allani"\n});
        $t->get_ok('/event/suricata/9')->status_is( 200, 'event view renders with Allani configured' )
            ->element_exists( 'button#event-logs-toggle', 'Logs dropdown present on the event view' )
            ->element_exists( 'a.dropdown-item[href*="source=syslog"][href*="host=web1"]',
            'syslog-by-host deep-link present' )
            ->element_exists( 'a.dropdown-item[href*="source=http_all"][href*="client_ip=203.0.113.5"]',
            'http_all-by-client deep-link present' )
            ->element_exists( 'a.dropdown-item[href*="go_back_minutes="]',
            'deep-links carry a go_back_minutes window' );
    }

    # not configured: no Logs dropdown
    {
        my $t = _app();
        $t->get_ok('/event/suricata/9')->status_is( 200, 'event view renders without Allani' )
            ->element_exists_not( 'button#event-logs-toggle', 'no Logs dropdown when Allani is not configured' );
    }
}

done_testing();
