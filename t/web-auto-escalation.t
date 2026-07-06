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

# a representative rule row as auto_escalations() would return it
sub _sample_rules {
    return [
        {   id            => 1,
            name          => 'high-malscore',
            enabled       => 1,
            priority      => 50,
            stop_on_match => 1,
            tables        => ['cape'],
            rule          => {
                match   => { field => 'malscore', op => '>=', value => 8 },
                actions => [ { escalate_to => ['soc-hook'] } ],
            },
            description  => 'nasty cape submissions',
            last_matched => '2026-07-05 00:00:00+00',
            match_count  => 17,
        }
    ];
}

sub _sample_targets {
    return [ { id => 1, name => 'soc-hook', enabled => 1 } ];
}

# ---------------------------------------------------------------------------
# 1.  Disabled (default): everything 404s and no navbar link
# ---------------------------------------------------------------------------

{
    my $t = _make_app();

    $t->get_ok('/auto_escalation')->status_is( 404, 'page 404 when escalation disabled' );
    $t->get_ok('/api/auto_escalation/rules')->status_is( 404, 'rules API 404 when disabled' );
    $t->post_ok('/api/auto_escalation/rules')->status_is( 404, 'save 404 when disabled' );
    $t->post_ok('/api/auto_escalation/rules/1/delete')->status_is( 404, 'delete 404 when disabled' );
    $t->post_ok('/api/auto_escalation/rules/1/toggle')->status_is( 404, 'toggle 404 when disabled' );
    $t->post_ok('/api/auto_escalation/preview')->status_is( 404, 'preview 404 when disabled' );

    $t->get_ok('/search')->status_is(200)
        ->element_exists_not( 'a#nav-auto-escalation', 'no navbar link when disabled' );
}

# ---------------------------------------------------------------------------
# 2.  View only (escalation_enable on, manage off): read UI + preview,
#     but mutations are 403
# ---------------------------------------------------------------------------

{
    my $t = _make_app("escalation_enable = true\n");

    no warnings qw(redefine once);
    local *Lilith::auto_escalations   = sub { _sample_rules() };
    local *Lilith::escalation_targets = sub { _sample_targets() };
    # preview runs the real auto_escalation_preview + evaluate in a subprocess;
    # the fork inherits these mocks
    local *Lilith::search = sub {
        return [
            { id => 100, malscore => 9, signature => 'nasty',  src_ip => '1.2.3.4', dest_ip => '5.6.7.8', stop => 't1', raw => '{}' },
            { id => 101, malscore => 3, signature => 'benign', src_ip => '1.2.3.4', dest_ip => '5.6.7.8', stop => 't2', raw => '{}' },
        ];
    };
    use warnings qw(redefine once);

    $t->get_ok('/search')->status_is(200)
        ->element_exists( 'a#nav-auto-escalation', 'navbar link present when escalation enabled' );

    $t->get_ok('/auto_escalation')->status_is( 200, 'page renders' )
        ->element_exists( 'table#ae-rules-table',      'rules table present' )
        ->element_exists( 'button.rule-edit-btn',      'view button present' )
        ->element_exists_not( 'button#rule-add-btn',   'no add button when management off' )
        ->element_exists_not( 'input.rule-toggle',     'no enable toggle when management off' )
        ->element_exists_not( 'button.rule-delete-btn','no delete button when management off' )
        ->element_exists_not( 'button#rule-save-btn',  'no save button when management off' )
        ->content_like( qr/read-only/, 'read-only notice shown' )
        ->content_like( qr/high-malscore/, 'rule name shown' );

    # read endpoint works
    my $rules = $t->get_ok('/api/auto_escalation/rules')->status_is(200)->tx->res->json->{rules};
    is( $rules->[0]{name}, 'high-malscore', 'rules API returns the rule' );

    # mutations are forbidden
    $t->post_ok( '/api/auto_escalation/rules' => json => { name => 'x', rule => {} } )
        ->status_is( 403, 'save is 403 when management off' )
        ->json_like( '/error', qr/management is disabled/, 'save 403 message' );
    $t->post_ok('/api/auto_escalation/rules/1/delete')->status_is( 403, 'delete is 403 when management off' );
    $t->post_ok( '/api/auto_escalation/rules/1/toggle' => json => { enabled => 0 } )
        ->status_is( 403, 'toggle is 403 when management off' );

    # preview is allowed in the read tier and never sends
    $t->post_ok(
        '/api/auto_escalation/preview' => json => {
            rule            => { match => { field => 'malscore', op => '>=', value => 8 }, actions => [ { escalate_to => ['soc-hook'] } ] },
            table           => 'cape',
            go_back_minutes => 60,
        }
    )->status_is( 200, 'preview renders 200 in the read tier' )
        ->json_is( '/scanned', 2, 'preview scanned count' )
        ->json_is( '/matched', 1, 'preview matched only the high-malscore alert' )
        ->json_is( '/matches/0/id', 100, 'preview returns the matching alert id' );

    # a bad rule is a 400 from preview
    $t->post_ok( '/api/auto_escalation/preview' => json => { rule => { match => { field => 'x', op => 'bogus', value => 1 }, actions => [ { escalate_to => ['soc-hook'] } ] } } )
        ->status_is( 400, 'invalid rule preview is a 400' );
}

# ---------------------------------------------------------------------------
# 3.  Management on (both flags): full CRUD UI + endpoints
# ---------------------------------------------------------------------------

{
    my $t = _make_app("escalation_enable = true\nauto_escalation_manage_enable = true\n");

    my %created;
    my %updated;
    my $deleted;
    no warnings qw(redefine once);
    local *Lilith::auto_escalations = sub { _sample_rules() };
    local *Lilith::escalation_targets = sub { _sample_targets() };
    local *Lilith::auto_escalation_create = sub {
        my ( $self, %opts ) = @_;
        Lilith::AutoEscalate->check_rule( $opts{rule} );    # validate like the real method
        %created = %opts;
        return 9;
    };
    local *Lilith::auto_escalation_update = sub {
        my ( $self, %opts ) = @_;
        %updated = %opts;
        return 1;
    };
    local *Lilith::auto_escalation_delete = sub {
        my ( $self, $id ) = @_;
        $deleted = $id;
        return 1;
    };
    use warnings qw(redefine once);

    $t->get_ok('/auto_escalation')->status_is(200)
        ->element_exists( 'button#rule-add-btn',    'add button present when management on' )
        ->element_exists( 'input.rule-toggle',      'enable toggle present when management on' )
        ->element_exists( 'button.rule-delete-btn', 'delete button present when management on' )
        ->element_exists( 'button#rule-save-btn',   'save button present when management on' );

    # create
    $t->post_ok(
        '/api/auto_escalation/rules' => json => {
            name          => 'c2-beacon',
            rule          => { match => { field => 'signature', op => 'regex', value => 'cobalt' }, actions => [ { escalate_to => ['soc-hook'] } ] },
            tables        => ['suricata'],
            priority      => 100,
            stop_on_match => 0,
            enabled       => 1,
        }
    )->status_is( 200, 'create renders 200' )->json_is( '/ok', 1 )->json_is( '/id', 9 );
    is( $created{name},        'c2-beacon',    'create passes the name through' );
    is_deeply( $created{tables}, ['suricata'], 'create passes the tables through' );

    # update (id present)
    $t->post_ok(
        '/api/auto_escalation/rules' => json => {
            id      => 1,
            name    => 'high-malscore',
            rule    => { match => { field => 'malscore', op => '>=', value => 9 }, actions => [ { escalate_to => ['soc-hook'] } ] },
            enabled => 0,
        }
    )->status_is( 200, 'update renders 200' )->json_is( '/ok', 1 );
    is( $updated{id},      1, 'update passes the id through' );
    is( $updated{enabled}, 0, 'update passes the enabled flag through' );

    # invalid rule surfaces as a 400
    $t->post_ok( '/api/auto_escalation/rules' => json => { name => 'bad', rule => { match => { field => 'malscore', op => '>=', value => 8 }, actions => [] } } )
        ->status_is( 400, 'invalid rule create is a 400' )
        ->json_like( '/error', qr/actions/, 'validation error passed through' );

    # toggle
    $t->post_ok( '/api/auto_escalation/rules/1/toggle' => json => { enabled => 1 } )
        ->status_is( 200, 'toggle renders 200' )->json_is( '/enabled', 1 );
    is( $updated{enabled}, 1, 'toggle updates enabled' );

    # delete
    $t->post_ok('/api/auto_escalation/rules/1/delete')->status_is( 200, 'delete renders 200' )->json_is( '/ok', 1 );
    is( $deleted, 1, 'delete passes the id through' );
    $t->post_ok('/api/auto_escalation/rules/abc/delete')->status_is( 400, 'non-numeric delete id is a 400' );
}

done_testing();
