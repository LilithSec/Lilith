#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use FindBin ();
use lib "$FindBin::Bin/lib";

use_ok('Lilith::Escalate') or BAIL_OUT('Lilith::Escalate failed to load');

# ---------------------------------------------------------------------------
# 1.  Type discovery
# ---------------------------------------------------------------------------

{
    my $types = Lilith::Escalate->types;
    is( ref $types, 'ARRAY', 'types returns an array ref' );
    my %found = map { $_ => 1 } @$types;
    ok( $found{Webhook}, 'Webhook type found' );
    ok( $found{Email},   'Email type found' );
    ok( $found{Syslog},  'Syslog type found' );
}

# ---------------------------------------------------------------------------
# 2.  type_module resolution + name validation
# ---------------------------------------------------------------------------

{
    my $module = Lilith::Escalate->type_module('Webhook');
    is( $module, 'Lilith::Escalate::Type::Webhook', 'Webhook resolves to its module' );
    ok( $module->can('escalate'),      'resolved module implements escalate' );
    ok( $module->can('check_config'),  'resolved module implements check_config' );
    ok( $module->can('config_fields'), 'resolved module implements config_fields' );

    foreach my $bad ( undef, '', 'Bad::Name', '../Escape', 'no-dash', '0Start' ) {
        my $label = defined $bad ? "'$bad'" : 'undef';
        eval { Lilith::Escalate->type_module($bad) };
        ok( $@, "invalid type name $label dies" );
    }

    eval { Lilith::Escalate->type_module('DoesNotExist') };
    like( $@, qr/unknown escalation type/, 'unknown type dies' );
}

# ---------------------------------------------------------------------------
# 3.  type_info
# ---------------------------------------------------------------------------

{
    my $info = Lilith::Escalate->type_info('Webhook');
    is( $info->{type}, 'Webhook', 'type_info reports the type' );
    ok( length $info->{description}, 'type_info has a description' );
    is( ref $info->{fields}, 'ARRAY', 'type_info fields is an array ref' );

    my ($url_field)    = grep { $_->{name} eq 'url' } @{ $info->{fields} };
    my ($apikey_field) = grep { $_->{name} eq 'apikey' } @{ $info->{fields} };
    ok( $url_field && $url_field->{required}, 'url field is required' );
    ok( $apikey_field && $apikey_field->{type} eq 'secret', 'apikey field is a secret' );
}

# ---------------------------------------------------------------------------
# 4.  Built-in check_config validation
# ---------------------------------------------------------------------------

{
    my $webhook = Lilith::Escalate->type_module('Webhook');
    eval { $webhook->check_config( {} ) };
    like( $@, qr/url/, 'Webhook: missing url dies' );
    eval { $webhook->check_config( { url => 'gopher://foo' } ) };
    like( $@, qr/http/, 'Webhook: non-http url dies' );
    eval { $webhook->check_config( { url => 'https://foo.bar/hook', timeout => 'abc' } ) };
    like( $@, qr/timeout/, 'Webhook: non-numeric timeout dies' );
    ok( eval { $webhook->check_config( { url => 'https://foo.bar/hook', timeout => 10 } ) },
        'Webhook: good config passes' );

    my $email = Lilith::Escalate->type_module('Email');
    eval { $email->check_config( { from => 'a@b.c', to => 'd@e.f' } ) };
    like( $@, qr/host/, 'Email: missing host dies' );
    eval { $email->check_config( { host => 'mx', from => 'a@b.c', to => 'd@e.f', port => 'x' } ) };
    like( $@, qr/port/, 'Email: non-numeric port dies' );
    ok( eval { $email->check_config( { host => 'mx', from => 'a@b.c', to => 'd@e.f' } ) },
        'Email: good config passes' );

    my $syslog = Lilith::Escalate->type_module('Syslog');
    eval { $syslog->check_config( { priority => 'superbad' } ) };
    like( $@, qr/priority/, 'Syslog: bad priority dies' );
    eval { $syslog->check_config( { facility => 'nope' } ) };
    like( $@, qr/facility/, 'Syslog: bad facility dies' );
    ok( eval { $syslog->check_config( {} ) }, 'Syslog: empty config passes (defaults)' );
}

# ---------------------------------------------------------------------------
# 5.  Additional namespaces (site-supplied types)
# ---------------------------------------------------------------------------

{
    my $module = Lilith::Escalate->type_module( 'Mock', ['TestEscType'] );
    is( $module, 'TestEscType::Mock', 'extra namespace resolves a site type' );

    my $types = Lilith::Escalate->types( ['TestEscType'] );
    my %found = map { $_ => 1 } @$types;
    ok( $found{Mock},    'types() finds the site type' );
    ok( $found{Webhook}, 'types() still finds the built-in types' );

    # without the extra namespace the site type is unknown
    eval { Lilith::Escalate->type_module('Mock') };
    like( $@, qr/unknown escalation type/, 'site type is unknown without the extra namespace' );

    my $payload = $module->escalate(
        event  => { id => 7 },
        table  => 'suricata',
        config => { flag => 'x' },
        note   => 'testing',
    );
    is_deeply(
        $payload,
        { flag => 'x', table => 'suricata', id => 7, note => 'testing' },
        'site type escalate returns its payload'
    );
}

# ---------------------------------------------------------------------------
# 6.  event_summary
# ---------------------------------------------------------------------------

{
    my $summary = Lilith::Escalate->event_summary(
        'suricata',
        {
            id        => 9,
            src_ip    => '1.2.3.4',
            signature => 'ET TEST sig',
            raw       => { alert => { signature => 'ET TEST sig' } },
        }
    );
    like( $summary, qr/^table: suricata$/m, 'summary has the table' );
    like( $summary, qr/^id: 9$/m,           'summary has the id' );
    like( $summary, qr/^src_ip: 1\.2\.3\.4$/m, 'summary has the src_ip' );
    like( $summary, qr/"signature"/,        'summary includes the pretty raw JSON' );
}

# ---------------------------------------------------------------------------
# 7.  Lilith->new passes escalation_type_namespaces through
# ---------------------------------------------------------------------------

{
    use_ok('Lilith');
    my $lilith = Lilith->new(
        dsn                        => 'dbi:Pg:dbname=test',
        escalation_type_namespaces => ['TestEscType'],
    );
    my %found = map { $_ => 1 } @{ $lilith->escalation_types };
    ok( $found{Mock},    'escalation_types sees the site type' );
    ok( $found{Webhook}, 'escalation_types sees the built-in types' );

    my $info = $lilith->escalation_type_info('Mock');
    is( $info->{type}, 'Mock', 'escalation_type_info resolves the site type' );

    my $default = Lilith->new( dsn => 'dbi:Pg:dbname=test' );
    my %default_found = map { $_ => 1 } @{ $default->escalation_types };
    ok( !$default_found{Mock}, 'site type absent without the namespace opt' );
}

done_testing();
