#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use JSON    ();
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
	ok( $url_field    && $url_field->{required},            'url field is required' );
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

	# priority/facility are now enums carrying their allowed options
	my %sfields = map { $_->{name} => $_ } @{ $syslog->config_fields };
	is( $sfields{priority}{type}, 'enum', 'Syslog: priority is an enum field' );
	ok( ( grep { $_ eq 'alert' } @{ $sfields{priority}{options} } ), 'Syslog: priority options include alert' );
	is( $sfields{facility}{type},                     'enum', 'Syslog: facility is an enum field' );
	is( $sfields{json_paths}{type},                   'list', 'Syslog: json_paths is a list field' );
	is( scalar( @{ $sfields{json_paths}{columns} } ), 2,      'Syslog: json_paths has key/path columns' );

	# json_paths ships a default set covering the core event fields
	my %jp_default = map { $_->{key} => $_->{path} } @{ $sfields{json_paths}{default} };
	is( $jp_default{event_id},  '$.event_id',       'Syslog: json_paths default has event_id' );
	is( $jp_default{dest_port}, '$.dest_port',      'Syslog: json_paths default has dest_port' );
	is( $jp_default{class},     '$.classification', 'Syslog: json_paths default maps class to $.classification' );
	is( $jp_default{signature}, '$.signature',      'Syslog: json_paths default has signature' );

	# json_paths validation
	eval { $syslog->check_config( { json_paths => 'nope' } ) };
	like( $@, qr/must be a list/, 'Syslog: non-list json_paths dies' );
	eval { $syslog->check_config( { json_paths => [ { key => 'bad key', path => '$.x' } ] } ) };
	like( $@, qr/field name/, 'Syslog: bad json_paths key dies' );
	eval { $syslog->check_config( { json_paths => [ { key => 'k', path => '$.[[[' } ] } ) };
	like( $@, qr/JSONPath/, 'Syslog: malformed JSONPath dies' );
	ok(
		eval {
			$syslog->check_config(
				{
					json_paths =>
						[ { key => 'sig', path => '$.raw.alert.signature' }, { key => '', path => '$.src_ip' } ]
				}
			);
		},
		'Syslog: good json_paths passes'
	);

	# extraction appends key="value" pairs, decoding a raw JSON string first
	my $raw = JSON::encode_json( { alert => { signature => 'ET SCAN "x"' } } );
	my $ret = $syslog->escalate(
		table  => 'suricata',
		event  => { id => 3, src_ip => '10.0.0.9', raw => $raw },
		config => {
			facility   => 'local0',
			json_paths => [
				{ key => 'sig', path => '$.raw.alert.signature' },
				{ key => 'sip', path => '$.src_ip' },
				{ key => '',    path => '$.raw.missing' },
			],
		},
	);
	like( $ret->{message}, qr/sig="ET SCAN \\"x\\""/, 'Syslog: nested JSONPath extracted and quoted' );
	like( $ret->{message}, qr/sip="10\.0\.0\.9"/,     'Syslog: row column JSONPath extracted' );
	unlike( $ret->{message}, qr/jsonpath=/, 'Syslog: unmatched JSONPath contributes nothing' );

	# with no json_paths of its own, the defaults are applied
	my $def = $syslog->escalate(
		table => 'suricata',
		event =>
			{ id => 5, event_id => 99, src_ip => '1.2.3.4', classification => 'attempted-recon', signature => 'sig!' },
		config => { facility => 'local0' },
	);
	like( $def->{message}, qr/id="5"/,                  'Syslog: default run logs id' );
	like( $def->{message}, qr/event_id="99"/,           'Syslog: default json_paths log event_id' );
	like( $def->{message}, qr/src_ip="1\.2\.3\.4"/,     'Syslog: default json_paths log src_ip' );
	like( $def->{message}, qr/class="attempted-recon"/, 'Syslog: default json_paths map class to classification' );

	# an explicitly empty list opts out of the defaults, leaving only id
	my $none = $syslog->escalate(
		table  => 'suricata',
		event  => { id       => 6,        src_ip     => '9.9.9.9' },
		config => { facility => 'local0', json_paths => [] },
	);
	like( $none->{message}, qr/id="6"/, 'Syslog: empty json_paths still logs id' );
	unlike( $none->{message}, qr/src_ip=/, 'Syslog: empty json_paths opts out of event fields' );

	# multiple matches for one path are joined with commas
	my $multi_raw = JSON::encode_json( { hits => [ { ip => 'a' }, { ip => 'b' }, { ip => 'c' } ] } );
	my $multi     = $syslog->escalate(
		table  => 'suricata',
		event  => { id       => 7,        raw        => $multi_raw },
		config => { facility => 'local0', json_paths => [ { key => 'ips', path => '$.raw.hits[*].ip' } ] },
	);
	like( $multi->{message}, qr/ips="a,b,c"/, 'Syslog: multi-match JSONPath joined with commas' );
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
	like( $summary, qr/^table: suricata$/m,    'summary has the table' );
	like( $summary, qr/^id: 9$/m,              'summary has the id' );
	like( $summary, qr/^src_ip: 1\.2\.3\.4$/m, 'summary has the src_ip' );
	like( $summary, qr/"signature"/,           'summary includes the pretty raw JSON' );
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

	my $default       = Lilith->new( dsn => 'dbi:Pg:dbname=test' );
	my %default_found = map { $_ => 1 } @{ $default->escalation_types };
	ok( !$default_found{Mock}, 'site type absent without the namespace opt' );
}

done_testing();
