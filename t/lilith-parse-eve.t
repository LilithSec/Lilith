#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use JSON        qw( encode_json decode_json );
use Digest::SHA qw( sha256_base64 );

use_ok('Lilith') or BAIL_OUT('Lilith failed to load');

my $lilith = Lilith->new( dsn => 'dbi:Pg:dbname=test' );

# ===========================================================================
# Non-alert / malformed records are skipped (parse_eve returns undef).
# ===========================================================================
is( $lilith->parse_eve( type => 'suricata', json => { event_type => 'flow' } ), undef, 'a non-alert event is skipped' );
is( $lilith->parse_eve( type => 'suricata', json => {} ),           undef, 'a record with no event_type is skipped' );
is( $lilith->parse_eve( type => 'suricata', json => undef ),        undef, 'undef json is skipped' );
is( $lilith->parse_eve( type => 'suricata', json => 'not a hash' ), undef, 'non-hash json is skipped' );
is( $lilith->parse_eve( type => 'bogus',    json => { event_type => 'alert' } ),
	undef, 'an unknown instance type yields undef' );

# ===========================================================================
# Suricata: field flattening, alert.* remapping, and the event_id recipe.
# ===========================================================================
{
	my $eve = {
		event_type => 'alert',
		timestamp  => '2026-07-12T00:00:00.000000+0000',
		flow_id    => 1234567890,
		in_iface   => 'eth0',
		src_ip     => '1.2.3.4',
		src_port   => 41000,
		dest_ip    => '5.6.7.8',
		dest_port  => 22,
		proto      => 'TCP',
		app_proto  => 'ssh',
		flow       => {
			pkts_toserver  => 10,
			bytes_toserver => 2000,
			pkts_toclient  => 8,
			bytes_toclient => 1500,
			start          => '2026-07-12T00:00:00.000000+0000',
		},
		alert => {
			category     => 'Misc activity',
			signature    => 'ET SCAN Potential SSH Scan',
			gid          => 1,
			signature_id => 2001219,
			rev          => 8,
		},
	};
	my $raw = encode_json($eve);

	my $row = $lilith->parse_eve(
		type     => 'suricata',
		json     => $eve,
		instance => 'foo-pie',
		host     => 'sensor1',
		raw      => $raw,
	);

	is( ref($row), 'HASH', 'suricata alert parses to a row hash' );

	# the row's keys are exactly the suricata_alerts columns -- nothing missing,
	# nothing stray
	is_deeply(
		[ sort keys %{$row} ],
		[ sort @{ $Lilith::alert_columns{suricata} } ],
		'suricata row keys match the suricata_alerts column set exactly'
	);

	is( $row->{instance},  'foo-pie', 'instance recorded from the argument' );
	is( $row->{host},      'sensor1', 'host is the sensor host' );
	is( $row->{src_ip},    '1.2.3.4', 'src_ip carried through' );
	is( $row->{dest_port}, 22,        'dest_port carried through' );
	is( $row->{app_proto}, 'ssh',     'app_proto carried through' );

	# nested flow.* flattened into flow_* columns
	is( $row->{flow_pkts_toserver},  10,                                'flow.pkts_toserver -> flow_pkts_toserver' );
	is( $row->{flow_bytes_toclient}, 1500,                              'flow.bytes_toclient -> flow_bytes_toclient' );
	is( $row->{flow_start},          '2026-07-12T00:00:00.000000+0000', 'flow.start -> flow_start' );

	# alert.* remapped
	is( $row->{classification}, 'Misc activity',              'alert.category -> classification' );
	is( $row->{signature},      'ET SCAN Potential SSH Scan', 'alert.signature -> signature' );
	is( $row->{gid},            1,                            'alert.gid -> gid' );
	is( $row->{sid},            2001219,                      'alert.signature_id -> sid' );
	is( $row->{rev},            8,                            'alert.rev -> rev' );

	is( $row->{raw}, $raw, 'the raw line is stored verbatim' );

	# event_id must be the SHA256 (base64) of instance + host + timestamp +
	# flow_id + in_iface, matching App::Lilu so both compute the same handle
	my $expect_eid = sha256_base64( 'foo-pie' . 'sensor1' . $eve->{timestamp} . $eve->{flow_id} . $eve->{in_iface} );
	is( $row->{event_id}, $expect_eid, 'event_id follows the documented recipe' );

	# and it is stable across two parses of the same event
	my $row2 = $lilith->parse_eve(
		type     => 'suricata',
		json     => decode_json($raw),
		instance => 'foo-pie',
		host     => 'sensor1',
		raw      => $raw,
	);
	is( $row2->{event_id}, $row->{event_id}, 'event_id is stable for the same event' );
}

# ===========================================================================
# Sagan: instance_host vs host, and the duplicate-proto regression.
# ===========================================================================
{
	my $eve = {
		event_type => 'alert',
		timestamp  => '2026-07-12T01:02:03.000000+0000',
		flow_id    => 99,
		in_iface   => 'eth1',
		src_ip     => '10.0.0.1',
		src_port   => 5000,
		dest_ip    => '10.0.0.2',
		dest_port  => 514,
		proto      => 'UDP',
		facility   => 'local0',
		host       => 'firewall1',
		level      => 'notice',
		priority   => '3',
		program    => 'sshd',
		xff        => '203.0.113.9',
		stream     => 7,
		alert      => {
			category     => 'Attempted Administrator Privilege Gain',
			signature    => 'SAGAN SSH auth failure',
			gid          => 1,
			signature_id => 5000000,
			rev          => 1,
		},
	};

	my $row = $lilith->parse_eve(
		type     => 'sagan',
		json     => $eve,
		instance => 'foo-lae',
		host     => 'sensor1',
		raw      => 'RAW',
	);

	is( ref($row), 'HASH', 'sagan alert parses to a row hash' );

	# Regression: the sagan INSERT once listed "proto" twice, which PostgreSQL
	# rejects with "column specified more than once". The row must have exactly
	# the schema's columns -- a single proto and no stray keys.
	is_deeply(
		[ sort keys %{$row} ],
		[ sort @{ $Lilith::alert_columns{sagan} } ],
		'sagan row keys match the sagan_alerts column set exactly (single proto)'
	);
	is( scalar( grep { $_ eq 'proto' } @{ $Lilith::alert_columns{sagan} } ),
		1, 'proto appears exactly once in the sagan column list' );

	# instance_host is the sensor Lilith runs on; host is the log-originating host
	is( $row->{instance_host}, 'sensor1',   'sagan instance_host is the sensor host' );
	is( $row->{host},          'firewall1', 'sagan host is the syslog-originating host' );

	is( $row->{proto},          'UDP',                                    'proto carried through' );
	is( $row->{facility},       'local0',                                 'facility carried through' );
	is( $row->{program},        'sshd',                                   'program carried through' );
	is( $row->{xff},            '203.0.113.9',                            'xff carried through' );
	is( $row->{classification}, 'Attempted Administrator Privilege Gain', 'alert.category -> classification' );
	is( $row->{sid},            5000000,                                  'alert.signature_id -> sid' );
	is( $row->{raw},            'RAW',                                    'raw stored verbatim' );
}

# ===========================================================================
# CAPE: the field-by-field fallbacks between cape_submit,
# suricata_extract_submit, and row.
# ===========================================================================

# -- cape_submit is the richest source; slug prefers suricata_extract_submit --
{
	my $eve = {
		event_type => 'alert',
		malscore   => 7.5,
		row        => {
			id           => 42,
			started_on   => '2026-07-12T00:00:00',
			completed_on => '2026-07-12T00:05:00',
			package      => 'exe',
			target       => '/should/not/be/used',
		},
		cape_submit => {
			name      => '/full/path/to/evil.exe',
			md5       => 'cape-md5',
			sha1      => 'cape-sha1',
			sha256    => 'cape-sha256',
			remote_ip => '198.51.100.5',
			size      => 1024,
			slug      => 'cape-slug',
		},
		suricata_extract_submit => {
			name => 'ses-name.bin',
			host => 'sensorX',
			md5  => 'ses-md5',
			slug => 'ses-slug',
		},
		http      => { url => 'http://evil.example/x', hostname => 'evil.example' },
		proto     => 'tcp',
		src_ip    => '1.1.1.1',
		src_port  => 44000,
		dest_ip   => '2.2.2.2',
		dest_port => 80,
	};

	my $row = $lilith->parse_eve(
		type     => 'cape',
		json     => $eve,
		instance => 'cape1',
		host     => 'sensor1',
		raw      => 'CRAW',
	);

	is( ref($row), 'HASH', 'cape alert parses to a row hash' );
	is_deeply(
		[ sort keys %{$row} ],
		[ sort @{ $Lilith::alert_columns{cape} } ],
		'cape row keys match the cape_alerts column set exactly'
	);

	is( $row->{instance_host},    'sensor1',               'cape instance_host is the sensor host' );
	is( $row->{target},           'evil.exe',              'target uses cape_submit.name, basename only' );
	is( $row->{task},             42,                      'task from row.id' );
	is( $row->{start},            '2026-07-12T00:00:00',   'start from row.started_on' );
	is( $row->{stop},             '2026-07-12T00:05:00',   'stop from row.completed_on' );
	is( $row->{pkg},              'exe',                   'pkg from row.package' );
	is( $row->{malscore},         7.5,                     'malscore carried through' );
	is( $row->{md5},              'cape-md5',              'md5 prefers cape_submit' );
	is( $row->{sha1},             'cape-sha1',             'sha1 prefers cape_submit' );
	is( $row->{sha256},           'cape-sha256',           'sha256 prefers cape_submit' );
	is( $row->{slug},             'ses-slug',              'slug prefers suricata_extract_submit' );
	is( $row->{subbed_from_ip},   '198.51.100.5',          'subbed_from_ip from cape_submit.remote_ip' );
	is( $row->{subbed_from_host}, 'sensorX',               'subbed_from_host from suricata_extract_submit.host' );
	is( $row->{size},             1024,                    'size prefers cape_submit.size' );
	is( $row->{url},              'http://evil.example/x', 'url from http.url' );
	is( $row->{url_hostname},     'evil.example',          'url_hostname from http.hostname' );
	is( $row->{proto},            'tcp',                   'proto carried through' );
	is( $row->{dest_port},        80,                      'dest_port carried through' );
	is( $row->{raw},              'CRAW',                  'raw stored verbatim' );
}

# -- falls back to suricata_extract_submit, fileinfo.size, and no cape_submit --
{
	my $eve = {
		event_type              => 'alert',
		row                     => { id => 7, target => '/var/spool/sample.bin' },
		suricata_extract_submit =>
			{ name => '/x/y/ses.bin', md5 => 'ses-md5', sha1 => 'ses-sha1', sha256 => 'ses-sha256', host => 'senY' },
		fileinfo => { size => 2048 },
	};

	my $row = $lilith->parse_eve( type => 'cape', json => $eve, instance => 'cape1', host => 'sensor1' );

	is( $row->{target},           'ses.bin',    'target falls back to suricata_extract_submit.name (basename)' );
	is( $row->{md5},              'ses-md5',    'md5 falls back to suricata_extract_submit' );
	is( $row->{sha256},           'ses-sha256', 'sha256 falls back to suricata_extract_submit' );
	is( $row->{size},             2048,         'size falls back to fileinfo.size' );
	is( $row->{subbed_from_host}, 'senY',       'subbed_from_host from suricata_extract_submit.host' );
	is( $row->{subbed_from_ip},   undef,        'no cape_submit => subbed_from_ip is undef' );
	is( $row->{url},              undef,        'no http => url is undef' );
}

# -- neither submit source: target comes from row.target --
{
	my $eve = { event_type => 'alert', row => { id => 1, target => '/a/b/c.doc' } };
	my $row = $lilith->parse_eve( type => 'cape', json => $eve, instance => 'i', host => 'h' );
	is( $row->{target}, 'c.doc', 'target falls back to row.target (basename)' );
	is( $row->{task},   1,       'task still read from row.id' );
}

# ===========================================================================
# End to end: parse straight from a raw EVE JSON line, as run() would.
# ===========================================================================
{
	my $line
		= '{"event_type":"alert","timestamp":"2026-07-12T02:00:00.000000+0000",'
		. '"flow_id":555,"in_iface":"eth0","src_ip":"9.9.9.9","src_port":1,'
		. '"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP",'
		. '"alert":{"category":"Potentially Bad Traffic","signature":"sig","signature_id":9,"gid":1,"rev":1}}';

	my $row = $lilith->parse_eve(
		type     => 'suricata',
		json     => decode_json($line),
		instance => 'pie',
		host     => 'sensor1',
		raw      => $line,
	);
	is( $row->{sid},            9,                         'sid parsed from a real decoded EVE line' );
	is( $row->{classification}, 'Potentially Bad Traffic', 'classification parsed from a real decoded EVE line' );
	is( $row->{dest_ip},        '8.8.8.8',                 'dest_ip parsed from a real decoded EVE line' );
}

done_testing();
