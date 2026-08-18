#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith::Shodan') or BAIL_OUT('Lilith::Shodan failed to load');

# The Shodan lookup, tested without a network: everything here is either pure
# or short circuits before a request is made. The two halves that do reach out
# -- fetch, and the gather that wraps it -- are exercised against the HTTP
# layer in web-api.t and against a real database in pg-migrate.t.

# ---------------------------------------------------------------------------
# 0.  source — which tier a key selects
# ---------------------------------------------------------------------------

{
	is( Lilith::Shodan::source('abc123'), 'api',        'a key selects the host API tier' );
	is( Lilith::Shodan::source(''),       'internetdb', 'no key selects the keyless tier' );
	is( Lilith::Shodan::source(undef),    'internetdb', 'an unset key selects the keyless tier' );
}

# ---------------------------------------------------------------------------
# 1.  Shodan — the addresses that are never sent anywhere
# ---------------------------------------------------------------------------

{
	for my $ip (
		qw( 10.0.0.5 172.16.4.1 172.31.255.254 192.168.1.1 127.0.0.1 169.254.10.1
		100.64.0.1 0.0.0.0 224.0.0.1 255.255.255.255 198.51.100.7 203.0.113.9
		192.0.2.10 198.18.0.1 ::1 :: fe80::1 fd00::1 2001:db8::1 ff02::1 )
		)
	{
		is( Lilith::Shodan::is_private_ip($ip), 1, "$ip is treated as private/reserved" );
	}

	for my $ip (qw( 8.8.8.8 1.1.1.1 172.15.0.1 172.32.0.1 100.128.0.1 2606:4700:4700::1111 )) {
		is( Lilith::Shodan::is_private_ip($ip), 0, "$ip is treated as public" );
	}

	# Anything unparseable counts as private, so a lookup is never made for an
	# address that was not understood.
	is( Lilith::Shodan::is_private_ip('....'), 1, 'an unparseable address counts as private' );
	is( Lilith::Shodan::is_private_ip(undef),  1, 'undef counts as private' );

	# A private address short circuits before any request is made.
	my ( $skipped, $error ) = Lilith::Shodan::gather( '10.1.2.3', '' );
	is( $error,              '',                            'a skipped lookup is not an error' );
	is( $skipped->{skipped}, 'private or reserved address', 'a private address is reported as skipped' );
	ok( !exists $skipped->{source}, 'a skipped lookup names no source' );
}

# ---------------------------------------------------------------------------
# 2.  Shodan — response normalization
# ---------------------------------------------------------------------------

{
	is_deeply( Lilith::Shodan::_list( [ 'a', '', undef, 'b' ] ), [ 'a', 'b' ], '_list drops blanks' );
	is_deeply( Lilith::Shodan::_list(undef),                     [], '_list turns a missing field into a list' );

	is(
		Lilith::Shodan::_dn( { CN => 'example.org', C => 'US', O => 'Example Inc' } ),
		'CN=example.org, C=US, O=Example Inc',
		'_dn leads with CN'
	);
	is( Lilith::Shodan::_dn(undef), '', '_dn copes with a missing name' );

	# The same CVE arrives twice -- bare in the host list, with detail under the
	# service -- and has to end up as one entry carrying the detail.
	my %vulns;
	Lilith::Shodan::_add_vulns( [ 'CVE-2021-40438', 'CVE-2019-0217' ], \%vulns );
	Lilith::Shodan::_add_vulns( { 'CVE-2021-40438' => { cvss => 9.8, summary => 'mod_proxy SSRF', verified => 1 } },
		\%vulns );
	is( scalar keys %vulns,                 2,   'a CVE seen twice is one entry' );
	is( $vulns{'CVE-2021-40438'}{cvss},     9.8, 'service detail is merged onto the host level id' );
	is( $vulns{'CVE-2021-40438'}{verified}, 1,   'verified is normalized to 1' );
	is( $vulns{'CVE-2019-0217'}{cvss},      '',  'a CVE with no detail keeps an empty score' );

	my $service = Lilith::Shodan::_service(
		{
			port      => 443,
			transport => 'tcp',
			product   => 'nginx',
			version   => '1.18.0',
			_shodan   => { module => 'https' },
			cpe23     => ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'],
			data      => 'HTTP/1.1 200 OK',
			vulns     => { 'CVE-2021-40438' => { cvss => 9.8 } },
			http      => { title => 'Example', server => 'nginx', components => { jQuery => {}, Bootstrap => {} } },
			ssl       => {
				versions => [ '-TLSv1', 'TLSv1.2', 'TLSv1.3' ],
				cipher   => { name => 'TLS_AES_256_GCM_SHA384', bits => 256 },
				jarm     => '29d3fd00029d',
				cert     => {
					subject     => { CN => 'example.org' },
					issuer      => { CN => 'R3' },
					expired     => 0,
					fingerprint => { sha256 => 'aabbcc' },
				},
			},
		}
	);

	is( $service->{port},              443,                                'service port is numeric' );
	is( $service->{module},            'https',                            'crawler module is pulled out of _shodan' );
	is( $service->{http}{components},  'Bootstrap, jQuery',                'detected components are joined' );
	is( $service->{ssl}{versions},     'TLSv1.2, TLSv1.3',                 'refused TLS versions are dropped' );
	is( $service->{ssl}{cipher},       'TLS_AES_256_GCM_SHA384 (256 bit)', 'cipher carries its strength' );
	is( $service->{ssl}{cert_subject}, 'CN=example.org',                   'certificate subject is rendered as a DN' );
	is( $service->{ssl}{cert_expired}, 0,                                  'an unexpired certificate normalizes to 0' );
	is_deeply( $service->{vulns}, ['CVE-2021-40438'], 'a service lists its own CVEs as bare ids' );
	is_deeply( $service->{ssh},   {},                 'an absent protocol section is an empty hash, not missing' );

	# A banner is capped so one chatty HTTP server cannot become the whole modal.
	my $long = Lilith::Shodan::_service( { port => 80, data => 'x' x 9000 } );
	ok( length( $long->{banner} ) < 4100, 'an oversized banner is truncated' );
	like( $long->{banner}, qr/truncated/, 'a truncated banner says so' );
}

# ---------------------------------------------------------------------------
# 2b.  Shodan — the enrichment fields pulled from a fuller banner
# ---------------------------------------------------------------------------

{
	my $service = Lilith::Shodan::_service(
		{
			port =>  443,
			hash => -1524570663,
			data => 'HTTP/1.1 200 OK',
			http => {
				server      => 'nginx',
				host        => 'example.org',
				html_hash   => 12345678,
				favicon     => { hash => -98765 },
				securitytxt => "Contact: mailto:sec\@example.org\n",
				robots      => "User-agent: *\n",
				redirects   => [ {}, {} ],
			},
			ssl => {
				versions => [ 'TLSv1.2', 'TLSv1.3' ],
				jarm     => '29d3fd00029d',
				chain    => [ 'PEM-LEAF', 'PEM-INTERMEDIATE' ],
				cert     => {
					subject => { CN => 'example.org' },
					issuer  => { CN => 'example.org' },
					issued  => '20260601000000Z',
					expires => '20260901000000Z',
					sig_alg => 'sha256WithRSAEncryption',
					pubkey  => { type => 'rsa', bits => 2048 },
				},
			},
			ssh => { type => 'ssh-rsa', cipher => 'aes128-ctr', mac => 'hmac-sha2-256' },
		}
	);

	is( $service->{hash}, -1524570663, 'the banner hash rides along as a pivot facet' );

	is( $service->{http}{host},        'example.org', 'the HTTP host header is pulled out' );
	is( $service->{http}{html_hash},   12345678,      'the HTML hash rides along as a pivot facet' );
	is( $service->{http}{securitytxt}, 1,             'a served security.txt is a presence flag, not its body' );
	is( $service->{http}{robots},      1,             'a served robots.txt is a presence flag, not its body' );
	is( $service->{http}{redirects},   2,             'the redirect count is the length of the chain' );

	is( $service->{ssl}{self_signed},  1,                         'subject == issuer is reported as self-signed' );
	is( $service->{ssl}{cert_issued},  '20260601000000Z',         'the certificate issuance date is pulled out' );
	is( $service->{ssl}{cert_sig_alg}, 'sha256WithRSAEncryption', 'the signature algorithm is pulled out' );
	is( $service->{ssl}{cert_pubkey},  'RSA 2048-bit',            'the public key is rendered type-and-bits' );
	is( $service->{ssl}{chain_len},    2,                         'the certificate chain length is counted' );
	is( $service->{ssl}{dh_bits},      '', 'an ECDHE handshake reports no DH group as empty, not zero' );

	is( $service->{ssh}{cipher}, 'aes128-ctr',    'the negotiated SSH cipher is pulled out' );
	is( $service->{ssh}{mac},    'hmac-sha2-256', 'the negotiated SSH MAC is pulled out' );

	# A CA-issued certificate is not flagged self-signed.
	my $ca = Lilith::Shodan::_service(
		{ port => 443, ssl => { cert => { subject => { CN => 'example.org' }, issuer => { CN => 'R3' } } } } );
	is( $ca->{ssl}{self_signed}, 0, 'a distinct issuer is not self-signed' );
}

# ---------------------------------------------------------------------------
# 2c.  Shodan — the plain-language callouts drawn out of a normalized result
# ---------------------------------------------------------------------------

{
	my $raw = {
		ports => [ 3389,    443, 27017 ],
		tags  => [ 'cloud', 'eol-product' ],
		data  => [
			# a live service on a deprecated protocol with a self-signed cert
			{
				port      => 443,
				transport => 'tcp',
				_shodan   => { module => 'https' },
				ssl       => {
					versions => [ 'TLSv1.0', 'TLSv1.2' ],
					cert     => { subject => { CN => 'a' }, issuer => { CN => 'a' } },
				},
			},

			# a second service whose certificate has already expired
			{
				port      => 8443,
				transport => 'tcp',
				_shodan   => { module => 'https' },
				ssl       => { cert   => { subject => { CN => 'b' }, issuer => { CN => 'R3' }, expired => 1 } },
			},
		],
	};
	my $info = Lilith::Shodan::normalize( $raw, 'api', '192.0.2.10' );

	is_deeply(
		[ map { $_->{text} } @{ $info->{callouts} } ],
		[
			'exposed RDP',
			'exposed MongoDB',
			'weak TLS (TLSv1.0)',
			'self-signed certificate',
			'expired certificate',
			'end-of-life product',
		],
		'every finding is drawn out, exposed services leading'
	);
	is( $info->{callouts}[0]{level}, 'danger',  'an exposed service is a danger finding' );
	is( $info->{callouts}[2]{level}, 'warning', 'a weakness is a warning finding' );

	# A clean host stands out for nothing.
	my $clean = Lilith::Shodan::normalize(
		{
			ports => [443],
			data  => [
				{
					port      => 443,
					transport => 'tcp',
					_shodan   => { module => 'https' },
					ssl       => {
						versions => ['TLSv1.3'],
						cert     => { subject => { CN => 'example.org' }, issuer => { CN => 'R3' }, expired => 0 },
					},
				},
			],
		},
		'api',
		'192.0.2.10'
	);
	is_deeply( $clean->{callouts}, [], 'a host with nothing wrong has no callouts' );

	# An empty response -- one Shodan has never crawled -- likewise.
	is_deeply( Lilith::Shodan::normalize( {}, 'internetdb', '192.0.2.10' )->{callouts},
		[], 'an empty response has no callouts' );
}

# ---------------------------------------------------------------------------
# 3.  Shodan — the response is what is stored, not the rendering
# ---------------------------------------------------------------------------

{
	# The point of caching the response rather than the rendering: normalizing a
	# stored response has to give what normalizing it fresh gave, or a cache hit
	# and a miss would not look the same on screen.
	my $raw = {
		ports => [ 443, 22 ],
		tags  => ['cloud'],
		vulns => ['CVE-2019-0217'],
		org   => 'Example Hosting LLC',
		isp   => 'Example Carrier Inc',
		asn   => 'AS64496',
		data  => [ { port => 443, transport => 'tcp', product => 'nginx', _shodan => { module => 'https' } } ],
	};
	my $first  = Lilith::Shodan::normalize( $raw, 'api', '192.0.2.10' );
	my $second = Lilith::Shodan::normalize( $raw, 'api', '192.0.2.10' );
	is_deeply( $second,         $first,      'normalizing the same response twice gives the same result' );
	is_deeply( $first->{ports}, [ 22, 443 ], 'ports are sorted whichever way they arrived' );
	is( $first->{services}[0]{product}, 'nginx', 'services are rebuilt from the stored response' );
	is_deeply( $first->{products},      ['nginx'],     'the product names are projected out, deduped and name-only' );
	is_deeply( $first->{port_products}, ['443 nginx'], 'the port-to-product pairing is projected out beside them' );

	# who the address belongs to rides along, for the modal and the columns
	# the dashboard groups by
	is( $first->{org}, 'Example Hosting LLC', 'org carries through' );
	is( $first->{isp}, 'Example Carrier Inc', 'isp carries through' );
	is( $first->{asn}, 'AS64496',             'asn carries through' );

	# An empty response is the full shape with nothing in it, which is what an
	# address Shodan has never crawled is cached as -- and what the keyless
	# tier, which sends no ownership fields, comes to for those.
	my $empty = Lilith::Shodan::normalize( {}, 'internetdb', '192.0.2.10' );
	is( $empty->{source}, 'internetdb', 'an empty response still names its source' );
	is_deeply( $empty->{ports},         [], 'an empty response has no ports' );
	is_deeply( $empty->{services},      [], 'an empty response has no services' );
	is_deeply( $empty->{port_products}, [], 'an empty response has no port pairings' );
	is( $empty->{org}, '', 'an absent org is an empty string' );
	is( $empty->{asn}, '', 'an absent asn is an empty string' );
}

# ---------------------------------------------------------------------------
# 3b.  Shodan — a history response: one service per crawl collapses to the
#      newest banner, dated by the oldest
# ---------------------------------------------------------------------------

{
	my $raw = {
		ports => [443],
		vulns => ['CVE-2021-40438'],
		data  => [
			# the same service crawled three times across two years, arriving
			# out of order
			{
				port      => 443,
				transport => 'tcp',
				product   => 'nginx',
				version   => '1.18.0',
				timestamp => '2026-07-01T00:00:00',
				_shodan   => { module => 'https' },
			},
			{
				port      => 443,
				transport => 'tcp',
				product   => 'nginx',
				version   => '1.14.0',
				timestamp => '2024-05-01T00:00:00',
				_shodan   => { module => 'https' },
			},
			{
				port      => 443,
				transport => 'tcp',
				product   => 'nginx',
				version   => '1.16.0',
				timestamp => '2025-06-01T00:00:00',
				_shodan   => { module => 'https' },
			},

			# a port long closed, whose old banner carried a CVE
			{
				port      => 21,
				transport => 'tcp',
				product   => 'vsftpd',
				timestamp => '2023-01-01T00:00:00',
				_shodan   => { module => 'ftp' },
				vulns     => ['CVE-2011-2523'],
			},
		],
	};
	my $info = Lilith::Shodan::normalize( $raw, 'api', '192.0.2.10' );

	is( scalar @{ $info->{services} }, 2, 'one service per port/transport/module, not one per crawl' );
	my ($https) = grep { $_->{port} == 443 } @{ $info->{services} };
	is( $https->{version},    '1.18.0',              'the newest crawl stands for the group' );
	is( $https->{first_seen}, '2024-05-01T00:00:00', 'dated by its oldest sighting' );
	is( $https->{timestamp},  '2026-07-01T00:00:00', 'and last seen by its newest' );

	# the closed port keeps its block -- that history is the point -- but its
	# old CVE must not resurface as the host's
	my ($ftp) = grep { $_->{port} == 21 } @{ $info->{services} };
	is( $ftp->{product}, 'vsftpd', 'a since-closed port keeps its block' );
	is_deeply( [ map { $_->{cve} } @{ $info->{vulns} } ],
		['CVE-2021-40438'], "a closed port's old CVEs do not resurface as the host's" );
	is_deeply( $info->{port_products},
		['443 nginx 1.18.0'], "a closed port's old product does not annotate a port it is no longer on" );

	# an ordinary response reads the same as before: a single crawl is its own
	# first sighting
	my $plain
		= Lilith::Shodan::normalize(
			{ ports => [80], data => [ { port => 80, transport => 'tcp', timestamp => '2026-07-01T00:00:00' } ] },
			'api', '192.0.2.10' );
	is( $plain->{services}[0]{first_seen}, '2026-07-01T00:00:00', 'a single crawl is its own first sighting' );
}

# ---------------------------------------------------------------------------
# 3c.  Shodan — port_product_map, the one reader of the pairing format
# ---------------------------------------------------------------------------

{
	is_deeply(
		Lilith::Shodan::port_product_map( [ '443 nginx 1.18.0', '8080 Apache httpd', '8080 nginx' ] ),
		{ 443 => 'nginx 1.18.0', 8080 => 'Apache httpd / nginx' },
		'pairings come back keyed by port, several on one port joined'
	);
	is_deeply( Lilith::Shodan::port_product_map(undef), {}, 'a row from before schema 20 hands in undef' );
	is_deeply( Lilith::Shodan::port_product_map( ['no leading port'] ),
		{}, 'a malformed entry is ignored rather than died on' );
}

# ---------------------------------------------------------------------------
# 4.  Shodan — the neighborhood count's pure parts
# ---------------------------------------------------------------------------

{
	# _facet shapes one Shodan count facet into the modal's { value, count } list
	# and copes with the facet being absent, as Shodan omits an empty one.
	is_deeply(
		Lilith::Shodan::_facet(
			{ port => [ { count => 900, value => 443 }, { count => 5, value => 22 } ] }, 'port'
		),
		[ { value => 443, count => 900 }, { value => 22, count => 5 } ],
		'_facet shapes a facet into value/count pairs'
	);
	is_deeply( Lilith::Shodan::_facet( {},    'port' ), [], '_facet turns a missing facet into an empty list' );
	is_deeply( Lilith::Shodan::_facet( undef, 'port' ), [], '_facet copes with no facets at all' );

	# _query_value quotes a phrase, leaves a token bare, and drops what would
	# break out of the query.
	is( Lilith::Shodan::_query_value( 'Example Hosting LLC', 1 ), '"Example Hosting LLC"', 'a phrase is quoted' );
	is( Lilith::Shodan::_query_value( 'a "b" \\ c',          1 ), '"a b  c"',  'quotes and backslashes are stripped' );
	is( Lilith::Shodan::_query_value( -1524570663,           0 ), -1524570663, 'a signed hash is left bare' );
	is( Lilith::Shodan::_query_value( 'aabbcc00',            0 ), 'aabbcc00',  'a hex fingerprint is left bare' );
	is( Lilith::Shodan::_query_value( 'no spaces here',      0 ), '',          'a bare token with spaces is rejected' );

	# Without a key the count cannot be made, and that is an error rather than an
	# empty answer -- the endpoint is API tier.
	my ( $result, $error, $capped ) = Lilith::Shodan::neighborhood_count( 'Example', [], '' );
	like( $error, qr/api key/i, 'a keyless neighborhood count is an error' );
	is( $capped, 0, 'and counts nothing as skipped' );
}

done_testing();
