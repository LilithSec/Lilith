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

	is( $app->dns_bg_timeout(),   3,  'dns_bg_timeout defaults to 3' );
	is( $app->dnstracer_enable(), 0,  'dnstracer_enable defaults to 0 (false)' );
	is( $app->shodan_enable(),    0,  'shodan_enable defaults to 0 (false)' );
	is( $app->shodan_api_key(),   '', 'shodan_api_key defaults to empty' );
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

	is_deeply( $app->dnstracer_flags(), [ '-q', '-s', '8.8.8.8' ], 'dnstracer_flags reads array from config' );
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

	is_deeply( $app->dnstracer_flags(), [], 'non-array dnstracer_flags in config is ignored; helper returns []' );
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

	is( $app->virani_enabled(),       0, 'virani disabled when no [virani.*] configured' );
	is( $app->virani_search_enable(), 0, 'virani search disabled by default' );
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

	is( $app->country_flag('US'),  "\x{1F1FA}\x{1F1F8}", 'US maps to the regional-indicator flag' );
	is( $app->country_flag('de'),  "\x{1F1E9}\x{1F1EA}", 'lowercase code is upcased before mapping' );
	is( $app->country_flag(''),    '',                   'empty code yields empty string' );
	is( $app->country_flag(undef), '',                   'undef code yields empty string' );
	is( $app->country_flag('USA'), '',                   'non two-letter code yields empty string' );
	is( $app->country_flag('1.2'), '',                   'non-alpha code yields empty string' );
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
	local $SIG{__WARN__}      = sub { };
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
	} ## end SKIP:
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
	} ## end SKIP:
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
	} ## end SKIP:
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

	is_deeply(
		$app->ip_geo('not-an-ip'),
		{ country => '', subdivision => '', city => '' },
		'ip_geo returns empty triple for malformed input'
	);

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

		is_deeply(
			$app->ip_geo('1.2.3.4'),
			{ country => 'US', subdivision => 'CA', city => 'Mountain View' },
			'ip_geo returns country, subdivision, and city from one pass, upcased where applicable'
		);

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
	} ## end SKIP:
}

# ---------------------------------------------------------------------------
# cape_results helpers: results endpoints are derived from [cape_servers.NAME]
# keyed by instance, with results_url/results_apikey falling back to url/apikey,
# and are available independently of cape_enable (results fetching is read-only).
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;

	is( $app->cape_results_enabled(),       0,     'cape_results_enabled defaults to 0 with no cape_servers' );
	is( $app->cape_results_for('anything'), undef, 'cape_results_for returns undef with no cape_servers' );
	is( $app->cape_results_for(undef),      undef, 'cape_results_for(undef) is undef' );
}

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	# cape_enable intentionally left off: results viewing must not depend on it.
	print $fh "[cape_servers.main]\n";
	print $fh "url = \"https://cape.example:8080/\"\n";
	print $fh "apikey = \"submitkey\"\n";
	print $fh "[cape_servers.split]\n";
	print $fh "url = \"https://submit.example:8080\"\n";
	print $fh "apikey = \"submitkey2\"\n";
	print $fh "results_url = \"https://results.example:9090/\"\n";
	print $fh "results_apikey = \"resultkey\"\n";
	print $fh "web_url = \"https://cape-ui.example/\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;

	is( $app->cape_results_enabled(), 1, 'cape_results_enabled is 1 when a cape_server is configured' );

	# main: results fall back to the submission url (trailing slash trimmed) and
	# apikey; no web_url configured, so the key is absent (not undef)
	is_deeply(
		$app->cape_results_for('main'),
		{ url => 'https://cape.example:8080', apikey => 'submitkey' },
		'results default to url/apikey with the trailing slash normalised off, no web_url'
	);

	# split: explicit results_url/results_apikey win over the submission ones, and
	# web_url is carried through with its trailing slash normalised off
	is_deeply(
		$app->cape_results_for('split'),
		{ url => 'https://results.example:9090', apikey => 'resultkey', web_url => 'https://cape-ui.example' },
		'results_url/results_apikey/web_url override and normalise correctly'
	);

	is( $app->cape_results_for('nope'), undef, 'cape_results_for is undef for an unknown instance' );
}

# ---------------------------------------------------------------------------
# 13.  Shodan helpers — the enable and the key that picks the tier
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh "enable_shodan = true\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;

	is( $app->shodan_enable(),    1,            'enable_shodan = true turns the lookup on' );
	is( $app->shodan_api_key(),   '',           'a key is optional -- without one the keyless tier is used' );
	is( $app->shodan_source(),    'internetdb', 'no key selects the keyless tier' );
	is( $app->shodan_cache_ttl(), 2592000,      'the cache ttl defaults to a month' );
	is( $app->shodan_history(),   0,            'history is off unless asked for' );
}

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh "enable_shodan = true\n";
	print $fh qq{shodan_api_key = "abc123"\n};
	print $fh "shodan_cache_ttl = 900\n";
	print $fh "shodan_history = true\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;

	is( $app->shodan_api_key(),   'abc123', 'shodan_api_key is read from the config' );
	is( $app->shodan_source(),    'api',    'a key selects the host API tier' );
	is( $app->shodan_cache_ttl(), 900,      'shodan_cache_ttl is read from the config' );
	is( $app->shodan_history(),   1,        'shodan_history = true turns history on' );

	# The tags that change what an alert means are coloured on the results
	# tables; everything else Shodan tags a host with stays grey.
	is( $app->shodan_tag_class('compromised'), 'bg-danger',            'a compromised host is flagged red' );
	is( $app->shodan_tag_class('tor'),         'bg-warning text-dark', 'a tor node is flagged amber' );
	is( $app->shodan_tag_class('cloud'),       'bg-secondary',         'a descriptive tag stays grey' );
	is( $app->shodan_tag_class(undef),         'bg-secondary',         'an unset tag stays grey' );

	# No rows, no query -- the badge helper never reaches the database for a page
	# that names no addresses, which is what keeps it off the unconfigured ones.
	is_deeply( $app->shodan_badges( [] ),  {}, 'no results means no badge lookup' );
	is_deeply( $app->shodan_badges(undef), {}, 'no result set at all means no badge lookup' );

	# a TOML false must read as off, through the whole parse path
	{
		my ( $false_fh, $false_cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
		print $false_fh "dsn = \"dbi:Pg:dbname=test\"\n";
		print $false_fh "shodan_history = false\n";
		close $false_fh;

		local $ENV{LILITH_CONFIG} = $false_cf;
		my $false_app = Test::Mojo->new('Lilith::Web')->app;
		is( $false_app->shodan_history(), 0, 'shodan_history = false reads as off' );
	}

	# cve_matches -- the rule's ids against the badges' vuln_ids, which is the
	# whole CVE-match comparison the results table badges by. Pure, so no
	# database and no mocks: rows and badges in, matched ids out.
	require Mojo::JSON;
	my $badges = {
		'198.51.100.9' => {
			ports    => [],
			tags     => [],
			vulns    => 2,
			vuln_ids => [ 'CVE-2021-44228', 'CVE-2020-1472' ],
			max_cvss => 10,
		},
	};
	my $rows = [
		{
			id      => 1,
			dest_ip => '198.51.100.9',
			raw     => Mojo::JSON::encode_json( { alert => { metadata => { cve => ['CVE_2021_44228'] } } } ),
		},
		{
			id      => 2,
			dest_ip => '198.51.100.9',
			raw     => Mojo::JSON::encode_json( { alert => { metadata => { cve => ['CVE-2014-6271'] } } } ),
		},
		{
			id      => 3,
			dest_ip => '203.0.113.7',
			raw     => Mojo::JSON::encode_json( { alert => { metadata => { cve => ['CVE-2021-44228'] } } } ),
		},
		{
			id      => 4,
			dest_ip => '198.51.100.9',
			raw     => Mojo::JSON::encode_json( { alert => { signature => 'no ids' } } )
		},

		# the cached-vulnerable host on the source end: which end it lands on
		# is up to the rule that fired, so both are compared
		{
			id     => 5,
			src_ip => '198.51.100.9',
			raw    => Mojo::JSON::encode_json( { alert => { metadata => { cve => ['CVE-2020-1472'] } } } ),
		},
	];

	is_deeply(
		$app->cve_matches( 'suricata', $rows, $badges ),
		{ 1 => { dest => ['CVE-2021-44228'] }, 5 => { src => ['CVE-2020-1472'] } },
		'each row matches on the end whose cached entry carries a rule CVE'
	);
	is_deeply( $app->cve_matches( 'sagan',    $rows, $badges ), {}, 'only suricata rules carry CVE metadata' );
	is_deeply( $app->cve_matches( 'suricata', $rows, {} ),      {}, 'no badges, no matches' );

	# the event view holds raw already decoded; that is read as it stands
	is_deeply(
		$app->cve_matches(
			'suricata',
			[
				{
					id      => 9,
					dest_ip => '198.51.100.9',
					raw     => { alert => { metadata => { cve => ['CVE-2020-1472'] } } },
				}
			],
			$badges
		),
		{ 9 => { dest => ['CVE-2020-1472'] } },
		'a decoded raw is read as it stands'
	);
}

# ---------------------------------------------------------------------------
# 14.  baphomet_subjects helper — subject_vars and subjects_crossed combined
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;

	is_deeply(
		$app->baphomet_subjects(
			{
				subject_vars        => { SRC => '203.0.113.66', USER => 'jdoe' },
				subject_vars_scores => { SRC => 9.5,            USER => 3 },
				subjects_crossed    => { SRC => 9.5 }
			}
		),
		{ SRC => { val => '203.0.113.66', score => 9.5, crossed => 1 }, USER => { val => 'jdoe', score => 3 } },
		'every var carries its held score, and only the one that crossed is marked'
	);

	# nothing held for a var means it stands at nothing, not at unknown
	is_deeply(
		$app->baphomet_subjects( { subject_vars => { USER => 'jdoe' } } ),
		{ USER => { val => 'jdoe', score => 0 } },
		'a var with no score held scores 0'
	);

	# a crossing record from a rule with no scores of its own still has the
	# crossing score to show
	is_deeply(
		$app->baphomet_subjects(
			{ subject_vars => { SRC => '203.0.113.66' }, subjects_crossed => { SRC => 9.5 } }
		),
		{ SRC => { val => '203.0.113.66', score => 9.5, crossed => 1 } },
		'the crossing score stands in when nothing is held'
	);

	# a usedns rule resolves a var to a hostname plus addresses; the value rides
	# through as it was stored rather than being flattened, and the addresses
	# raced the one threshold so the highest of their scores is the var's
	is_deeply(
		$app->baphomet_subjects(
			{
				subject_vars =>
					{ SRC => { hostname => 'scanner.example.org', ip => [ '203.0.113.66', '198.51.100.9' ] } },
				subject_vars_scores => { SRC => { '203.0.113.66' => 5, '198.51.100.9' => 7 } }
			}
		),
		{
			SRC => {
				val   => { hostname => 'scanner.example.org', ip => [ '203.0.113.66', '198.51.100.9' ] },
				score => 7
			}
		},
		'a resolved subject keeps its hostname/ip structure and takes its highest address score'
	);

	# a var seen only as scored still shows up, without a value to show for it
	is_deeply(
		$app->baphomet_subjects( { subjects_crossed => { USER => 5 } } ),
		{ USER => { score => 5, crossed => 1 } },
		'a crossed var missing from subject_vars still appears'
	);

	is_deeply( $app->baphomet_subjects( {} ),   {}, 'a record with none of the keys combines to nothing' );
	is_deeply( $app->baphomet_subjects(undef),  {}, 'an undecodable record combines to nothing' );
	is_deeply( $app->baphomet_subjects('nope'), {}, 'a non-hash record combines to nothing' );
	is_deeply( $app->baphomet_subjects( { subject_vars => 'nope' } ),
		{}, 'a subject_vars that is not a hash is ignored' );
}

# ---------------------------------------------------------------------------
# 15.  baphomet_subjects_line helper — the search column's one line render
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;

	is(
		$app->baphomet_subjects_line(
			{
				subject_vars        => { USER => 'jdoe', SRC => '203.0.113.66' },
				subject_vars_scores => { USER => 3,      SRC => 9.5 },
				subjects_crossed    => { SRC  => 9.5 }
			}
		),
		'!SRC=203.0.113.66 (9.5), USER=jdoe (3)',
		'vars render sorted by name with their scores, the crossed one marked'
	);

	is(
		$app->baphomet_subjects_line(
			{
				subject_vars        => { SRC => { hostname       => 'scanner.example.org', ip => ['203.0.113.66'] } },
				subject_vars_scores => { SRC => { '203.0.113.66' => 5 } }
			}
		),
		'SRC=scanner.example.org (5)',
		'a resolved subject renders as its hostname'
	);

	is(
		$app->baphomet_subjects_line( { subject_vars => { SRC => { ip => ['203.0.113.66'] } } } ),
		'SRC=203.0.113.66 (0)',
		'a resolved subject with no hostname falls back to its first address'
	);

	is(
		$app->baphomet_subjects_line( { subject_vars => { SRC => [ '203.0.113.66', '198.51.100.9' ] } } ),
		'SRC=203.0.113.66, 198.51.100.9 (0)',
		'a var holding several unresolved values renders as the list it is'
	);

	is( $app->baphomet_subjects_line( { subjects_crossed => { USER => 5 } } ),
		'!USER (5)', 'a var with no value renders as the name and score alone' );

	is( $app->baphomet_subjects_line( {} ),  '', 'a record with no subject vars renders as empty' );
	is( $app->baphomet_subjects_line(undef), '', 'an undecodable record renders as empty' );
}

# ---------------------------------------------------------------------------
# 16.  the Subjects cell partial — the same line with the crossed var in red
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $app = Test::Mojo->new('Lilith::Web')->app;
	my $c   = $app->build_controller;

	my $subjects = $c->baphomet_subjects(
		{
			subject_vars => {
				SRC  => { hostname => 'scanner.example.org', ip => [ '203.0.113.66', '198.51.100.9' ] },
				USER => 'j<doe>'
			},
			subject_vars_scores => { SRC => { '203.0.113.66' => 5, '198.51.100.9' => 7 }, USER => 3 },
			subjects_crossed    => { SRC => 7 },
		}
	);

	my $rendered = $c->render_to_string( template => 'partials/_subjects_cell', subjects => $subjects );

	like(
		$rendered,
		qr{<span class="text-danger fw-bold" title="crossed its threshold">!SRC</span>=scanner\.example\.org \(7\)},
		'the var that crossed renders in red, as its hostname and highest address score'
	);
	like( $rendered, qr/(?<!>)USER=j&lt;doe&gt; \(3\)/, 'a var that did not cross renders plain, and escaped' );

	is( $c->render_to_string( template => 'partials/_subjects_cell', subjects => {} ),
		"\n", 'a record with no subject vars renders nothing' );
}

done_testing();
