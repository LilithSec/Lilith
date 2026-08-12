#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith::CVEDB') or BAIL_OUT('Lilith::CVEDB failed to load');

# The CVEDB lookup, tested without a network: everything here is either pure
# or has its fetching half mocked out. The real fetch and the cache table it
# feeds are exercised against a real database in pg-migrate.t.

# ---------------------------------------------------------------------------
# 0.  is_cve_id — the ids that are never sent anywhere
# ---------------------------------------------------------------------------

{
	for my $id (qw( CVE-2021-44228 CVE-1999-0001 CVE-2024-1234567 )) {
		is( Lilith::CVEDB::is_cve_id($id), 1, "$id is a CVE id" );
	}

	# The ids come out of other people's data, so anything off the canonical
	# form is rejected rather than guessed at.
	for my $id (
		'cve-2021-44228',  'CVE-21-44228',        'CVE-2021-123',        ' CVE-2021-44228',
		'CVE-2021-44228 ', 'GHSA-jfh8-c2jp-hhvq', 'CVE-2021-44228;drop', ''
		)
	{
		is( Lilith::CVEDB::is_cve_id($id), 0, "'$id' is not" );
	}
	is( Lilith::CVEDB::is_cve_id(undef),                0, 'undef is not' );
	is( Lilith::CVEDB::is_cve_id( ['CVE-2021-44228'] ), 0, 'a ref is not' );
}

# ---------------------------------------------------------------------------
# 0b.  rule_cves — the ids a rule names, out of a decoded EVE record
# ---------------------------------------------------------------------------

{
	# Every shape rulesets actually write: underscores, lowercase, a bare
	# year-number pair, and ids only present in the signature text. All of it
	# lands in canonical form, deduplicated and sorted. This must stay in step
	# with the suricata_alert_cves SQL function, which pg-migrate.t exercises
	# on the same shapes.
	is_deeply(
		Lilith::CVEDB::rule_cves(
			{
				alert => {
					metadata  => { cve => [ 'CVE_2021_44228', '2020-1472' ] },
					signature => 'ET EXPLOIT Citrix thing CVE-2019-19781 attempt',
				}
			}
		),
		[ 'CVE-2019-19781', 'CVE-2020-1472', 'CVE-2021-44228' ],
		'metadata shapes and a signature id all normalize, sorted'
	);

	is_deeply( Lilith::CVEDB::rule_cves( { alert => { metadata => { cve => 'cve-2014-6271' } } } ),
		['CVE-2014-6271'], 'a single string entry is taken as a one-entry list' );

	is_deeply(
		Lilith::CVEDB::rule_cves(
			{ alert => { metadata => { cve => ['CVE-2021-44228'] }, signature => 'log4j CVE-2021-44228 exploit' } }
		),
		['CVE-2021-44228'],
		'the same id in metadata and signature is one id'
	);

	is_deeply(
		Lilith::CVEDB::rule_cves(
			{ alert => { metadata => { cve => { odd => 1 } }, signature => 'thing CVE_2017_0144 eternalblue' } }
		),
		['CVE-2017-0144'],
		'a structured metadata value is ignored, the signature still read'
	);

	# Anything that does not normalize to an id is dropped rather than guessed
	# at, the same reasoning as is_cve_id.
	is_deeply( Lilith::CVEDB::rule_cves( { alert => { metadata => { cve => [ 'GHSA-jfh8-c2jp', 'not-a-cve' ] } } } ),
		[], 'non-CVE ids yield nothing' );
	is_deeply( Lilith::CVEDB::rule_cves( { alert => { metadata => { cve => ['CVE-2021-123'] } } } ),
		[], 'a short sequence number is rejected' );

	is_deeply( Lilith::CVEDB::rule_cves( { event_type => 'alert' } ), [], 'a record with no alert yields nothing' );
	is_deeply( Lilith::CVEDB::rule_cves(undef),                       [], 'undef yields nothing' );
	is_deeply( Lilith::CVEDB::rule_cves('not a hash'),                [], 'a non-ref yields nothing' );
}

# ---------------------------------------------------------------------------
# 1.  normalize — response reduction
# ---------------------------------------------------------------------------

{
	# CVEDB's own preferred score leads, then v3, then v2.
	is( Lilith::CVEDB::normalize( { cvss => 10, cvss_v3 => 9.8, cvss_v2 => 9.3 } )->{cvss},
		10, 'the preferred cvss field wins' );
	is( Lilith::CVEDB::normalize( { cvss_v3 => 9.8, cvss_v2 => 9.3 } )->{cvss}, 9.8, 'v3 stands in when it is absent' );
	is( Lilith::CVEDB::normalize( { cvss_v2 => 9.3 } )->{cvss},                 9.3, 'v2 last' );
	is( Lilith::CVEDB::normalize( { cvss => 'high' } )->{cvss}, '', 'a non-numeric score is dropped, not passed on' );

	my $info = Lilith::CVEDB::normalize(
		{
			cvss                => 9.8,
			epss                => 0.94321,
			kev                 => 1,
			ransomware_campaign => 'Known',
			summary             => 'mod_proxy SSRF',
			published_time      => '2021-09-16T15:15:07',
		}
	);
	is( $info->{epss},       0.94321,               'epss carries through as a number' );
	is( $info->{kev},        1,                     'kev normalizes to 1' );
	is( $info->{ransomware}, 1,                     'a named ransomware campaign normalizes to 1' );
	is( $info->{summary},    'mod_proxy SSRF',      'summary carries through' );
	is( $info->{published},  '2021-09-16T15:15:07', 'published_time carries through' );

	# An empty response is the full shape with nothing in it, which is what an
	# id CVEDB has nothing on comes to.
	my $empty = Lilith::CVEDB::normalize( {} );
	is_deeply(
		$empty,
		{ cvss => '', epss => '', kev => 0, ransomware => 0, summary => '', published => '' },
		'an empty response is the full shape, empty'
	);
	is_deeply( Lilith::CVEDB::normalize(undef), $empty, 'a non-hash normalizes the same way' );

	# A field holding a structure where a scalar belongs is dropped, not
	# stringified.
	is( Lilith::CVEDB::normalize( { summary => {} } )->{summary}, '', 'a structured summary is dropped' );
}

# ---------------------------------------------------------------------------
# 2.  gather — the guard, and the fetch outcomes
# ---------------------------------------------------------------------------

{
	# A bad id short circuits before any request is made.
	my ( $skipped, $error ) = Lilith::CVEDB::gather('not-a-cve');
	is( $error,              '',             'a skipped lookup is not an error' );
	is( $skipped->{skipped}, 'not a CVE id', 'a bad id is reported as skipped' );

	# The fetch mocked: what is under test is how gather routes its outcomes,
	# the same three-way split Lilith::Shodan::gather makes.
	no warnings qw(redefine once);
	local *Lilith::CVEDB::fetch = sub {
		return ( { cvss => 9.8, kev => 1 }, '' );
	};
	my ( $info, $gather_error, $raw ) = Lilith::CVEDB::gather('CVE-2021-40438');
	is( $gather_error, '',  'a good lookup carries no error' );
	is( $info->{kev},  1,   'the result is the normalized response' );
	is( $raw->{cvss},  9.8, 'the response rides along as it arrived, for the cache' );

	local *Lilith::CVEDB::fetch = sub {
		return ( undef, 'cvedb: request failed (503)' );
	};
	my ( $failed, $failed_error, $failed_raw ) = Lilith::CVEDB::gather('CVE-2021-40438');
	is( $failed_error, 'cvedb: request failed (503)', 'a failed lookup carries the error' );
	is_deeply( $failed, {}, 'and an empty result' );
	is( $failed_raw, undef, 'and nothing to cache' );
}

done_testing();
