#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith')         or BAIL_OUT('Lilith failed to load');
use_ok('Lilith::Schema') or BAIL_OUT('Lilith::Schema failed to load');

# The Shodan enrichment filters, the rule CVE filter, and the locality pair,
# tested at the same level as lilith-search-strings.t: Lilith::Schema->connect
# mocked out, the search hash captured, and the clauses inspected. The literal
# SQL asserted here is the contract; the same filters run against a real
# database in pg-migrate.t.

# ---------------------------------------------------------------------------
# Mock out Lilith::Schema->connect so a search builds its clauses without a
# database; MockRS->search captures the clause tree the assertions read. The
# filters reference the current schema's columns and tables directly, so
# nothing here has to answer the catalog.
# ---------------------------------------------------------------------------

my $captured_search;

{

	package Lilith::Test::MockRS;

	sub search {
		my ( $self, $search, $attrs ) = @_;
		$captured_search = $search;
		return $self;
	}

	sub all {
		return ();
	}

	package Lilith::Test::MockStorage;

	sub dbh {
		return bless {}, 'Lilith::Test::MockDbh';
	}

	package Lilith::Test::MockSchema;

	sub resultset {
		return bless {}, 'Lilith::Test::MockRS';
	}

	sub storage {
		return bless {}, 'Lilith::Test::MockStorage';
	}
}

no warnings qw(redefine once);
*Lilith::Schema::connect = sub { return bless {}, 'Lilith::Test::MockSchema' };
use warnings qw(redefine once);

my $lilith = Lilith->new( dsn => 'dbi:Pg:dbname=test' );

# Run a search with the given filters and hand back the clauses it produced.
sub filter_clauses {
	my (%search) = @_;
	$captured_search = undef;
	$lilith->search( table => 'suricata', %search );
	return $captured_search->{'-and'};
}

# the EXISTS bodies the clauses are built from, so the assertions below read
# as structure rather than as one long string each
my $src_tag_exists
	= 'exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip and shodan_cache.tags && ?::varchar[])';
my $dest_tag_exists
	= 'exists (select 1 from shodan_cache where shodan_cache.ip = me.dest_ip and shodan_cache.tags && ?::varchar[])';
my $src_known     = 'exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip and shodan_cache.found)';
my $src_unknown   = 'exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip and not shodan_cache.found)';
my $src_unchecked = 'not exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip)';
my $cvss_coalesce
	= 'coalesce(max_cvss, (select max(cvedb.cvss) from unnest(vulns) as vuln_id'
	. ' join cvedb_cache as cvedb on cvedb.cve = vuln_id))';

# ---------------------------------------------------------------------------
# tags: positives one overlap, negations one NOT of the same
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( shodan_src_tag => 'tor' ),
	[ \[ $src_tag_exists, '{"tor"}' ] ],
	'a source tag becomes one EXISTS overlap'
);

is_deeply(
	filter_clauses( shodan_src_tag => [ 'tor', 'vpn' ] ),
	[ \[ $src_tag_exists, '{"tor","vpn"}' ] ],
	'several tags stay one overlap, which reads any-of'
);

is_deeply(
	filter_clauses( shodan_src_tag => [ 'tor', '!honeypot' ] ),
	[ \[ $src_tag_exists, '{"tor"}' ], \[ 'not ' . $src_tag_exists, '{"honeypot"}' ] ],
	'a negated tag becomes a NOT EXISTS of its own'
);

is_deeply(
	filter_clauses( shodan_dest_tag => 'compromised' ),
	[ \[ $dest_tag_exists, '{"compromised"}' ] ],
	'the dest side filters dest_ip'
);

# ---------------------------------------------------------------------------
# known: the three cache states, positives ORed, negations complemented
# ---------------------------------------------------------------------------

is_deeply( filter_clauses( shodan_src_known => 'known' ), [ \[$src_known] ], 'known is an EXISTS on found' );

is_deeply( filter_clauses( shodan_src_known => 'unknown' ), [ \[$src_unknown] ], 'unknown is an EXISTS on not found' );

is_deeply( filter_clauses( shodan_src_known => 'unchecked' ), [ \[$src_unchecked] ], 'unchecked is a NOT EXISTS' );

is_deeply(
	filter_clauses( shodan_src_known => [ 'known', 'unknown' ] ),
	[ { '-or' => [ \[$src_known], \[$src_unknown] ] } ],
	'two states OR together'
);

is_deeply(
	filter_clauses( shodan_src_known => '!unchecked' ),
	[ \[ 'not (' . $src_unchecked . ')' ] ],
	'a negated state is its complement'
);

my $bad_known = '';
eval { filter_clauses( shodan_src_known => 'sometimes' ) };
$bad_known = $@ if $@;
like(
	$bad_known,
	qr/"sometimes" for shodan_src_known is not one of known, unknown, or unchecked/,
	'an unknown state dies rather than matching nothing'
);

# ---------------------------------------------------------------------------
# cvss: numeric grammar against the badge-coloring expression
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( shodan_src_cvss => ['>=9'] ),
	[
		\[
			'exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip and ('
				. $cvss_coalesce
				. ') >= ?)',
			'9'
		]
	],
	'a cvss comparison tests the CVEDB-coalesced worst score'
);

is_deeply(
	filter_clauses( shodan_src_cvss => [ '>=7', '<9' ] ),
	[
		\[
			'exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip and ('
				. $cvss_coalesce
				. ') >= ? and ('
				. $cvss_coalesce
				. ') < ?)',
			'7',
			'9'
		]
	],
	'several terms AND inside one row test'
);

my $bad_cvss = '';
eval { filter_clauses( shodan_src_cvss => ['seven'] ) };
$bad_cvss = $@ if $@;
like( $bad_cvss, qr/"seven" does not appear to be a valid item/, 'a non-numeric cvss dies' );

# ---------------------------------------------------------------------------
# cve: normalization, overlap, null-safe negation
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( cve => 'CVE-2021-44228' ),
	[ \[ 'me.cves && ?::text[]', '{"CVE-2021-44228"}' ] ],
	'a cve becomes one overlap against the cves column'
);

is_deeply(
	filter_clauses( cve => 'cve_2021_44228' ),
	[ \[ 'me.cves && ?::text[]', '{"CVE-2021-44228"}' ] ],
	'underscored lowercase normalizes to the canonical id'
);

is_deeply(
	filter_clauses( cve => '2021-44228' ),
	[ \[ 'me.cves && ?::text[]', '{"CVE-2021-44228"}' ] ],
	'a bare year-number pair gains the prefix'
);

is_deeply(
	filter_clauses( cve => '!CVE-2021-44228' ),
	[ \[ 'not coalesce(me.cves && ?::text[], false)', '{"CVE-2021-44228"}' ] ],
	'a negated cve is null-safe, so a rule naming none still matches'
);

my $bad_cve = '';
eval { filter_clauses( cve => 'GHSA-jfh8-c2jp' ) };
$bad_cve = $@ if $@;
like( $bad_cve, qr/is not a CVE id/, 'a non-CVE id dies rather than matching nothing' );

# ---------------------------------------------------------------------------
# the cve_match pair: the dimensions' four buckets as filters, one per end
# ---------------------------------------------------------------------------

# The bucket tests a side's filter builds, against that side's address
# column. Built the same way the code under test builds them, so the
# assertions read as structure.
sub match_sql_for {
	my ($side) = @_;

	my $ip = 'me.' . $side . '_ip';
	my $overlap
		= 'exists (select 1 from shodan_cache where shodan_cache.ip = '
		. $ip
		. ' and me.cves && (shodan_cache.vulns)::text[])';
	my $row = 'exists (select 1 from shodan_cache where shodan_cache.ip = ' . $ip . ')';
	return {
		'matched'   => $overlap,
		'unmatched' => '(me.cves is not null and ' . $row . ' and not ' . $overlap . ')',
		'no-cve'    => 'me.cves is null',
		'unchecked' => '(me.cves is not null and ' . $ip . ' is not null and not ' . $row . ')',
	};
} ## end sub match_sql_for

for my $side (qw(src dest)) {
	my $match_sql = match_sql_for($side);
	my $filter    = 'shodan_' . $side . '_cve_match';

	for my $state ( 'matched', 'unmatched', 'no-cve', 'unchecked' ) {
		is_deeply(
			filter_clauses( $filter => $state ),
			[ \[ $match_sql->{$state} ] ],
			"$filter $state builds its bucket's test"
		);
	}
} ## end for my $side (qw(src dest))

my $dest_match_sql = match_sql_for('dest');

is_deeply(
	filter_clauses( shodan_dest_cve_match => [ 'matched', 'unchecked' ] ),
	[ { '-or' => [ \[ $dest_match_sql->{'matched'} ], \[ $dest_match_sql->{'unchecked'} ] ] } ],
	'two states OR together'
);

is_deeply(
	filter_clauses( shodan_dest_cve_match => '!matched' ),
	[ \[ 'not (' . $dest_match_sql->{'matched'} . ')' ] ],
	'a negated state is its complement'
);

my $bad_match = '';
eval { filter_clauses( shodan_dest_cve_match => 'perhaps' ) };
$bad_match = $@ if $@;
like(
	$bad_match,
	qr/"perhaps" for shodan_dest_cve_match is not one of matched, unmatched, no-cve, or unchecked/,
	'an unknown state dies rather than matching nothing, naming the filter'
);

# ---------------------------------------------------------------------------
# the locality pair: the alert's own ends against the local_networks list
# ---------------------------------------------------------------------------

is_deeply(
	filter_clauses( src_locality => 'internal', local_networks => [ '192.0.2.0/24', '203.0.113.7' ] ),
	[ \["me.src_ip <<= any (array['192.0.2.0/24'::inet, '203.0.113.7'::inet])"] ],
	'src_locality internal is one membership test against the given networks'
);
is_deeply(
	filter_clauses( dest_locality => 'external', local_networks => ['192.0.2.0/24'] ),
	[ \["(me.dest_ip is not null and not (me.dest_ip <<= any (array['192.0.2.0/24'::inet])))"] ],
	'external is null-guarded, so an alert naming no address on that end matches neither'
);

# with no list given, DBUtil's unroutable defaults stand in -- the same list
# the dashboard dimensions fall back to
my $default_inside = Lilith::DBUtil::local_networks_frag('me.src_ip');
is_deeply(
	filter_clauses( src_locality => 'internal' ),
	[ \[$default_inside] ],
	'with no local_networks the default ranges stand in'
);
like( $default_inside, qr{'10\.0\.0\.0/8'::inet}, 'and they are the private ranges' );

my $bad_locality = '';
eval { filter_clauses( src_locality => 'sideways' ) };
$bad_locality = $@ if $@;
like(
	$bad_locality,
	qr/"sideways" for src_locality is not one of internal or external/,
	'an unknown locality dies rather than matching nothing'
);

my $bad_network = '';
eval { filter_clauses( src_locality => 'internal', local_networks => ['10.0.0.0/8; drop'] ) };
$bad_network = $@ if $@;
like( $bad_network, qr/is not an address or CIDR/, 'a network outside the address charset dies' );

{
	# locality reads the alert's own columns, so unlike the enrichment filters
	# cape gets it too
	$captured_search = undef;
	$lilith->search( table => 'cape', src_locality => 'internal' );
	ok( defined $captured_search->{'-and'}, 'locality needs no enrichment, so cape gets it' );
}

# ---------------------------------------------------------------------------
# gating: which tables see the filters at all, and the schema probes
# ---------------------------------------------------------------------------

{
	$captured_search = undef;
	$lilith->search( table => 'cape', shodan_src_tag => 'tor', cve => 'CVE-2021-44228' );
	is( $captured_search->{'-and'}, undef, 'cape skips the enrichment filters entirely' );

	$captured_search = undef;
	$lilith->search( table => 'sagan', cve => 'CVE-2021-44228' );
	is( $captured_search->{'-and'}, undef, 'the cve filter is suricata only' );

	$captured_search = undef;
	$lilith->search( table => 'sagan', shodan_src_cve_match => 'matched', shodan_dest_cve_match => 'matched' );
	is( $captured_search->{'-and'}, undef, 'the cve_match pair is suricata only' );

	$captured_search = undef;
	$lilith->search( table => 'baphomet', shodan_src_tag => 'tor' );
	ok( defined $captured_search->{'-and'}, 'baphomet gets the shodan filters' );
}

# a blank filter adds nothing, the same as every other filter
{
	is_deeply( filter_clauses( shodan_src_tag => [ '', undef ] ), undef, 'blank values add no clauses' );
}

done_testing();
