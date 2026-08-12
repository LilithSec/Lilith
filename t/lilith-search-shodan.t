#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('Lilith')         or BAIL_OUT('Lilith failed to load');
use_ok('Lilith::Schema') or BAIL_OUT('Lilith::Schema failed to load');

# The Shodan enrichment filters and the rule CVE filter, tested at the same
# level as lilith-search-strings.t: Lilith::Schema->connect mocked out, the
# search hash captured, and the clauses inspected. The literal SQL asserted
# here is the contract; the same filters run against a real database in
# pg-migrate.t.

# ---------------------------------------------------------------------------
# Mock out Lilith::Schema->connect. Unlike the other search mocks this one
# also answers storage->dbh->selectrow_array, since these filters probe the
# catalog for shodan_cache, cvedb_cache, and the cves column; the three
# package flags below are what a test flips to play an older schema.
# ---------------------------------------------------------------------------

my $captured_search;
our ( $shodan_present, $cvedb_present, $cves_present ) = ( 1, 1, 1 );

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

	package Lilith::Test::MockDbh;

	sub selectrow_array {
		my ( $self, $sql ) = @_;
		if ( $sql =~ /to_regclass\('shodan_cache'\)/ ) {
			return $main::shodan_present ? ('shodan_cache') : (undef);
		}
		if ( $sql =~ /to_regclass\('cvedb_cache'\)/ ) {
			return $main::cvedb_present ? ('cvedb_cache') : (undef);
		}
		if ( $sql =~ /pg_attribute/ ) {
			return $main::cves_present ? (1) : ();
		}
		return ();
	} ## end sub selectrow_array

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

{
	# on a schema before 16 the coalesce has nothing to reach for and the
	# bare column is used, the same as the badges read
	local $cvedb_present = 0;
	is_deeply(
		filter_clauses( shodan_src_cvss => ['>=9'] ),
		[ \[ 'exists (select 1 from shodan_cache where shodan_cache.ip = me.src_ip and (max_cvss) >= ?)', '9' ] ],
		'without cvedb_cache the bare max_cvss is compared'
	);
}

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
	$lilith->search( table => 'baphomet', shodan_src_tag => 'tor' );
	ok( defined $captured_search->{'-and'}, 'baphomet gets the shodan filters' );
}

{
	local $shodan_present = 0;
	my $died = '';
	eval { filter_clauses( shodan_src_tag => 'tor' ) };
	$died = $@ if $@;
	like(
		$died,
		qr/the shodan_\* search filters need the shodan_cache table \(schema version 15\)/,
		'a schema without shodan_cache dies plainly'
	);
}

{
	local $cves_present = 0;
	my $died = '';
	eval { filter_clauses( cve => 'CVE-2021-44228' ) };
	$died = $@ if $@;
	like(
		$died,
		qr/the cve search filter needs the suricata_alerts cves column \(schema version 16\)/,
		'a schema without the cves column dies plainly'
	);
}

# a blank filter adds nothing, the same as every other filter
{
	is_deeply( filter_clauses( shodan_src_tag => [ '', undef ] ), undef, 'blank values add no clauses' );
}

done_testing();
