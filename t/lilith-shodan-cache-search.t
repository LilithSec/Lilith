#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use DBI                    ();
use Lilith                 ();
use Lilith::Schema         ();
use DBIx::Class::Migration ();

# shodan_cache_search against a real PostgreSQL server: TestPG initdb's a
# throwaway cluster, the schema is deployed into it, three cache rows are
# written through shodan_cache_put, and every filter runs its real SQL. The
# addresses are 45.0.0.x for the same reason lilith-shodan-cli.t's are; nothing
# here makes a request either way.
use TestPG ();

plan skip_all => 'PostgreSQL server binaries (initdb/pg_ctl/postgres) not found'
	unless TestPG->bindir;

my $pg = eval { TestPG->new };
BAIL_OUT("could not start PostgreSQL: $@") unless $pg;

DBIx::Class::Migration->new(
	schema_class => 'Lilith::Schema',
	schema_args  => [ $pg->dsn, $pg->user, $pg->pass ],
)->dbic_dh->install;

my $lilith = Lilith->new( dsn => $pg->dsn, user => $pg->user, pass => $pg->pass );

# The fixtures: an API-tier host with the works, a keyless summary whose CVE
# only the CVEDB cache can score, and an address Shodan has never crawled.
$lilith->shodan_cache_put(
	ip     => '45.0.0.1',
	source => 'api',
	raw    => { ports => [ 22, 80 ] },
	info   => {
		ports       => [ 22,         80 ],
		tags        => [ 'honeypot', 'cloud' ],
		cpes        => ['cpe:2.3:a:nginx:nginx:1.18.0'],
		vulns       => [ { cve => 'CVE-2021-44228', cvss => 9.8, summary => '', verified => 0 } ],
		hostnames   => ['gate1.example.org'],
		last_update => '2026-06-14T02:11:33',
		os          => 'Linux 3.x',
		org         => 'Example Hosting LLC',
		isp         => 'Example Carrier Inc',
		asn         => 'AS64496',
		callouts    => [
			{ text => 'self-signed certificate', level => 'warning', key => 'self-signed' },
			{ text => 'exposed RDP',             level => 'danger',  key => 'exposed-rdp' },
		],
		html_hashes       => [12345678],
		cert_fingerprints => ['aabbcc'],
		banner_hashes     => [-1524570663],
		products          => ['nginx'],
		port_products     => ['80 nginx 1.18.0'],
	},
	ttl => 3600,
);
$lilith->shodan_cache_put(
	ip     => '45.0.0.2',
	source => 'internetdb',
	raw    => { ports => [443] },
	info   => {
		ports     => [443],
		tags      => [],
		cpes      => [],
		vulns     => [ { cve => 'CVE-2020-11984', cvss => '', summary => '', verified => 0 } ],
		hostnames => [],
	},
	ttl => 3600,
);
$lilith->shodan_cache_put( ip => '45.0.0.3', source => 'api', raw => {}, info => {}, ttl => 3600 );

# put writes an empty list as '{}' rather than NULL, so NULL the never-crawled
# row's arrays by hand -- the array filters must read a NULL column as "no
# matching element" rather than let SQL NULL poison a negation.
{
	my $dbh = DBI->connect( $pg->dsn, $pg->user, $pg->pass, { RaiseError => 1 } );
	$dbh->do(
		q{update shodan_cache set ports = NULL, tags = NULL, cpes = NULL, vulns = NULL,
		hostnames = NULL, callouts = NULL, html_hashes = NULL, cert_fingerprints = NULL,
		banner_hashes = NULL, products = NULL, port_products = NULL where ip = '45.0.0.3'}
	);
	$dbh->disconnect;
}

# Run a search with the given options and hand back the matched addresses,
# sorted -- what most of the assertions below care about.
sub matched_ips {
	my (%opts) = @_;

	my $rows = $lilith->shodan_cache_search(%opts);
	return [ sort map { $_->{ip} } @{$rows} ];
}

# ----------------------------------------------------------------------------
# the row shape
# ----------------------------------------------------------------------------

my $rows = $lilith->shodan_cache_search( order_by => 'ip', order_dir => 'ASC' );
is( scalar @{$rows}, 3,          'no filters returns the whole cache' );
is( $rows->[0]{ip},  '45.0.0.1', 'ordered by ip ascending' );
ok( $rows->[0]{found},  'the crawled host reads found' );
ok( !$rows->[2]{found}, 'the never-crawled address reads not found' );
is_deeply( $rows->[0]{ports},         [ 22,         80 ],      'ports come back as an array ref' );
is_deeply( $rows->[0]{tags},          [ 'honeypot', 'cloud' ], 'tags come back as an array ref' );
is_deeply( $rows->[0]{port_products}, ['80 nginx 1.18.0'], 'the port-to-product pairing rides back with the row' );
is( $rows->[0]{max_cvss} + 0, 9.8,         'max_cvss carries the stored worst score' );
is( $rows->[0]{os},           'Linux 3.x', 'the schema 17 host columns ride along' );
is( $rows->[0]{source},       'api',       'source rides along' );
like( $rows->[0]{fetched}, qr/^\d{4}-\d{2}-\d{2} /, 'fetched is a timestamp string' );
# stored as UTC, read back in the session's zone -- so only the parts a zone
# shift cannot move are asserted
like( $rows->[0]{last_update}, qr/^2026-06-1[34] \d{2}:11:33/, 'last_update is stored and returned' );

# ----------------------------------------------------------------------------
# the filters
# ----------------------------------------------------------------------------

is_deeply( matched_ips( ip => '45.0.0.1' ),    ['45.0.0.1'],                            'ip equality' );
is_deeply( matched_ips( ip => '45.0.0.2/31' ), [ '45.0.0.2', '45.0.0.3' ],              'ip CIDR containment' );
is_deeply( matched_ips( ip => '45.0.0.%' ),    [ '45.0.0.1', '45.0.0.2', '45.0.0.3' ],  'ip % pattern' );
is_deeply( matched_ips( ip => '!45.0.0.1' ),   [ '45.0.0.2', '45.0.0.3' ],              'ip negation' );
is_deeply( matched_ips( ip => [ '45.0.0.1', '45.0.0.2' ] ), [ '45.0.0.1', '45.0.0.2' ], 'several ips OR' );

is_deeply( matched_ips( tag => 'honeypot' ), ['45.0.0.1'], 'tag membership' );
is_deeply(
	matched_ips( tag => '!honeypot' ),
	[ '45.0.0.2', '45.0.0.3' ],
	'tag negation matches the empty and the NULL row alike'
);

is_deeply( matched_ips( port => '22' ),   ['45.0.0.1'],               'port membership' );
is_deeply( matched_ips( port => '>400' ), ['45.0.0.2'],               'port comparison' );
is_deeply( matched_ips( port => '!22' ),  [ '45.0.0.2', '45.0.0.3' ], 'port negation' );

is_deeply( matched_ips( cve => 'CVE-2021-44228' ), ['45.0.0.1'], 'cve membership' );
is_deeply( matched_ips( cve => 'CVE-2020-%' ),     ['45.0.0.2'], 'cve % pattern' );

is_deeply( matched_ips( hostname => '%.example.org' ), ['45.0.0.1'], 'hostname % pattern' );
is_deeply( matched_ips( cpe      => '%nginx%' ),       ['45.0.0.1'], 'cpe % pattern' );

is_deeply( matched_ips( found => 'known' ),   [ '45.0.0.1', '45.0.0.2' ], 'found known' );
is_deeply( matched_ips( found => 'unknown' ), ['45.0.0.3'],               'found unknown' );

is_deeply( matched_ips( source => 'api' ),        [ '45.0.0.1', '45.0.0.3' ], 'source api' );
is_deeply( matched_ips( source => 'internetdb' ), ['45.0.0.2'],               'source internetdb' );

is_deeply( matched_ips( os  => 'Linux%' ),              ['45.0.0.1'], 'os LIKE' );
is_deeply( matched_ips( org => 'Example Hosting LLC' ), ['45.0.0.1'], 'org equality' );
is_deeply( matched_ips( asn => 'AS64496' ),             ['45.0.0.1'], 'asn equality' );
is_deeply(
	matched_ips( os => '!Linux%' ),
	[ '45.0.0.2', '45.0.0.3' ],
	'os negation matches the rows the tier sent nothing for'
);

is_deeply( matched_ips( max_cvss => '>=9' ), ['45.0.0.1'], 'max_cvss comparison' );
is_deeply( matched_ips( max_cvss => '9.8' ), ['45.0.0.1'], 'max_cvss equality' );

# the version 18 columns: the callout keys, and the service fingerprints
is_deeply( matched_ips( callout => 'self-signed' ), ['45.0.0.1'], 'callout membership by key' );
is_deeply( matched_ips( callout => 'exposed-%' ),   ['45.0.0.1'], 'callout % pattern' );
is_deeply(
	matched_ips( callout => '!self-signed' ),
	[ '45.0.0.2', '45.0.0.3' ],
	'callout negation matches the empty and the NULL row alike'
);
is_deeply( matched_ips( html_hash   => '12345678' ),    ['45.0.0.1'], 'html_hash membership' );
is_deeply( matched_ips( banner_hash => '-1524570663' ), ['45.0.0.1'], 'banner_hash membership, negative and all' );
is_deeply( matched_ips( cert        => 'aabbcc' ),      ['45.0.0.1'], 'cert fingerprint membership' );
is_deeply( matched_ips( html_hash   => '!12345678' ),   [ '45.0.0.2', '45.0.0.3' ], 'html_hash negation' );

# the version 19 product column
is_deeply( matched_ips( product => 'nginx' ),  ['45.0.0.1'],               'product membership' );
is_deeply( matched_ips( product => 'ngin%' ),  ['45.0.0.1'],               'product % pattern' );
is_deeply( matched_ips( product => '!nginx' ), [ '45.0.0.2', '45.0.0.3' ], 'product negation' );

is_deeply( matched_ips( tag => 'honeypot', port => '80' ), ['45.0.0.1'], 'filters AND across each other' );
is_deeply(
	matched_ips( fetched_within_minutes => 60 ),
	[ '45.0.0.1', '45.0.0.2', '45.0.0.3' ],
	'a fresh cache is inside the fetched window'
);

# ----------------------------------------------------------------------------
# the CVEDB stand-in: the keyless row's CVE has no score of its own until the
# cvedb_cache holds one, and then max_cvss reads it, the same as the badges
# ----------------------------------------------------------------------------

is_deeply( matched_ips( max_cvss => '>=7' ), ['45.0.0.1'], 'the unscored keyless CVE fails the comparison' );

$lilith->cvedb_cache_put(
	cve  => 'CVE-2020-11984',
	raw  => { summary => 'buffer overflow' },
	info => { cvss    => 7.5 },
);

is_deeply(
	matched_ips( max_cvss => '>=7' ),
	[ '45.0.0.1', '45.0.0.2' ],
	'the CVEDB cache stands in for the tier that sent no scores'
);

$rows = $lilith->shodan_cache_search( ip => '45.0.0.2' );
is( $rows->[0]{max_cvss} + 0, 7.5, 'and the stood-in score is the one returned' );

# ----------------------------------------------------------------------------
# ordering and paging
# ----------------------------------------------------------------------------

$rows = $lilith->shodan_cache_search( order_by => 'max_cvss', order_dir => 'DESC' );
is( $rows->[0]{ip}, '45.0.0.1', 'ordering by max_cvss leads with the worst host' );
is( $rows->[2]{ip}, '45.0.0.3', 'and the row with no score anywhere sorts last' );

$rows = $lilith->shodan_cache_search( order_by => 'ip', order_dir => 'ASC', limit => 1, offset => 1 );
is( scalar @{$rows}, 1,          'limit caps the page' );
is( $rows->[0]{ip},  '45.0.0.2', 'offset moves it' );

# ----------------------------------------------------------------------------
# shodan_cache_values -- what the browser's filter dropdowns offer
# ----------------------------------------------------------------------------

is_deeply(
	$lilith->shodan_cache_values( column => 'tag' ),
	[ { value => 'cloud', count => 1 }, { value => 'honeypot', count => 1 } ],
	'tag values count once per element, ties ordered by value'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'port' ),
	[ { value => 22, count => 1 }, { value => 80, count => 1 }, { value => 443, count => 1 } ],
	'port values come from the integer column, in numeric order'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'source' ),
	[ { value => 'api', count => 2 }, { value => 'internetdb', count => 1 } ],
	'scalar values count once per row, most common first'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'os' ),
	[ { value => 'Linux 3.x', count => 1 } ],
	'the rows holding nothing are not offered as values'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'cve', limit => 1 ),
	[ { value => 'CVE-2020-11984', count => 1 } ],
	'limit caps the list'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'tag', fetched_within_minutes => 60 ),
	[ { value => 'cloud', count => 1 }, { value => 'honeypot', count => 1 } ],
	'a fresh cache is inside the fetched window'
);

is_deeply(
	$lilith->shodan_cache_values( column => 'callout' ),
	[ { value => 'exposed-rdp', count => 1 }, { value => 'self-signed', count => 1 } ],
	'callout values count once per key, ties ordered by value'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'html_hash' ),
	[ { value => 12345678, count => 1 } ],
	'html_hash values come from the integer column'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'banner_hash' ),
	[ { value => -1524570663, count => 1 } ],
	'banner_hash values keep their sign'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'cert' ),
	[ { value => 'aabbcc', count => 1 } ],
	'cert fingerprint values are offered'
);
is_deeply(
	$lilith->shodan_cache_values( column => 'product' ),
	[ { value => 'nginx', count => 1 } ],
	'product values are offered'
);

eval { $lilith->shodan_cache_values( column => 'raw' ) };
like( $@, qr/not a shodan_cache filter/, 'a column with no values to offer dies' );
eval { $lilith->shodan_cache_values( column => 'tag', fetched_within_minutes => 'week' ) };
like( $@, qr/fetched_within_minutes/, 'a non-numeric window dies' );

# ----------------------------------------------------------------------------
# shodan_cache_stats -- the summary the CLI command prints
# ----------------------------------------------------------------------------

{
	my $stats = $lilith->shodan_cache_stats( ttl => 3600 );
	is( $stats->{total},     3, 'the total is every cached address' );
	is( $stats->{found},     2, 'found counts the addresses Shodan had something on' );
	is( $stats->{not_found}, 1, 'not_found counts the cached "nothing known"' );
	is_deeply( $stats->{by_source}, { api => 2, internetdb => 1 }, 'the source breakdown' );
	is( $stats->{with_vulns}, 2, 'with_vulns counts the rows carrying a CVE' );
	is( $stats->{high_cvss},  1, 'high_cvss counts the rows with a stored score >= 9' );
	is( $stats->{fresh},      3, 'fresh counts the rows fetched within the ttl' );

	# coverage counts rows written since the upgrade -- an empty array is still a
	# write (it is not NULL); only the row NULLed to mimic a pre-upgrade one is
	# uncovered.
	is( $stats->{with_callouts},      2, 'callout coverage excludes only the NULL (pre-upgrade) row' );
	is( $stats->{with_products},      2, 'product coverage excludes only the NULL (pre-upgrade) row' );
	is( $stats->{with_port_products}, 2, 'port product coverage excludes only the NULL (pre-upgrade) row' );

	like( $stats->{newest}, qr/^\d{4}-\d{2}-\d{2} /, 'newest is a timestamp string' );

	my $no_ttl = $lilith->shodan_cache_stats;
	ok( !exists $no_ttl->{fresh}, 'without a ttl there is no freshness count' );
}

# ----------------------------------------------------------------------------
# the deaths
# ----------------------------------------------------------------------------

for my $bad (
	[ { order_by               => 'raw' },       qr/not a sortable/,  'an unknown order_by dies' ],
	[ { order_dir              => 'SIDEWAYS' },  qr/order_dir/,       'a bad order_dir dies' ],
	[ { limit                  => 'all' },       qr/limit/,           'a non-numeric limit dies' ],
	[ { ip                     => 'not an ip' }, qr/for ip/,          'a malformed ip dies naming the filter' ],
	[ { port                   => 'ssh' },       qr/for port/,        'a non-numeric port dies' ],
	[ { max_cvss               => 'high' },      qr/for max_cvss/,    'a non-numeric max_cvss dies' ],
	[ { html_hash              => 'abc' },       qr/for html_hash/,   'a non-integer html_hash dies' ],
	[ { banner_hash            => 'xyz' },       qr/for banner_hash/, 'a non-integer banner_hash dies' ],
	[ { found                  => 'maybe' },     qr/for found/,       'a value outside the found vocabulary dies' ],
	[ { source                 => 'psychic' },   qr/for source/,      'a value outside the source vocabulary dies' ],
	[ { fetched_within_minutes => 'week' },      qr/fetched_within_minutes/, 'a non-numeric window dies' ],
	)
{
	my ( $opts, $message, $name ) = @{$bad};
	eval { $lilith->shodan_cache_search( %{$opts} ) };
	like( $@, $message, $name );
} ## end for my $bad ( [ { order_by => 'raw' }, qr/not a sortable/...])

done_testing();
