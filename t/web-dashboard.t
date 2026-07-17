#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';
use File::Temp qw(tempfile);
use Test::Mojo;

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# Build a Test::Mojo app whose config points at the given connection.
sub app_for {
	my (%c) = @_;
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh 'dsn = "' . $c{dsn} . '"' . "\n";
	print $fh 'user = "' . ( defined $c{user} ? $c{user} : '' ) . '"' . "\n";
	print $fh 'pass = "' . ( defined $c{pass} ? $c{pass} : '' ) . '"' . "\n";
	close $fh;
	$ENV{LILITH_CONFIG} = $cf;
	return Test::Mojo->new('Lilith::Web');
} ## end sub app_for

# ---------------------------------------------------------------------------
# Shell page + static asset + validation error need no database.
# ---------------------------------------------------------------------------
{
	my $t = app_for( dsn => 'dbi:Pg:dbname=test' );

	$t->get_ok('/dashboard')
		->status_is( 200, 'GET /dashboard renders' )
		->element_exists( 'select#db-table',                    'has the table selector' )
		->element_exists( '#db-range button[data-mins="1440"]', 'has the 24h range button' )
		->element_exists( '#card-esc',                          'has the escalated card' )
		->element_exists( 'input#db-gpcd[type="checkbox"]',     'has the Show GPCD checkbox' )
		->element_exists_not( 'input#db-gpcd[checked]', 'Show GPCD is unchecked by default' )
		->element_exists( 'div.grid-stack',                                   'has the (widget) gridstack container' )
		->element_exists( '#db-add-widget',                                   'has the Add widget button' )
		->element_exists( '#widget-modal',                                    'has the widget config modal' )
		->element_exists( '#wm-type',                                         'modal has a widget type selector' )
		->element_exists( '#wm-style option[value="pie"]',                    'modal offers a pie style' )
		->element_exists( 'input#wm-limit[type="number"][min="1"][max="50"]', 'modal has a 1-50 count input' )
		->element_exists( '#db-reset',                                        'has the reset-layout button' )
		->element_exists( 'script[src="/vendor/gridstack/gridstack-all.js"]', 'pulls in Gridstack' )
		->element_exists( 'script[src="/vendor/Chart.js"]',                   'pulls in Chart.js' );

	# The vendored Gridstack assets are served.
	$t->get_ok('/vendor/gridstack/gridstack-all.js')->status_is( 200, 'Gridstack JS served' );
	$t->get_ok('/vendor/gridstack/gridstack.min.css')->status_is( 200, 'Gridstack CSS served' );

	# The column catalog that drives the widget pickers (no DB needed).
	$t->get_ok('/api/dashboard/columns?table=suricata')
		->status_is( 200, 'columns ok' )
		->json_has( '/columns', 'columns returns a list' );
	my %cols = map { $_ => 1 } @{ $t->tx->res->json->{columns} };
	ok( $cols{classification} && $cols{src_ip}, 'columns lists suricata dimensions' );
	ok( $cols{severity},                        'columns includes the virtual severity dimension' );

	# The measures catalog that drives the measure picker (no DB needed).
	$t->get_ok('/api/dashboard/measures?table=suricata')
		->status_is( 200, 'measures ok' )
		->json_has( '/measures', 'measures returns a list' );
	my %meas = map { $_->{name} => 1 } @{ $t->tx->res->json->{measures} };
	ok( $meas{count} && $meas{bytes}, 'measures include count and bytes' );

	# The navbar link the layout now carries.
	$t->get_ok('/search')->element_exists( 'a#nav-dashboard[href="/dashboard"]', 'navbar has a Dashboard link' );

	# The vendored library is actually served.
	$t->get_ok('/vendor/Chart.js')
		->status_is( 200, 'Chart.js is served' )
		->content_type_like( qr/javascript/, 'Chart.js served as javascript' )
		->content_like( qr/Chart/, 'Chart.js body looks like the library' );

	# A non-whitelisted column is rejected before any SQL, so no DB is needed.
	$t->get_ok('/api/dashboard/top?column=bogus')
		->status_is( 400, 'bad column is a 400' )
		->json_like( '/error', qr/not an aggregatable column/, 'error explains the bad column' );
}

# ---------------------------------------------------------------------------
# Live API against a real database.
# ---------------------------------------------------------------------------
SKIP: {
	require TestPG;
	skip 'PostgreSQL server binaries not found', 1 unless TestPG->bindir;

	require DBIx::Class::Migration;
	require Lilith::Schema;

	my $pg = TestPG->new;
	DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $pg->dsn, $pg->user, $pg->pass ],
	)->install;

	my $dbh = $pg->dbh;

	# Three recent Suricata alerts: classification A x2 (src 1.1.1.1), B x1 (src 2.2.2.2).
	my @rows = ( [ 'A', 'sigA', '1.1.1.1' ], [ 'A', 'sigA', '1.1.1.1' ], [ 'B', 'sigB', '2.2.2.2' ] );
	for my $r (@rows) {
		$dbh->do(
			"insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,classification,signature)"
				. " values ('i','h', now(), 'e', ?, ?, ?)",
			undef, $r->[2], $r->[0], $r->[1]
		);
	}

	my $t = app_for( dsn => $pg->dsn, user => $pg->user, pass => $pg->pass );

	$t->get_ok('/api/dashboard/summary?table=suricata')
		->status_is( 200, 'summary ok' )
		->json_is( '/total',                  3,           'summary total' )
		->json_is( '/escalated',              0,           'summary escalated' )
		->json_is( '/distinct_src_ip',        2,           'summary distinct src_ip' )
		->json_is( '/distinct_detail',        2,           'summary distinct signatures' )
		->json_is( '/detail_label',           'signature', 'summary detail label is signature' )
		->json_is( '/busiest_instance/value', 'i',         'summary busiest instance' );

	# The countries panel depends on whether GeoIP MMDBs are installed on the
	# box running the tests, so assert its shape either way: disabled -> empty;
	# enabled -> the geolocated top-IP counts sum back to the source-IP total.
	$t->get_ok('/api/dashboard/countries?table=suricata')->status_is( 200, 'countries ok' );
	my $cj = $t->tx->res->json;
	ok( defined $cj->{enabled}, 'countries reports an enabled flag' );
	is( ref $cj->{rows}, 'ARRAY', 'countries returns a rows array' );
	if ( $cj->{enabled} ) {
		my $sum = 0;
		$sum += $_->{count} for @{ $cj->{rows} };
		is( $sum, 3, 'country counts sum to the source-IP total' );
	} else {
		is_deeply( $cj->{rows}, [], 'no rows when GeoIP is disabled' );
	}

	$t->get_ok('/api/dashboard/top?table=suricata&column=classification')
		->status_is( 200, 'top ok' )
		->json_is( '/rows/0/value', 'A', 'top classification value' )
		->json_is( '/rows/0/count', 2,   'top classification count' );

	$t->get_ok('/api/dashboard/timeseries?table=suricata&group_by=classification&bucket=hour')
		->status_is( 200, 'timeseries ok' )
		->json_is( '/grouped', 1, 'timeseries reports grouped' );

	# The Show GPCD toggle: a GPCD row is hidden by default, included at show_gpcd=1.
	$dbh->do( "insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,classification)"
			. " values ('i','h', now(), 'e', '3.3.3.3', 'Generic Protocol Command Decode')" );
	$t->get_ok('/api/dashboard/summary?table=suricata')->json_is( '/total', 3, 'GPCD hidden by default' );
	$t->get_ok('/api/dashboard/summary?table=suricata&show_gpcd=1')
		->json_is( '/total', 4, 'GPCD included when show_gpcd=1' );

	# Layout persistence: the seeded default board is empty; a POST is stored and
	# read back (exercises Lilith::dashboard_get/save and the version-6 table).
	$t->get_ok('/api/dashboard/layout')
		->status_is( 200, 'layout ok' )
		->json_is( '/name',       'default', 'default board' )
		->json_is( '/is_default', 1,         'is the default' )
		->json_is( '/layout',     [],        'starts empty' );

	# A widget definition round-trips; an unknown type and unknown config keys are
	# dropped by the sanitizer.
	my $layout = [
		{
			id     => 'w1',
			type   => 'top',
			config => { column => 'src_ip', style => 'bar', limit => 25, measure => 'bytes', bogus => 'x' },
			x      => 0,
			y      => 0,
			w      => 4,
			h      => 4
		},
		{ id => 'w2', type => 'nope', config => {}, x => 4, y => 0, w => 4, h => 4 },
	];
	$t->post_ok( '/api/dashboard/layout' => json => { layout => $layout } )
		->status_is( 200, 'layout saved' )
		->json_is( '/ok',    1, 'save ok' )
		->json_is( '/count', 1, 'only the valid widget was kept' );
	$t->get_ok('/api/dashboard/layout')
		->json_is( '/layout/0/id',             'w1',     'saved widget id round-trips' )
		->json_is( '/layout/0/type',           'top',    'saved widget type round-trips' )
		->json_is( '/layout/0/config/column',  'src_ip', 'saved widget config round-trips' )
		->json_is( '/layout/0/config/style',   'bar',    'saved widget style round-trips' )
		->json_is( '/layout/0/config/limit',   25,       'saved widget count round-trips as an integer' )
		->json_is( '/layout/0/config/measure', 'bytes',  'saved widget measure round-trips' )
		->json_hasnt( '/layout/0/config/bogus', 'unknown config key was stripped' )
		->json_hasnt( '/layout/1',              'the unknown-type widget was dropped' );

	# A malformed body is rejected.
	$t->post_ok( '/api/dashboard/layout' => json => { nope => 1 } )->status_is( 400, 'bad layout body is a 400' );

	$dbh->disconnect;
	$pg->stop;
} ## end SKIP:

done_testing;
