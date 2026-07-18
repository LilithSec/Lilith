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
	print $fh qq{[allani]\ndsn = "dbi:Pg:dbname=allani"\n} if $c{allani};
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
		->element_exists( 'select#db-table option[value="cape"]', 'default-table selector offers the alert tables' )
		->element_exists_not( 'select#db-table option[value="syslog"]', 'no log sources in the default-table selector without Allani' )
		->element_exists( 'div.time-range select[data-role="preset"]', 'has the time-range control' )
		->element_exists( 'script[src="/js/time-range.js"]',            'loads the shared time-range script' )
		->element_exists_not( '#card-total', 'the fixed stat strip is gone (now stat widgets)' )
		->element_exists( 'select#db-bucket option[value="week"]', 'has the board time-bucket selector' )
		->element_exists( '#wm-bucket option[value="month"]',      'modal has a per-widget bucket override' )
		->element_exists( 'input#db-gpcd[type="checkbox"]',     'has the Show GPCD checkbox' )
		->element_exists_not( 'input#db-gpcd[checked]', 'Show GPCD is unchecked by default' )
		->element_exists( 'div.grid-stack',                                   'has the (widget) gridstack container' )
		->element_exists( '#db-add-widget',                                   'has the Add widget button' )
		->element_exists( '#widget-modal',                                    'has the widget config modal' )
		->element_exists( '#wm-type',                                         'modal has a widget type selector' )
		->element_exists( '#wm-table option[value="cape"]',                   'modal has a per-widget table selector' )
		->element_exists( '#wm-table option[value=""]',                       'and a Follow-default-table option' )
		->element_exists_not( '#wm-table optgroup[label="Logs (Allani)"]', 'no log sources in the picker without Allani' )
		->element_exists( '#wm-type option[value="stat"]',                    'modal offers a stat (text) widget type' )
		->element_exists( '#wm-metric option[value="distinct"]',              'stat widget has a metric picker' )
		->element_exists( '#wm-style option[value="pie"]',                    'modal offers a pie style' )
		->element_exists( 'input#wm-limit[type="number"][min="1"][max="50"]', 'modal has a 1-50 count input' )
		->element_exists( '[data-preset="suricata"]',                         'reset menu offers the Suricata preset' )
		->element_exists( '[data-preset="cape"]',                             'reset menu offers the CAPE preset' )
		->element_exists_not( '[data-preset="syslog"]', 'no log presets in the reset menu without Allani' )
		->element_exists( 'select#db-board',                                  'has the dashboard selector' )
		->element_exists( '#db-edit',                                         'has the Edit toggle' )
		->element_exists( '#db-new',                                          'has the New dashboard action' )
		->element_exists( '#db-rename',                                       'has the Rename action' )
		->element_exists( '#db-set-default',                                  'has the Set-as-default action' )
		->element_exists( '#db-delete',                                       'has the Delete action' )
		->element_exists( '#board-modal',                                     'has the board-name modal' )
		->element_exists( 'script[src="/vendor/gridstack/gridstack-all.js"]', 'pulls in Gridstack' )
		->element_exists( 'script[src="/vendor/Chart.js"]',                   'pulls in Chart.js' );

	# With Allani configured, a widget can target a log source too.
	my $ta = app_for( dsn => 'dbi:Pg:dbname=test', allani => 1 );
	$ta->get_ok('/dashboard')->status_is( 200, 'dashboard renders with Allani configured' )
		->element_exists( '#wm-table optgroup[label="Logs (Allani)"] option[value="syslog"]',
		'widget table picker offers Allani log sources when configured' )
		->element_exists( '[data-preset="syslog"]',     'reset menu offers the Syslog preset with Allani' )
		->element_exists( '[data-preset="http"]',       'reset menu offers the combined HTTP preset with Allani' )
		->element_exists( '[data-preset="http_access"]', 'reset menu offers the HTTP Access preset with Allani' )
		->element_exists( '[data-preset="http_error"]',  'reset menu offers the HTTP Error preset with Allani' )
		->element_exists( 'select#db-table optgroup[label="Logs (Allani)"] option[value="http_error"]',
		'default-table selector offers log sources when Allani is configured' );

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

	# A column not in the accepted set is rejected before any SQL, so no DB is needed.
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

	# The stat (text) widget endpoint: one number + a label per metric.
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=total')
		->status_is( 200, 'stat total ok' )
		->json_is( '/value', 3,              'stat total value' )
		->json_is( '/label', 'Total alerts', 'stat total label' );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=distinct&column=src_ip')
		->status_is( 200, 'stat distinct ok' )
		->json_is( '/label', 'Unique src_ip', 'stat distinct label' )
		->json_is( '/value', 2,               'stat distinct src_ip value' );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=distinct&column=signature')
		->json_is( '/value', 2, 'stat distinct signature value' );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=escalated')
		->status_is( 200, 'stat escalated ok' )
		->json_is( '/value', 0,           'stat escalated value' )
		->json_is( '/label', 'Escalated', 'stat escalated label' );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=busiest&column=instance')
		->json_like( '/value', qr/^i\s+\(\d+\)$/, 'stat busiest instance value (with count)' );

	# An explicit absolute range bounds the query (preferred over go_back_minutes):
	# a future window has nothing, a wide one has everything.
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=total&start=2999-01-01+00:00')
		->status_is( 200, 'future-range stat ok' )
		->json_is( '/value', 0, 'a future start excludes every row' );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=total&start=2000-01-01+00:00&end=2999-01-01+00:00')
		->status_is( 200, 'wide-range stat ok' )
		->json_is( '/value', 3, 'a wide start/end range includes all rows' );

	# The Show GPCD toggle: a GPCD row is hidden by default, included at show_gpcd=1.
	$dbh->do( "insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,classification)"
			. " values ('i','h', now(), 'e', '3.3.3.3', 'Generic Protocol Command Decode')" );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=total')
		->json_is( '/value', 3, 'GPCD hidden by default' );
	$t->get_ok('/api/dashboard/stat?table=suricata&metric=total&show_gpcd=1')
		->json_is( '/value', 4, 'GPCD included when show_gpcd=1' );

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

	# Per-widget table: a valid table on a widget round-trips (so one board can
	# span tables); an invalid one is dropped, leaving the widget to fall back to
	# the board table.
	my $mt = [
		{ id => 'a', type => 'top',        config => { column => 'target',  table => 'cape' },  x => 0, y => 0, w => 4, h => 4 },
		{ id => 'b', type => 'timeseries', config => { group_by => 'signature', table => 'sagan', bucket => 'week' }, x => 4, y => 0, w => 4, h => 4 },
		{ id => 'c', type => 'top',        config => { column => 'src_ip',  table => 'bogus' }, x => 8, y => 0, w => 4, h => 4 },
		{ id => 'd', type => 'top',        config => { column => 'program', table => 'syslog' }, x => 0, y => 4, w => 4, h => 4 },
		{ id => 'e', type => 'stat', config => { metric => 'distinct', column => 'src_ip', label => 'My hosts', abbrev => 1 }, x => 4, y => 4, w => 2, h => 2 },
		{ id => 'f', type => 'stat', config => { metric => 'nonsense' }, x => 6, y => 4, w => 2, h => 2 },
		{ id => 'g', type => 'stat', config => { metric => 'total', abbrev => 'yes' }, x => 8, y => 4, w => 2, h => 2 },
		{ id => 'h', type => 'timeseries', config => { group_by => 'proto', bucket => 'fortnight' }, x => 0, y => 8, w => 4, h => 4 },
	];
	$t->post_ok( '/api/dashboard/layout' => json => { layout => $mt } )
		->status_is( 200, 'multi-table layout saved' )
		->json_is( '/count', 8, 'all eight widgets kept' );
	$t->get_ok('/api/dashboard/layout')
		->json_is( '/layout/0/config/table',   'cape',   'a valid per-widget table round-trips (cape)' )
		->json_is( '/layout/1/config/table',   'sagan',  'a valid per-widget table round-trips (sagan)' )
		->json_is( '/layout/1/config/bucket',  'week',   'a valid per-widget bucket round-trips' )
		->json_hasnt( '/layout/7/config/bucket', 'an invalid per-widget bucket is dropped' )
		->json_is( '/layout/2/config/column',  'src_ip', 'the widget with a bad table is still kept' )
		->json_hasnt( '/layout/2/config/table', 'an invalid per-widget table is dropped' )
		->json_is( '/layout/3/config/table',   'syslog', 'an Allani log source round-trips as a widget table' )
		->json_is( '/layout/4/type',           'stat',      'a stat widget round-trips' )
		->json_is( '/layout/4/config/metric',  'distinct',  'stat metric round-trips' )
		->json_is( '/layout/4/config/label',   'My hosts',  'stat label round-trips' )
		->json_is( '/layout/4/config/abbrev',  1,           'stat abbrev flag round-trips as 1' )
		->json_hasnt( '/layout/5/config/metric', 'an invalid stat metric is dropped' )
		->json_is( '/layout/6/config/abbrev',  1,           'a truthy abbrev value normalizes to 1' );

	# ---- multiple dashboards + per-board settings ----
	# The list starts with just the seeded default board.
	$t->get_ok('/api/dashboard/boards')
		->status_is( 200, 'boards ok' )
		->json_is( '/default',             'default', 'default board is the default' )
		->json_is( '/boards/0/name',       'default', 'default board is listed' )
		->json_is( '/boards/0/is_default', 1,         'and flagged default' );

	# A board's view state (table/range/gpcd) rides along with the layout save and
	# reads back; an unknown settings key is dropped by the sanitizer.
	$t->post_ok(
		'/api/dashboard/layout' => json => {
			name     => 'default',
			layout   => [],
			settings => { table => 'cape', go_back_minutes => 360, show_gpcd => 1, bucket => 'day', bogus => 'x' }
		}
	)->status_is( 200, 'default board settings saved' );
	$t->get_ok('/api/dashboard/layout')
		->json_is( '/settings/table',           'cape', 'saved board table round-trips' )
		->json_is( '/settings/go_back_minutes', 360,    'saved board range round-trips' )
		->json_is( '/settings/show_gpcd',       1,      'saved board gpcd round-trips' )
		->json_is( '/settings/bucket',          'day',  'saved board bucket round-trips' )
		->json_hasnt( '/settings/bogus', 'unknown settings key was stripped' );

	# A bad board bucket is dropped rather than stored.
	$t->post_ok( '/api/dashboard/layout' => json => { name => 'default', layout => [], settings => { bucket => 'fortnight' } } )
		->status_is( 200, 'board with a bad bucket accepted' );
	$t->get_ok('/api/dashboard/layout')->json_hasnt( '/settings/bucket', 'an invalid board bucket is dropped' );

	# The board Default table may also be an Allani log source (a following widget
	# then reads that log); a bad value is dropped.
	$t->post_ok( '/api/dashboard/layout' => json => { name => 'default', layout => [], settings => { table => 'syslog' } } )
		->status_is( 200, 'log-source board table saved' );
	$t->get_ok('/api/dashboard/layout')->json_is( '/settings/table', 'syslog', 'a log-source board table round-trips' );
	$t->post_ok( '/api/dashboard/layout' => json => { name => 'default', layout => [], settings => { table => 'nope' } } )
		->status_is( 200, 'bad board table accepted but dropped' );
	$t->get_ok('/api/dashboard/layout')->json_hasnt( '/settings/table', 'an invalid board table is dropped' );

	# Create a second board; it appears, empty and non-default.
	$t->post_ok( '/api/dashboard/boards' => json => { name => 'ops' } )
		->status_is( 200, 'board created' )
		->json_is( '/name', 'ops', 'create echoes the name' );
	$t->get_ok('/api/dashboard/layout?name=ops')
		->json_is( '/name',       'ops', 'named board fetched' )
		->json_is( '/is_default', 0,     'new board is not default' )
		->json_is( '/layout',     [],    'new board starts empty' );

	# A duplicate name and an invalid name are refused.
	$t->post_ok( '/api/dashboard/boards' => json => { name => 'ops' } )->status_is( 400, 'duplicate name refused' );
	$t->post_ok( '/api/dashboard/boards' => json => { name => 'bad/name' } )->status_is( 400, 'invalid name refused' );

	# Move the default flag to the new board; the no-name layout endpoint follows it.
	$t->post_ok( '/api/dashboard/default' => json => { name => 'ops' } )->status_is( 200, 'set default ok' );
	$t->get_ok('/api/dashboard/boards')->json_is( '/default', 'ops', 'default moved to ops' );
	$t->get_ok('/api/dashboard/layout')->json_is( '/name',    'ops', 'no-name layout follows the default flag' );

	# Rename it.
	$t->post_ok( '/api/dashboard/rename' => json => { name => 'ops', to => 'soc' } )->status_is( 200, 'rename ok' );
	$t->get_ok('/api/dashboard/layout?name=soc')->json_is( '/name', 'soc', 'board renamed' );

	# The default board is protected from deletion; a non-default one deletes.
	$t->post_ok( '/api/dashboard/delete' => json => { name => 'soc' } )
		->status_is( 400, 'deleting the default board is refused' );
	$t->post_ok( '/api/dashboard/delete' => json => { name => 'default' } )
		->status_is( 200, 'non-default board deleted' );
	# The last remaining board is also protected.
	$t->post_ok( '/api/dashboard/delete' => json => { name => 'soc' } )
		->status_is( 400, 'deleting the last board is refused' );

	$dbh->disconnect;
	$pg->stop;
} ## end SKIP:

done_testing;
