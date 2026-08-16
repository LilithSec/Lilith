#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;
use JSON         qw(encode_json);
use MIME::Base64 qw(encode_base64);

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub _make_app {
	my ($extra_toml) = @_;
	$extra_toml //= '';

	my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh $extra_toml;
	close $fh;

	local $ENV{LILITH_CONFIG} = $config_file;
	return Test::Mojo->new('Lilith::Web');
} ## end sub _make_app

# ---------------------------------------------------------------------------
# 1.  Root redirect
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	$t->get_ok('/')
		->status_is( 302, 'GET / returns 302' )
		->header_is( Location => '/search', 'GET / redirects to /search' );
}

# ---------------------------------------------------------------------------
# 2.  Search form — GET /search
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# No params — still renders the form (a default search runs but there is no
	# real DB, so the error is stashed and the page renders 200)
	$t->get_ok('/search')
		->status_is( 200, 'GET /search renders search form' )
		->element_exists( 'input#auto-refresh[type="checkbox"]', 'auto-refresh checkbox is present' )
		->element_exists( 'input#auto-refresh-secs[type="number"][value="30"]',
			'auto-refresh interval input defaults to 30' )
		->element_exists( 'div.col-auto.ms-auto input#auto-refresh',
			'auto-refresh control sits in the far-right column' )
		->element_exists( 'input#auto-fc[type="checkbox"]',     'Auto-FC checkbox is present' )
		->element_exists( 'div.col-auto.ms-auto input#auto-fc', 'Auto-FC control sits in the far-right column' )
		->element_exists( 'span#ar-status',                     'auto-refresh status indicator is present' )
		->element_exists( 'input#nav-https-port[value="443"]',  'HTTPS port input defaults to 443' )
		->element_exists( 'button#nav-https-btn',               'HTTPS button present in Domain Info' )
		->element_exists( 'div#httpsinfo-modal',                'HTTPS info modal present' )
		->element_exists( 'input#nav-mail-ip',                  'SPF IP input present in Domain Info' )
		->element_exists( 'input#nav-mail-selector',            'DKIM selector input present in Domain Info' )
		->element_exists( 'button#nav-mail-btn',                'Mail button present in Domain Info' )
		->element_exists( 'div#mailinfo-modal',                 'Mail auth modal present' )
		->element_exists( 'tbody#mailinfo-mx',                  'MX section present' )
		->element_exists( 'tbody#mailinfo-spf',                 'SPF section present' )
		->element_exists( 'tbody#mailinfo-dmarc',               'DMARC section present' )
		->element_exists( 'div#mailinfo-dkim',                  'DKIM section present' );

	# search param triggers a DB query; no real DB so it stashes an error but
	# still renders 200
	$t->get_ok('/search?search=1&table=suricata')->status_is( 200, 'GET /search?search=1 renders 200 (error stashed)' );

	# Invalid table value is sanitized to "suricata"
	$t->get_ok('/search?search=1&table=badtable')
		->status_is( 200, 'invalid table is sanitized; page still renders 200' );

	# Invalid order_dir is sanitized to "DESC"
	$t->get_ok('/search?search=1&order_dir=INVALID')
		->status_is( 200, 'invalid order_dir is sanitized; page still renders 200' );

	# POST is not routed — only GET /search is defined
	$t->post_ok('/search')->status_is( 404, 'POST /search is not routed (404)' );

	# the classification selects allow multiple selections
	$t->get_ok('/search')
		->element_exists( 'select[name="class"][multiple]',     'class select is a multi-select' )
		->element_exists( 'select[name="class_not"][multiple]', 'class_not select is a multi-select' );

	# multiple class params render and are marked selected on the way back out
	$t->get_ok('/search?search=1&class=Misc+activity&class=Not+Suspicious+Traffic')
		->status_is( 200, 'multiple class params render 200' )
		->element_exists( 'option[value="Misc activity"][selected]', 'first class param is selected in the form' )
		->element_exists( 'option[value="Not Suspicious Traffic"][selected]',
			'second class param is selected in the form' )
		->element_exists_not( 'select[name="class_not"] option[selected]',
			'class params do not mark the exclude select' );

	# class_not params round trip via the exclude select
	$t->get_ok('/search?search=1&class_not=Misc+activity')
		->status_is( 200, 'class_not param renders 200' )
		->element_exists( 'select[name="class_not"] option[value="Misc activity"][selected]',
			'class_not param is selected in the exclude select' )
		->element_exists_not( 'select[name="class"] option[selected]',
			'class_not params do not mark the match select' );

	# a fresh form defaults to excluding Generic Protocol Command Decode ...
	$t->get_ok('/search')
		->element_exists( 'select[name="class_not"] option[value="Generic Protocol Command Decode"][selected]',
			'fresh form defaults to excluding GPCD' );

	# ... but a submitted search keeps the user's choice, even deselecting it
	$t->get_ok('/search?search=1')
		->element_exists_not( 'select[name="class_not"] option[value="Generic Protocol Command Decode"][selected]',
			'submitted search without class_not does not re-select GPCD' );
}

# ---------------------------------------------------------------------------
# 2b.  Search controller merges class/class_not for Lilith::search
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	my %captured;
	no warnings qw(redefine once);
	local *Lilith::search = sub {
		my ( $self, %opts ) = @_;
		%captured = %opts;
		return [];
	};
	use warnings qw(redefine once);

	$t->get_ok('/search?search=1&class=Misc+activity&class_not=Misc+Attack&class_not=Spam')
		->status_is( 200, 'mixed class/class_not search renders 200' );
	is_deeply(
		$captured{class},
		[ 'Misc activity', '!Misc Attack', '!Spam' ],
		'class_not values reach search() negated after the class values'
	);
}

# ---------------------------------------------------------------------------
# 2c.  Text filters take several values — one query parameter per value, so a
#      chip can drop one value and leave the rest of the filter alone
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# every text filter is a token field rather than a plain text input, which
	# is what makes the browser submit one parameter per value
	$t->get_ok('/search')
		->element_exists( 'select[name="instance"][multiple].token-filter-field',  'instance is a token field' )
		->element_exists( 'select[name="signature"][multiple].token-filter-field', 'signature is a token field' )
		->element_exists_not( 'input[name="instance"]', 'instance is no longer a plain text input' );

	# both values round trip into the field
	$t->get_ok('/search?search=1&instance=nibbles0%25&instance=inari-pie')
		->status_is( 200, 'a filter with two values renders 200' )
		->element_exists( 'select[name="instance"] option[value="nibbles0%"][selected]',
			'the first value is selected in the form' )
		->element_exists( 'select[name="instance"] option[value="inari-pie"][selected]',
			'the second value is selected in the form' );

	# ... and gets a chip each, dropping only its own value
	my @chips = @{ $t->tx->res->dom->find('a.badge')->map( sub { $_->all_text } )->to_array };
	is( scalar( grep { /^Instance:/ } @chips ), 2, 'a two valued filter gets a chip per value' );

	my @hrefs = @{ $t->tx->res->dom->find('a.badge')->map( attr => 'href' )->to_array };
	ok( ( grep { /instance=inari-pie/ && !/instance=nibbles0/ } @hrefs ), 'dropping the first value keeps the second' );
	ok( ( grep { /instance=nibbles0%25/ && !/instance=inari-pie/ } @hrefs ),
		'dropping the second value keeps the first' );

	# what reaches Lilith::search
	my %captured;
	no warnings qw(redefine once);
	local *Lilith::search = sub {
		my ( $self, %opts ) = @_;
		%captured = %opts;
		return [];
	};
	use warnings qw(redefine once);

	$t->get_ok('/search?search=1&instance=nibbles0%25&instance=inari-pie&src_port=22&src_port=80,443')
		->status_is( 200, 'multi valued filters render 200' );
	is_deeply( $captured{instance}, [ 'nibbles0%', 'inari-pie' ], 'both instance values reach search()' );
	is_deeply(
		$captured{src_port},
		[ '22', '80', '443' ],
		'a numeric filter takes both several values and a comma separated one'
	);

	$t->get_ok('/search?search=1&instance=&instance=inari-pie')->status_is( 200, 'a blank value renders 200' );
	is_deeply( $captured{instance}, ['inari-pie'], 'blank values are dropped rather than passed on' );

	$t->get_ok('/search?search=1&instance=')->status_is( 200, 'an empty filter renders 200' );
	is( $captured{instance}, undef, 'a filter with nothing in it is not passed to search() at all' );
}

# ---------------------------------------------------------------------------
# 2c-i.  Filter value suggestions — GET /api/search/values
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# the fields whose dropdown offers the values that occur name their column;
	# the src-or-dst pairs have no single column to offer and name none
	$t->get_ok('/search')
		->element_exists( 'select[name="instance"][data-column="instance"]',   'instance offers values for its column' )
		->element_exists( 'select[name="signature"][data-column="signature"]', 'signature offers values' )
		->element_exists_not( 'select[name="ip"][data-column]',   'the src-or-dst IP filter offers none' )
		->element_exists_not( 'select[name="port"][data-column]', 'the src-or-dst port filter offers none' );

	# loaded up front: Lilith::stats requires it on first use, which would
	# compile the real top() straight over the mock below
	require Lilith::Stats;

	my %captured;
	no warnings qw(redefine once);
	local *Lilith::Stats::top = sub {
		my ( $self, %opts ) = @_;
		%captured = %opts;
		return [ { value => 'nibbles04', count => 812 }, { value => 'inari-pie', count => 3 } ];
	};
	use warnings qw(redefine once);

	$t->get_ok('/api/search/values?table=sagan&column=instance&go_back_minutes=60')
		->status_is( 200, 'the values endpoint renders 200' )
		->json_is( '/table',          'sagan',     'it names the table asked for' )
		->json_is( '/column',         'instance',  'and the column' )
		->json_is( '/values/0/value', 'nibbles04', 'the most common value comes first' )
		->json_is( '/values/0/count', 812,         'with its count' )
		->json_is( '/values/1/value', 'inari-pie', 'and the rest follow' );
	is( $captured{table},           'sagan',    'the table reaches Lilith::Stats' );
	is( $captured{column},          'instance', 'the column reaches Lilith::Stats' );
	is( $captured{go_back_minutes}, 60,         'the window reaches Lilith::Stats' );
	is( $captured{limit},           200,        'a fixed number of values is asked for' );

	# an explicit range is passed through, the same way the search itself takes
	# one, so the values describe the rows the search covers
	$t->get_ok('/api/search/values?column=instance&start=2026-07-18T00:00&end=2026-07-18T12:00')
		->status_is( 200, 'a ranged request renders 200' );
	is( $captured{start}, '2026-07-18T00:00', 'start reaches Lilith::Stats' );
	is( $captured{end},   '2026-07-18T12:00', 'end reaches Lilith::Stats' );

	# an unknown table is sanitized rather than passed on
	$t->get_ok('/api/search/values?table=badtable&column=instance')->status_is( 200, 'a bad table renders 200' );
	is( $captured{table}, 'suricata', 'an unknown table falls back to suricata' );

	# a column the table cannot be grouped by dies in Lilith::Stats, which is a
	# 400 naming it rather than a 500
	{
		no warnings qw(redefine once);
		local *Lilith::Stats::top = sub { die qq{"raw" is not a column that can be grouped by\n} };
		use warnings qw(redefine once);

		$t->get_ok('/api/search/values?column=raw')
			->status_is( 400, 'a column that cannot be grouped by is a 400' )
			->json_like( '/error', qr/not a column/, 'and says why' );
	}
}

# ---------------------------------------------------------------------------
# 2d.  Explicit time range — the When toggle and start/end passthrough
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# the search form uses the reusable time-range control: a preset dropdown
	# (relative) plus a Custom range of native date + 24h hour/minute fields
	$t->get_ok('/search')
		->status_is( 200, 'search form renders' )
		->element_exists( 'div.time-range',                                    'has the reusable time-range control' )
		->element_exists( 'select[data-role="preset"] option[value="custom"]', 'preset dropdown offers a Custom range' )
		->element_exists( 'select[data-role="preset"] option[value="43200"]',  'and relative presets (30 days)' )
		->element_exists( 'input[type="date"][data-role="start-date"]',        'custom range has a From date' )
		->element_exists( 'input[type="number"][data-role="start-hour"][max="23"]', 'and a 24-hour From hour' )
		->element_exists( 'input[type="hidden"][name="go_back_minutes"][data-role="minutes"]', 'emits go_back_minutes' )
		->element_exists( 'input[type="hidden"][name="start"][data-role="start"]',             'emits start' )
		->element_exists( 'script[src="/js/time-range.js"]', 'loads the shared time-range script' );

	my %captured;
	no warnings qw(redefine once);
	local *Lilith::search = sub { my ( $self, %opts ) = @_; %captured = %opts; return []; };
	use warnings qw(redefine once);

	$t->get_ok('/search?search=1&start=2026-07-18T00:00&end=2026-07-18T12:00')
		->status_is( 200, 'range search renders 200' );
	is( $captured{start}, '2026-07-18T00:00', 'start reaches search()' );
	is( $captured{end},   '2026-07-18T12:00', 'end reaches search()' );

	# with no range params, start/end are undef (relative window is used)
	$t->get_ok('/search?search=1');
	ok( !defined $captured{start}, 'no start param -> undef' );
	ok( !defined $captured{end},   'no end param -> undef' );
}

# ---------------------------------------------------------------------------
# 2c.  Auto-refresh partial render — GET /search?...&partial=1
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [ { id => 42, timestamp => 't', src_ip => '8.8.8.8', classification => 'Misc Attack' } ];
	};
	use warnings qw(redefine once);

	my $full = $t->get_ok('/search?search=1&table=suricata')->tx->res->body;
	my $part
		= $t->get_ok('/search?search=1&table=suricata&partial=1')
		->status_is( 200, 'partial render returns 200' )
		->tx->res->body;

	# the fragment has the results container and the row ...
	like( $part, qr/id="search-results"/, 'partial contains the results container' );
	like( $part, qr{/event/suricata/42},  'partial contains the result row' );

	# ... but none of the page chrome (layout, navbar, filter form)
	unlike( $part, qr/<html/,             'partial has no layout/html wrapper' );
	unlike( $part, qr/id="filter-panel"/, 'partial has no filter panel' );
	unlike( $part, qr/navbar/,            'partial has no navbar' );

	# and it is dramatically smaller than the full page
	ok( length($part) < length($full) / 2, 'partial is much smaller than the full page' );

	# pagination links must not carry partial=1 (they do full navigation)
	my $paged = $t->get_ok('/search?search=1&table=suricata&limit=1&partial=1')->tx->res->body;
	unlike( $paged, qr/offset=\d+[^"]*partial=1/, 'pagination links drop the partial param' );

	# a bare /search (no params) runs the default search and shows results
	my %opts;
	{
		no warnings qw(redefine once);
		local *Lilith::search = sub {
			my ( $s, %o ) = @_;
			%opts = %o;
			return [ { id => 7, timestamp => 't', src_ip => '8.8.8.8', classification => 'Misc Attack' } ];
		};
		my $bare = $t->get_ok('/search')->status_is( 200, 'bare /search renders 200' )->tx->res->body;
		like( $bare, qr/id="search-results"/, 'bare /search shows the results container' );
		like( $bare, qr{/event/suricata/7},   'bare /search shows default-search results' );
	}
	is( $opts{table},           'suricata', 'default search uses the suricata table' );
	is( $opts{go_back_minutes}, 1440,       'default search uses the 1440-minute window' );
	is( $opts{limit},           100,        'default search uses the default limit' );
}

# ---------------------------------------------------------------------------
# 3.  Event view — GET /event/:table/:id
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# All valid table values render without a 500 (DB error is stashed)
	$t->get_ok('/event/suricata/1')->status_is( 200, 'GET /event/suricata/1 renders 200' );
	$t->get_ok('/event/sagan/1')->status_is( 200, 'GET /event/sagan/1 renders 200' );
	$t->get_ok('/event/cape/1')->status_is( 200, 'GET /event/cape/1 renders 200' );

	# Invalid table is sanitized to "suricata" and the page still renders
	$t->get_ok('/event/badtable/1')->status_is( 200, 'invalid table in /event is sanitized; page still renders 200' );
}

# ---------------------------------------------------------------------------
# 3-0.  Suricata protocol cards — the top-level EVE drives the card selection
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# a normal Suricata row: app_proto column + http sub-object at the top of raw
	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [
			{
				id        => 1,
				app_proto => 'http',
				raw       => encode_json( { http => { hostname => 'plain.suricata.example', http_method => 'GET' } } ),
			}
		];
	};
	use warnings qw(redefine once);

	$t->get_ok('/event/suricata/1')
		->status_is( 200, 'suricata event renders 200' )
		->content_like( qr/HTTP Details/,             'suricata http card still renders after the refactor' )
		->content_like( qr/plain\.suricata\.example/, 'and shows the http hostname' );
}

# ---------------------------------------------------------------------------
# 3-1.  Baphomet protocol cards — a verdict that judged a Suricata line carries
#       the original EVE under raw.raw, and the cards render off of it
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# Case A: nested raw is already a hash; app_proto=http picks the HTTP card,
	# and the payload rides along under the embedded EVE.
	{
		no warnings qw(redefine once);
		local *Lilith::search = sub {
			return [
				{
					id         => 1,
					event_type => 'alert',
					kur        => 'baphomet-ids',
					raw        => encode_json(
						{
							event_type => 'alert',
							kur        => 'baphomet-ids',
							raw        => {
								app_proto => 'http',
								http      =>
									{ hostname => 'login.evil.example', http_method => 'POST', url => '/steal' },
								payload => 'YmFzZTY0cGF5bG9hZA==',
							},
						}
					),
				}
			];
		}; ## end *Lilith::search = sub
		use warnings qw(redefine once);

		$t->get_ok('/event/baphomet/1')
			->status_is( 200, 'baphomet event renders 200' )
			->content_like( qr/HTTP Details/,         'embedded suricata http card renders for baphomet' )
			->content_like( qr/login\.evil\.example/, 'and shows the embedded http hostname' )
			->element_exists( '#download-payload-btn', 'the embedded payload download button appears' )
			->content_unlike( qr/TLS Details/, 'only the card matching the embedded app_proto renders' );
	}

	# Case B: nested raw arrives as a JSON *string*; the controller promotes it
	# to a hash so a declarative card (TLS) still renders.
	{
		no warnings qw(redefine once);
		local *Lilith::search = sub {
			return [
				{
					id         => 2,
					event_type => 'alert',
					raw        => encode_json(
						{
							event_type => 'alert',
							raw        => encode_json(
								{ app_proto => 'tls', tls => { sni => 'c2.evil.example', version => 'TLS 1.3' } }
							),
						}
					),
				}
			];
		}; ## end *Lilith::search = sub
		use warnings qw(redefine once);

		$t->get_ok('/event/baphomet/2')
			->status_is( 200, 'baphomet event with a string-nested raw renders 200' )
			->content_like( qr/TLS Details/,       'a string-nested embedded EVE is promoted and its card renders' )
			->content_like( qr/c2\.evil\.example/, 'and shows the embedded tls sni' );
	}

	# Case C: nested raw is a plain, non-JSON string; the defensive ref checks
	# mean no protocol cards render, but the page is still fine.
	{
		no warnings qw(redefine once);
		local *Lilith::search = sub {
			return [
				{
					id         => 3,
					event_type => 'banish',
					raw        => encode_json( { event_type => 'banish', raw => 'not json, just a log line' } ),
				}
			];
		};
		use warnings qw(redefine once);

		$t->get_ok('/event/baphomet/3')
			->status_is( 200, 'baphomet event with a non-JSON raw string renders 200' )
			->content_unlike( qr/HTTP Details|TLS Details/,
				'no protocol cards render when raw is not a decodable EVE' );
	}
}

# ---------------------------------------------------------------------------
# 3a.  Virani PCAP download — GET /event/:t/:id/pcap
# ---------------------------------------------------------------------------

# With no [virani.*] configured the feature is off: no button, route is 404.
{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [ { id => 5, instance => 'inari-pie', src_ip => '1.1.1.1', dest_ip => '2.2.2.2', raw => '{}' } ];
	};
	use warnings qw(redefine once);

	$t->get_ok('/event/suricata/5')
		->status_is(200)
		->element_exists_not( 'div#pcap-controls', 'no PCAP controls when no virani configured' );
	$t->get_ok('/event/suricata/5/pcap?remote=inari-pie')
		->status_is( 404, 'pcap route is 404 when virani is not configured' );
}

# With [virani.*] configured: button appears, and the route streams the PCAP.
{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh qq{[virani.inari-pie]\nurl = "https://v.example/"\napikey = "k"\nset = "default"\n};
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	require Virani::Client;
	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [
			{
				id         => 9,
				instance   => 'inari-pie',
				src_ip     => '192.168.0.5',
				dest_ip    => '20.64.105.235',
				src_port   => '40000',
				dest_port  => '443',
				flow_start => '2026-07-04T12:00:00',
				timestamp  => '2026-07-04T12:00:05',
				raw        => '{}',
			}
		];
	}; ## end *Lilith::search = sub
	 # The fetch runs in a subprocess, so it (and any capture) happens in a child;
	 # the mock just writes the pcap bytes the parent will stream back.
	local *Virani::Client::fetch = sub {
		my ( $self, %o ) = @_;
		open( my $w, '>:raw', $o{file} );
		print $w "PCAPBYTES";
		close($w);
		return '{}';
	};
	use warnings qw(redefine once);

	# PCAP controls present in the event view (remote hidden input, set select,
	# download button, and the local-command menu item)
	$t->get_ok('/event/suricata/9')
		->status_is(200)
		->element_exists( 'div#pcap-controls',                     'PCAP controls present when configured' )
		->element_exists( 'button#pcap-dl',                        'download button present' )
		->element_exists( 'select#pcap-set',                       'set selector present' )
		->element_exists( 'a#pcap-local',                          'local-command menu item present' )
		->element_exists( '#pcap-local-cmd button#pcap-cmd-close', 'local-command area has a close button' );

	# unknown remote is rejected
	$t->get_ok('/event/suricata/9/pcap?remote=nope')->status_is( 400, 'unknown virani remote is 400' );

	# non-suricata table is rejected
	$t->get_ok('/event/cape/9/pcap?remote=inari-pie')->status_is( 400, 'pcap on a non-suricata table is 400' );

	# happy path streams the pcap (fetched in a subprocess, streamed by the parent)
	$t->get_ok('/event/suricata/9/pcap?remote=inari-pie')
		->status_is( 200, 'pcap download renders 200' )
		->header_is( 'Content-Type'        => 'application/vnd.tcpdump.pcap',        'served as a pcap' )
		->header_is( 'Content-Disposition' => 'attachment; filename="event-9.pcap"', 'pcap download filename' )
		->content_is( 'PCAPBYTES', 'the fetched pcap bytes are streamed back' );

	# an explicit set is validated
	$t->get_ok('/event/suricata/9/pcap?remote=inari-pie&set=bad%20set')
		->status_is( 400, 'a malformed set is rejected' );

	# the sets endpoint returns the remote's available sets
	no warnings qw(redefine once);
	local *Virani::Client::get_sets = sub {
		return '{"sets":{"http":{},"dns":{}},"default_set":"http"}';
	};
	use warnings qw(redefine once);

	$t->get_ok('/api/virani/sets/inari-pie')
		->status_is( 200, 'sets endpoint renders 200' )
		->json_is( '/default_set', 'http',            'default_set reported' )
		->json_is( '/sets',        [ 'dns', 'http' ], 'sets listed (sorted)' );

	$t->get_ok('/api/virani/sets/nope')->status_is( 400, 'sets endpoint rejects an unknown remote' );
}

# ---------------------------------------------------------------------------
# 3a-ii.  Standalone Virani PCAP search — modal gating + GET /api/virani/pcap
# ---------------------------------------------------------------------------

# Search DOWNLOAD disabled (default): navbar modal offers only the command; the
# general pcap route is a 404.
{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh qq{[virani.r1]\nurl = "https://v.example/"\n};
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	$t->get_ok('/search')
		->status_is(200)
		->element_exists( 'button#nav-virani-toggle',                        'Virani navbar dropdown present' )
		->element_exists( 'a.dropdown-item[data-bs-target="#virani-modal"]', 'PCAP Search dropdown item present' )
		->element_exists( 'div#virani-modal',                                'Virani search modal present' )
		->element_exists( 'button#virani-show-cmd',                          'show-command button present' )
		->element_exists_not( 'button#virani-download', 'download button hidden when search disabled' )
		->element_exists_not(
			'a.dropdown-item[data-bs-target="#virani-cache-modal"]',
			'Cached Searches item hidden when search disabled'
		)->element_exists_not( 'div#virani-cache-modal', 'cached modal absent when search disabled' );

	$t->get_ok('/api/virani/pcap?remote=r1&filter=host+1.2.3.4&start=1000&end=2000')
		->status_is( 404, 'general pcap route is 404 when search is disabled' );
	$t->get_ok('/api/virani/cached/r1')->status_is( 404, 'cached list is 404 when search is disabled' );
}

# Search enabled: download button shown and the route streams.
{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh "virani_search_enable = true\n";
	print $fh qq{[virani.r1]\nurl = "https://v.example/"\n};
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	$t->get_ok('/search')
		->status_is(200)
		->element_exists( 'button#virani-download', 'download button shown when search enabled' )
		->element_exists( 'a.dropdown-item[data-bs-target="#virani-cache-modal"]',
			'Cached Searches item shown when search enabled' )
		->element_exists( 'div#virani-cache-modal',  'cached modal present when search enabled' )
		->element_exists( 'tbody#virani-cache-rows', 'cached results table present' );

	require Virani::Client;
	no warnings qw(redefine once);
	local *Virani::Client::fetch = sub {
		my ( $self, %o ) = @_;
		open( my $w, '>:raw', $o{file} );
		print $w 'SEARCHPCAP';
		close($w);
		return '{}';
	};
	my $md5 = 'a' x 32;
	# list_cached without filter/final_size (older Virani); those come from meta.
	local *Virani::Client::list_cached = sub {
		return encode_json(
			[
				{
					id       => "setA-tcpdump-1000-2000-$md5",
					set      => 'setA',
					type     => 'tcpdump',
					start_s  => 1000,
					end_s    => 2000,
					has_pcap => 1
				},
				{
					id       => "setA-tcpdump-3000-4000-$md5",
					set      => 'setA',
					type     => 'tcpdump',
					start_s  => 3000,
					end_s    => 4000,
					has_pcap => 1
				},
			]
		);
	}; ## end *Virani::Client::list_cached = sub
	local *Virani::Client::fetch_cached = sub {
		my ( $self, %o ) = @_;
		if ( $o{meta_only} ) {
			my ($end) = $o{id} =~ /-(\d+)-[a-f0-9]{32}\z/;
			return encode_json(
				{
					pcap_count    => 10,
					success_count => 7,
					filter        => ( $end == 4000 ? 'port 443' : 'host 1.1.1.1' ),
					final_size    => ( $end == 4000 ? 5678       : 1234 ),
				}
			);
		} ## end if ( $o{meta_only} )
		open( my $w, '>:raw', $o{file} );
		print $w 'CACHEDPCAP';
		close($w);
		return '{}';
	}; ## end *Virani::Client::fetch_cached = sub
	use warnings qw(redefine once);

	# cached list is newest-first and enriched from metadata (counts, filter, size)
	my $cached = $t->get_ok('/api/virani/cached/r1')->status_is( 200, 'cached list renders 200' )->tx->res->json;
	is( scalar( @{ $cached->{cached} } ), 2,          'two cached searches listed' );
	is( $cached->{cached}[0]{start_s},    3000,       'cached list is newest-first' );
	is( $cached->{cached}[0]{found},      10,         'found count enriched from metadata' );
	is( $cached->{cached}[0]{success},    7,          'success count enriched from metadata' );
	is( $cached->{cached}[0]{filter},     'port 443', 'filter enriched from metadata' );
	is( $cached->{cached}[0]{final_size}, 5678,       'final_size enriched from metadata' );

	# cached pcap streams
	$t->get_ok( '/api/virani/cached/r1/pcap/setA-tcpdump-3000-4000-' . $md5 )
		->status_is( 200, 'cached pcap streams 200' )
		->header_is( 'Content-Type' => 'application/vnd.tcpdump.pcap', 'served as a pcap' )
		->content_is( 'CACHEDPCAP', 'cached pcap bytes streamed' );

	# cached pcap validation
	$t->get_ok('/api/virani/cached/nope/pcap/x')->status_is( 400, 'cached pcap unknown remote rejected' );
	$t->get_ok('/api/virani/cached/r1/pcap/bad%20id')->status_is( 400, 'cached pcap invalid id rejected' );

	# cached metadata JSON download
	$t->get_ok( '/api/virani/cached/r1/meta/setA-tcpdump-3000-4000-' . $md5 )
		->status_is( 200, 'cached metadata renders 200' )
		->header_is( 'Content-Type' => 'application/json', 'served as json' )
		->header_is(
			'Content-Disposition' => 'attachment; filename="virani-cached-setA-tcpdump-3000-4000-' . $md5 . '.json"',
			'metadata download filename'
		)->json_is( '/filter', 'port 443', 'metadata JSON body is the entry metadata' );
	$t->get_ok('/api/virani/cached/r1/meta/bad%20id')->status_is( 400, 'cached meta invalid id rejected' );

	$t->get_ok('/api/virani/pcap?remote=r1&filter=host+1.2.3.4&start=1000&end=2000')
		->status_is( 200, 'general pcap search streams 200' )
		->header_is( 'Content-Type'        => 'application/vnd.tcpdump.pcap',                 'served as a pcap' )
		->header_is( 'Content-Disposition' => 'attachment; filename="virani-1000-2000.pcap"', 'download filename' )
		->content_is( 'SEARCHPCAP', 'streamed pcap bytes' );

	# validation
	$t->get_ok('/api/virani/pcap?remote=r1&filter=&start=1000&end=2000')->status_is( 400, 'empty filter rejected' );
	$t->get_ok('/api/virani/pcap?remote=r1&filter=x&start=2000&end=1000')->status_is( 400, 'start after end rejected' );
	$t->get_ok('/api/virani/pcap?remote=nope&filter=x&start=1&end=2')->status_is( 400, 'unknown remote rejected' );
	$t->get_ok('/api/virani/pcap?remote=r1&filter=x&start=notepoch&end=2')
		->status_is( 400, 'non-epoch times rejected' );
}

# ---------------------------------------------------------------------------
# 3b.  HTTP body password-protected zip download — GET /event/:t/:id/body/:w/zip
# ---------------------------------------------------------------------------

{
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	my $t = Test::Mojo->new('Lilith::Web');

	# bad "which" and non-numeric id are rejected before any DB access
	$t->get_ok('/event/suricata/1/body/bogus/zip')->status_is( 400, 'invalid body type is 400' );
	$t->get_ok('/event/suricata/abc/body/response/zip')->status_is( 400, 'non-numeric id is 400' );

	my $payload = "GIF89a\x00\x01 this is the fake malicious response body \xDE\xAD\xBE\xEF";

	no warnings qw(redefine once);
	local *Lilith::search = sub {
		my ( $self, %opts ) = @_;
		return [
			{
				id  => $opts{id}[0],
				raw => encode_json(
					{
						http => {
							http_response_body => encode_base64( $payload, '' ),
						},
					}
				),
			}
		];
	}; ## end *Lilith::search = sub
	use warnings qw(redefine once);

	# missing body type on the event → 404
	{
		no warnings qw(redefine once);
		local *Lilith::search = sub { return [ { id => 1, raw => encode_json( { http => {} } ) } ] };
		use warnings qw(redefine once);
		$t->get_ok('/event/suricata/1/body/request/zip')->status_is( 404, 'absent body is 404' );
	}

	my $tx
		= $t->get_ok('/event/suricata/7/body/response/zip')
		->status_is( 200, 'response body zip download renders 200' )
		->header_is( 'Content-Type' => 'application/zip', 'served as application/zip' )
		->header_is(
			'Content-Disposition' => 'attachment; filename="response-body-7.zip"',
			'zip has the expected download filename'
		)->tx;

	my $zipbytes = $tx->res->body;
	like( substr( $zipbytes, 0, 2 ), qr/^PK/, 'download body is a zip archive' );

	# the archive must actually decrypt with the "infected" password and yield
	# the original bytes back under the expected member name
SKIP: {
		my $unzip = `sh -c 'command -v unzip' 2>/dev/null`;
		chomp $unzip;
		skip 'unzip not available', 1 unless $unzip;

		my ( $zh, $zpath ) = tempfile( SUFFIX => '.zip', UNLINK => 1 );
		binmode $zh;
		print $zh $zipbytes;
		close $zh;

		my $got = `unzip -p -P infected \Q$zpath\E response-body-7 2>/dev/null`;
		is( $got, $payload, 'zip decrypts with password "infected" back to the original body' );
	} ## end SKIP:
}

# ---------------------------------------------------------------------------
# CAPE submission — off by default (no nav button, routes 404); on when
# cape_enable is set with a [cape_servers.*] configured.
# ---------------------------------------------------------------------------
{
	my $t = _make_app('');
	$t->get_ok('/search')
		->status_is( 200, 'search renders with cape off' )
		->element_exists_not( '#nav-cape-submit', 'no CAPE nav button when disabled' );
	$t->get_ok('/cape_submit')->status_is( 404, 'GET /cape_submit is 404 when disabled' );
	$t->post_ok('/api/cape_submit/submit')->status_is( 404, 'submit endpoint is 404 when disabled' );
}

# cape_enable = false must read as off, even with a server configured.
{
	my $t = _make_app("cape_enable = false\n\n[cape_servers.main]\nurl = \"http://127.0.0.1:9/\"\n");
	$t->get_ok('/search')
		->status_is( 200, 'search renders with cape_enable=false' )
		->element_exists_not( '#nav-cape-submit', 'cape_enable=false leaves the feature off' );
	$t->get_ok('/cape_submit')->status_is( 404, 'GET /cape_submit is 404 with cape_enable=false' );
}

{
	my $extra
		= "cape_enable = true\n"
		. "cape_slug = \"lil\"\n\n"
		. "[cape_servers.main]\n"
		. "url = \"http://127.0.0.1:9/\"\n"
		. "apikey_needed = false\n";
	my $t = _make_app($extra);

	$t->get_ok('/search')
		->status_is( 200, 'search renders with cape on' )
		->element_exists( 'a#nav-cape-submit', 'CAPE nav button present when enabled' );

	$t->get_ok('/cape_submit')
		->status_is( 200, 'GET /cape_submit renders when enabled' )
		->element_exists( 'form#cape-submit-form', 'submission form present' )
		->element_exists( 'input#cape-file',       'file input present' )
		->content_like( qr/value="lil"/, 'slug defaults to cape_slug' );

	# a submit with no file is rejected before any network call
	$t->post_ok('/api/cape_submit/submit')
		->status_is( 400, 'submit with no file is 400' )
		->json_is( '/status' => 'error', 'no-file submit reports an error' );
}

# ---------------------------------------------------------------------------
# Shodan enrichment filters — the form offers them and they reach search()
# ---------------------------------------------------------------------------

{
	my $t = _make_app('');

	my %captured;
	no warnings qw(redefine once);
	local *Lilith::search = sub {
		my ( $self, %opts ) = @_;
		%captured = %opts;
		return [];
	};
	use warnings qw(redefine once);

	$t->get_ok( '/search?search=1&shodan_src_tag=tor&shodan_src_tag=vpn'
			. '&shodan_dest_known=unchecked&shodan_src_cvss=%3E%3D9&cve=CVE-2021-44228'
			. '&shodan_dest_cve_match=matched&shodan_src_cve_match=unchecked'
			. '&src_locality=external&dest_locality=internal' )
		->status_is( 200, 'a search with enrichment filters renders 200' )
		->element_exists( 'select#shodan-src-tag-input',        'the src tag field is on the form' )
		->element_exists( 'select#shodan-dest-known-input',     'the dest known field is on the form' )
		->element_exists( 'select#cve-input',                   'the rule CVE field is on the form' )
		->element_exists( 'select#shodan-src-cve-match-input',  'the src CVE match field is on the form' )
		->element_exists( 'select#shodan-dest-cve-match-input', 'the dest CVE match field is on the form' )
		->element_exists( 'select#src-locality-input',          'the src locality field is on the form' )
		->element_exists( 'select#dest-locality-input',         'the dest locality field is on the form' );

	is_deeply( $captured{shodan_src_tag},        [ 'tor', 'vpn' ],   'the tag values reach search()' );
	is_deeply( $captured{shodan_dest_known},     ['unchecked'],      'the known value reaches search()' );
	is_deeply( $captured{shodan_src_cvss},       ['>=9'],            'the cvss comparison reaches search()' );
	is_deeply( $captured{cve},                   ['CVE-2021-44228'], 'the cve value reaches search()' );
	is_deeply( $captured{shodan_dest_cve_match}, ['matched'],        'the dest cve_match state reaches search()' );
	is_deeply( $captured{shodan_src_cve_match},  ['unchecked'],      'the src cve_match state reaches search()' );
	is_deeply( $captured{src_locality},          ['external'],       'the src locality state reaches search()' );
	is_deeply( $captured{dest_locality},         ['internal'],       'the dest locality state reaches search()' );
	is_deeply( $captured{local_networks},        [], 'the network list rides in from the config, empty when unset' );
	is( $captured{shodan_dest_tag}, undef, 'a filter left blank passes nothing' );

	# the cve_match pair is fixed-vocabulary the same way the known fields
	# are: the dimensions' four buckets, offered rather than guessed at
	$t->get_ok('/search')
		->element_exists( 'select#shodan-dest-cve-match-input[data-fixed="1"]', 'the dest CVE match field is fixed' )
		->element_exists( 'select#shodan-src-cve-match-input[data-fixed="1"]',  'the src CVE match field is fixed' );
	my $cve_match_options
		= $t->tx->res->dom->find('select#shodan-dest-cve-match-input option')
		->map( sub { $_->attr('value') } )
		->to_array;
	is_deeply(
		$cve_match_options,
		[ 'matched', 'unmatched', 'no-cve', 'unchecked' ],
		'and offers exactly the four buckets'
	);

	# the locality pair likewise: exactly its two states
	my $locality_options
		= $t->tx->res->dom->find('select#src-locality-input option')->map( sub { $_->attr('value') } )->to_array;
	is_deeply( $locality_options, [ 'internal', 'external' ], 'the locality field offers exactly its two states' );

	# the known fields are fixed-vocabulary: they offer exactly their three
	# states rather than leaving what the filter takes to be guessed at, and
	# carry the data-fixed mark that turns free typing off
	$t->get_ok('/search')
		->element_exists( 'select#shodan-src-known-input[data-fixed="1"]',       'the src known field is marked fixed' )
		->element_exists( 'select#shodan-src-known-input option[value="known"]', 'and offers known' )
		->element_exists( 'select#shodan-src-known-input option[value="unknown"]',   'and unknown' )
		->element_exists( 'select#shodan-src-known-input option[value="unchecked"]', 'and unchecked' )
		->element_exists( 'select#shodan-dest-known-input option[value="unchecked"]',
			'the dest twin offers the same set' )
		->element_exists_not( 'select#shodan-src-tag-input[data-fixed]', 'an open field is not marked fixed' );

	# a submitted state comes back selected on its fixed option, and a value
	# outside the set -- a negation written into the URL by hand -- still
	# round-trips instead of being dropped from the search the page describes
	$t->get_ok('/search?search=1&shodan_src_known=unchecked')
		->element_exists( 'select#shodan-src-known-input option[value="unchecked"][selected]',
			'a submitted state is selected on its fixed option' );
	my $known_options
		= $t->tx->res->dom->find('select#shodan-src-known-input option')->map( sub { $_->attr('value') } )->to_array;
	is_deeply(
		$known_options,
		[ 'known', 'unknown', 'unchecked' ],
		'a submitted state is not doubled into the option list'
	);
	$t->get_ok('/search?search=1&shodan_src_known=!known')
		->element_exists( 'select#shodan-src-known-input option[value="!known"][selected]',
			'a hand-written negation still round-trips' );
}

# ---------------------------------------------------------------------------
# CVE-match badge on the results table — the rule's ids against the cached
# vuln_ids of the destination
# ---------------------------------------------------------------------------

{
	my $t = _make_app("enable_shodan = true\n");

	no warnings qw(redefine once);
	# Two rows against the same destination. Row 7 names a CVE the destination
	# is cached as vulnerable to and hits a port on its open list; row 8's
	# rule CVE is one the *source* is cached as vulnerable to, and its source
	# port is on the source's open list -- both ends are compared, since which
	# end the vulnerable host lands on is up to the rule that fired.
	local *Lilith::search = sub {
		return [
			{
				id        => 7,
				src_ip    => '203.0.113.5',
				dest_ip   => '198.51.100.9',
				dest_port => 80,
				raw       => encode_json( { alert => { metadata => { cve => ['CVE_2021_44228'] } } } ),
			},
			{
				id        => 8,
				src_ip    => '203.0.113.5',
				src_port  => 51515,
				dest_ip   => '198.51.100.9',
				dest_port => 8443,
				raw       => encode_json( { alert => { metadata => { cve => ['CVE-2014-6271'] } } } ),
			},
		];
	}; ## end *Lilith::search = sub
	local *Lilith::shodan_cache_badges = sub {
		return {
			'198.51.100.9' => {
				ports    => [80],
				tags     => [],
				vulns    => 1,
				vuln_ids => ['CVE-2021-44228'],
				max_cvss => 10,
			},
			'203.0.113.5' => {
				ports    => [51515],
				tags     => [],
				vulns    => 1,
				vuln_ids => ['CVE-2014-6271'],
				max_cvss => undef,
			},
		};
	}; ## end *Lilith::shodan_cache_badges = sub
	use warnings qw(redefine once);

	$t->get_ok('/search?search=1')->status_is( 200, 'search with CVE matches renders 200' );

	my $match_badges = $t->tx->res->dom->find('span.badge.bg-danger')->grep( sub { $_->text eq 'CVE match' } );
	is( $match_badges->size, 2, 'each row carries the badge on the end that matched' );
	like(
		$match_badges->first->attr('title'),
		qr/destination is vulnerable.*CVE-2021-44228/,
		'row 7 matched on the destination'
	);
	like( $match_badges->last->attr('title'), qr/source is vulnerable.*CVE-2014-6271/, 'row 8 matched on the source' );

	# the port half: row 7's dest port and row 8's src port are on their ends'
	# open lists; row 8's dest port is not
	my $open_badges = $t->tx->res->dom->find('span.badge.bg-secondary')->grep( sub { $_->text eq 'open' } );
	is( $open_badges->size, 2, 'each end hitting a cached-open port carries the open badge' );
	like( $open_badges->first->attr('title'), qr/on the destination/, 'row 7 on the destination side' );
	like( $open_badges->last->attr('title'),  qr/on the source/,      'row 8 on the source side' );
}

# ---------------------------------------------------------------------------
# Event view Shodan strip + CVE-match banner — cache-only, rendered per end
# ---------------------------------------------------------------------------

{
	my $t = _make_app("enable_shodan = true\n");

	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [
			{
				id        => 7,
				src_ip    => '203.0.113.5',
				dest_ip   => '198.51.100.9',
				dest_port => 80,
				proto     => 'TCP',
				raw       => encode_json(
					{
						alert => { metadata => { cve  => ['CVE_2021_44228'] }, signature => 'log4j' },
						tls   => { ja3s     => { hash => 'abc123' } },
					}
				),
			}
		];
	}; ## end *Lilith::search = sub
	 # Only the destination has a fresh cache entry: a row three days old,
	 # tor-tagged, vulnerable to the rule's CVE, with an API-tier service
	 # block on the attacked port -- the crawl saw the same TLS server
	 # fingerprint the alert carries, and that very service holds the CVE.
	local *Lilith::shodan_cache_info = sub {
		return {
			'198.51.100.9' => {
				found       => 1,
				age_seconds => 259200,
				raw         => {
					ports     => [80],
					tags      => ['tor'],
					vulns     => ['CVE-2021-44228'],
					hostnames => ['iron.example'],
					data      => [
						{
							port      => 80,
							transport => 'tcp',
							product   => 'nginx',
							version   => '1.18.0',
							vulns     => ['CVE-2021-44228'],
							ssl       => { ja3s => 'abc123' },
						}
					],
				},
			},
		};
	}; ## end *Lilith::shodan_cache_info = sub
	 # the keyless tier sends no scores; the CVEDB cache stands in
	local *Lilith::cvedb_cache_annotations = sub {
		return { 'CVE-2021-44228' =>
				{ cvss => 10, epss => 0.97, kev => 1, ransomware => 1, summary => 'log4shell', found => 1 }, };
	};
	use warnings qw(redefine once);

	$t->get_ok('/event/suricata/7')
		->status_is( 200, 'event with a CVE match renders 200' )
		->content_like( qr/shodan dest/, 'the destination strip renders' )
		->content_unlike( qr/shodan src/, 'an end with no cache entry gets no strip' )
		->content_like( qr/cached 3d ago/,      'the strip carries the cache age' )
		->content_like( qr/iron\.example/,      'the strip carries the hostnames' )
		->content_like( qr/port 80 open/,       'the attacked port is confirmed open' )
		->content_like( qr/nginx 1\.18\.0/,     'the strip names what the crawl saw on that port' )
		->content_like( qr/ja3s matches crawl/, 'the alert and the crawl saw the same TLS server' )
		->content_like( qr/CVE match/,          'the banner is on the page' )
		->content_like( qr/CVE-2021-44228/,     'the banner names the matched id' )
		->content_like( qr/CVSS 10/,            'the banner carries the CVEDB score' )
		->content_like( qr/KEV/,                'and the KEV flag' )
		->content_like( qr/on the flow port/,   'and that the vulnerable service is the one on the flow port' );

	# the strip's CVE badge is red: the worst score came from the CVEDB
	# stand-in even though the keyless tier sent none
	my $strip_cve = $t->tx->res->dom->find('span.badge.bg-danger')->grep( sub { $_->text =~ /1 CVE/ } );
	is( $strip_cve->size, 1, 'the strip CVE badge is colored by the stood-in worst score' );
}

# the disagreeing side of the same strip: a port off the open list, and a
# crawled fingerprint that is not the one the alert saw
{
	my $t = _make_app("enable_shodan = true\n");

	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [
			{
				id        => 8,
				src_ip    => '203.0.113.5',
				dest_ip   => '198.51.100.9',
				dest_port => 443,
				proto     => 'TCP',
				raw       =>
					encode_json( { alert => { signature => 'tls thing' }, tls => { ja3s => { hash => 'abc123' } } } ),
			}
		];
	}; ## end *Lilith::search = sub
	local *Lilith::shodan_cache_info = sub {
		return {
			'198.51.100.9' => {
				found       => 1,
				age_seconds => 259200,
				raw         => {
					ports => [80],
					data  => [ { port => 443, transport => 'tcp', ssl => { ja3s => 'zzz999' } } ],
				},
			},
		};
	}; ## end *Lilith::shodan_cache_info = sub
	local *Lilith::cvedb_cache_annotations = sub { return {} };
	use warnings qw(redefine once);

	$t->get_ok('/event/suricata/8')
		->status_is( 200, 'event against a not-open port renders 200' )
		->content_like( qr/port 443 not seen open/,  'absence from the port list is said, softly' )
		->content_like( qr/ja3s differs from crawl/, 'a fingerprint disagreement is called out' )
		->content_unlike( qr/CVE match/, 'no banner when the rule names no CVE' );
}

done_testing();
