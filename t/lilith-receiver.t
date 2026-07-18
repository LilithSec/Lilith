#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;
use Mojo::IOLoop;
use JSON        qw(decode_json);
use Digest::SHA qw(sha256_base64);

use_ok('Lilith::Receiver') or BAIL_OUT('Lilith::Receiver failed to load');

# ---------------------------------------------------------------------------
# A fake DBI handle/statement. It records the prepared SQL and the values bound
# at execute() time (so the SQL-injection and auth tests can prove user data
# only ever travels as a placeholder bind) and returns a caller-supplied row.
# ---------------------------------------------------------------------------
{

	package FakeSTH;
	sub new { my ( $c, %a ) = @_; return bless {%a}, $c; }

	sub execute {
		my $self = shift;
		$self->{cap}{sql}   = $self->{sql};
		$self->{cap}{binds} = [@_];
		$self->{done}       = 0;
		return 1;
	}
	sub fetchrow_array { return (4242); }

	sub fetchrow_hashref {
		my $self = shift;
		return undef if $self->{done}++;
		return $self->{cap}{row};
	}
}
{

	package FakeDBH;
	sub new     { my ( $c,    $cap ) = @_; return bless { cap => $cap }, $c; }
	sub prepare { my ( $self, $sql ) = @_; return FakeSTH->new( sql => $sql, cap => $self->{cap} ); }
	sub do      { my $self = shift; push @{ $self->{cap}{do} }, [@_]; return 1; }
}

# A Lilith object for the pure-logic unit tests. Lilith->new does not connect.
my $lilith = Lilith->new( dsn => 'dbi:Pg:dbname=test' );

# Build a Lilith::Receiver Test::Mojo app. Auth now lives in the database, so
# the config only needs a dsn; the tests mock the DB-facing methods.
sub _app {
	my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh qq{dsn = "dbi:Pg:dbname=test"\n};
	print $fh qq{user = "lilith"\n};
	close $fh;

	local $ENV{LILITH_CONFIG} = $cf;
	return Test::Mojo->new('Lilith::Receiver');
}

# ---------------------------------------------------------------------------
# 1.  Instance-scope matching, including wildcards (pure logic)
# ---------------------------------------------------------------------------

# no restriction => any instance
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances => undef }, 'anything' ),
	'undef allowed_instances permits any instance' );
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances => [] }, 'anything' ),
	'empty allowed_instances permits any instance' );

# exact names still behave exactly as before wildcards existed
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances  => ['foo-pie'] }, 'foo-pie' ), 'exact name matches' );
ok( !$lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-pie'] }, 'foo-lae' ),
	'exact name does not match a different instance' );

# '*' wildcard
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-*'] }, 'foo-pie' ), 'foo-* matches foo-pie' );
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-*'] }, 'foo-' ),
	'foo-* matches foo- (star may match empty)' );
ok( !$lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-*'] }, 'bar-pie' ), 'foo-* rejects bar-pie' );
ok( !$lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-*'] }, 'xfoo-pie' ),
	'foo-* is anchored: rejects xfoo-pie' );

# '?' wildcard (single character)
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-?'] }, 'foo-1' ),
	'foo-? matches a single trailing char' );
ok( !$lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-?'] }, 'foo-12' ),
	'foo-? does not match two trailing chars' );

# multiple patterns are OR-ed
ok( $lilith->receiver_apikey_instance_ok( { allowed_instances => [ 'a-*', 'b-*' ] }, 'b-1' ),
	'any pattern in the list may match' );

# a restricted key with no instance to check is refused
ok( !$lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo-*'] }, undef ),
	'a restricted key rejects an undef instance' );

# regex metacharacters in a pattern are matched literally, not as regex
ok( !$lilith->receiver_apikey_instance_ok( { allowed_instances => ['foo.pie'] }, 'fooXpie' ),
	'"." in a pattern is a literal dot, not any-char' );

# ---------------------------------------------------------------------------
# 2.  receiver_apikey_auth builds a parameterized, IP-scoped lookup
# ---------------------------------------------------------------------------

{
	my %cap = ( row => { id => 7, allowed_instances => undef } );
	no warnings qw(redefine once);
	local *DBI::connect_cached = sub { return FakeDBH->new( \%cap ); };
	use warnings qw(redefine once);

	my $key = $lilith->receiver_apikey_auth( apikey => 'secret', ip => '10.1.2.3' );
	is( $key->{id}, 7, 'auth returns the matched key row' );

	like( $cap{sql}, qr/key_sha256 = \?/,        'auth looks the key up by its hash' );
	like( $cap{sql}, qr/<<= any\(allowed_ips\)/, 'IP containment is delegated to SQL' );
	is( $cap{binds}[0],               sha256_base64('secret'), 'the token hash is bound, never the token itself' );
	is( index( $cap{sql}, 'secret' ), -1,                      'the token never appears in the SQL text' );
	is( $cap{binds}[1],               '10.1.2.3',              'the client IP is bound for the containment check' );
	ok( ( $cap{do} && @{ $cap{do} } ), 'a successful lookup stamps last_used' );

	# a syntactically bogus IP is bound as NULL so a key with an IP restriction
	# fails closed instead of erroring on the ::inet cast
	$lilith->receiver_apikey_auth( apikey => 'secret', ip => 'not-an-ip' );
	ok( !defined $cap{binds}[1], 'a bogus client IP is bound as NULL (fail closed)' );

	# an empty token short-circuits before any query
	%cap = ();
	is( $lilith->receiver_apikey_auth( apikey => '', ip => '1.2.3.4' ), undef, 'empty apikey => undef' );
	ok( !exists $cap{sql}, 'an empty apikey never runs a query' );
}

# ---------------------------------------------------------------------------
# 3.  HTTP authentication
# ---------------------------------------------------------------------------

{
	my $t = _app();

	my $seen_ip;
	no warnings qw(redefine once);
	local *Lilith::receiver_apikey_auth = sub {
		my ( $self, %o ) = @_;
		$seen_ip = $o{ip};
		return ( defined $o{apikey} && $o{apikey} eq 'good' ) ? { id => 1, allowed_instances => undef } : undef;
	};
	local *Lilith::insert_alert = sub { return 1; };
	use warnings qw(redefine once);

	$t->post_ok( '/eve/suricata_alerts' => json => { instance => 'x' } )
		->status_is( 401, 'missing Authorization header => 401' )
		->json_is( '/status', 'error', 'unauthorized body is an error' );
	$t->post_ok( '/eve/suricata_alerts' => { Authorization => 'Basic good' } => json => { instance => 'x' } )
		->status_is( 401, 'non-Bearer scheme => 401' );
	$t->post_ok( '/eve/suricata_alerts' => { Authorization => 'Bearer bad' } => json => { instance => 'x' } )
		->status_is( 401, 'unknown key => 401' );
	$t->post_ok( '/eve/suricata_alerts' => { Authorization => 'Bearer good' } => json => { instance => 'x' } )
		->status_is( 201, 'a valid key is accepted' );

	is( $seen_ip, '127.0.0.1', 'the client IP is passed through to the key lookup' );
}

# ---------------------------------------------------------------------------
# 4.  Routing and body validation (auth mocked to an unrestricted key)
# ---------------------------------------------------------------------------

{
	my $t = _app();

	my %got;
	no warnings qw(redefine once);
	local *Lilith::receiver_apikey_auth = sub { return { id => 1, allowed_instances => undef }; };
	local *Lilith::insert_alert         = sub {
		my ( $self, %o ) = @_;
		%got = %o;
		return 99;
	};
	use warnings qw(redefine once);

	my $H = { Authorization => 'Bearer k' };

	# unknown table
	%got = ();
	$t->post_ok( '/eve/bogus_alerts' => $H => json => { instance => 'x' } )->status_is( 404, 'unknown table => 404' );
	ok( !%got, 'unknown table never reaches insert_alert' );

	# body is a JSON array, not an object
	$t->post_ok( '/eve/suricata_alerts' => $H => json => [ 1, 2, 3 ] )->status_is( 400, 'array body => 400' );

	# body is not JSON at all
	$t->post_ok( '/eve/suricata_alerts' => $H => 'this is not json' )->status_is( 400, 'non-JSON body => 400' );

	# each of the four table names routes to the right type
	for my $case (
		[ 'suricata_alerts', 'suricata' ],
		[ 'sagan_alerts',    'sagan' ],
		[ 'cape_alerts',     'cape' ],
		[ 'baphomet_alerts', 'baphomet' ],
		)
	{
		my ( $table, $type ) = @$case;
		%got = ();
		$t->post_ok( "/eve/$table" => $H => json => { instance => 'x' } )
			->status_is( 201, "POST /eve/$table => 201" )
			->json_is( '/status', 'ok', "$table push reports ok" )
			->json_is( '/id',     99,   "$table push returns the new id" );
		is( $got{type}, $type, "$table routed to the '$type' type" );
	}

	# the three database/escalation-managed columns are rejected, not stripped
	for my $col (qw( id escalations auto_escalated )) {
		%got = ();
		$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => 'x', $col => 'evil' } )
			->status_is( 400, "column '$col' is rejected" )
			->json_is( '/error',       'rejected columns', "'$col' reported as a rejected column" )
			->json_is( '/forbidden/0', $col,               "'$col' named in the rejection" );
		ok( !%got, "a body carrying '$col' never reaches insert_alert" );
	}

	# an unknown column is refused
	%got = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => 'x', not_a_column => 1 } )
		->status_is( 400, 'unknown column => 400' )
		->json_is( '/error',     'unknown columns', 'unknown column reported' )
		->json_is( '/unknown/0', 'not_a_column',    'the unknown column is named' );
	ok( !%got, 'an unknown column never reaches insert_alert' );

	# raw sent as a structured object is re-encoded to JSON text
	%got = ();
	$t->post_ok(
		'/eve/suricata_alerts' => $H => json => {
			instance => 'foo-pie',
			raw      => { alert => { signature => 'ET TEST' }, event_type => 'alert' },
		}
	)->status_is( 201, 'structured push accepted' );
	ok( !ref $got{row}{raw}, 'raw is re-encoded to a JSON string, not a ref' );
	is_deeply(
		decode_json( $got{row}{raw} ),
		{ alert => { signature => 'ET TEST' }, event_type => 'alert' },
		'the re-encoded raw round-trips to the pushed object'
	);

	# raw sent as a JSON string is left as-is
	%got = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => 'x', raw => '{"already":"text"}' } )
		->status_is(201);
	is( $got{row}{raw}, '{"already":"text"}', 'a raw string is passed through unchanged' );
}

# ---------------------------------------------------------------------------
# 5.  Per-key instance scope over HTTP (real receiver_apikey_instance_ok)
# ---------------------------------------------------------------------------

{
	my $t = _app();

	my %got;
	no warnings qw(redefine once);
	# the key is scoped to the 'foo-*' wildcard; instance_ok is the real method
	local *Lilith::receiver_apikey_auth = sub { return { id => 1, allowed_instances => ['foo-*'] }; };
	local *Lilith::insert_alert         = sub {
		my ( $self, %o ) = @_;
		%got = %o;
		return 55;
	};
	use warnings qw(redefine once);

	my $H = { Authorization => 'Bearer k' };

	%got = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => 'foo-pie' } )
		->status_is( 201, 'an instance within foo-* is accepted' )
		->json_is( '/id', 55 );
	is( $got{row}{instance}, 'foo-pie', 'the permitted instance reaches insert_alert' );

	%got = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => 'bar-pie' } )
		->status_is( 403, 'an instance outside foo-* is refused' )
		->json_is( '/error', 'instance not permitted for this key', 'the refusal names the reason' );
	ok( !%got, 'a disallowed instance never reaches insert_alert' );

	# a restricted key may not push a row with no instance at all
	%got = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { host => 'h' } )
		->status_is( 403, 'a restricted key may not push an instance-less row' );
	ok( !%got, 'the instance-less row never reaches insert_alert' );
}

# ---------------------------------------------------------------------------
# 6.  SQL injection is not possible
#
# The real insert_alert runs against a fake DBI handle; auth is mocked to an
# unrestricted key so the request reaches the insert. Proves that user data is
# only ever a placeholder bind and the table name comes from a fixed map.
# ---------------------------------------------------------------------------

{
	my $t = _app();

	my %cap;
	no warnings qw(redefine once);
	local *Lilith::receiver_apikey_auth = sub { return { id => 1, allowed_instances => undef }; };
	local *DBI::connect_cached          = sub { return FakeDBH->new( \%cap ); };
	use warnings qw(redefine once);

	my $H       = { Authorization => 'Bearer k' };
	my $payload = q{x'); DROP TABLE suricata_alerts; --};

	%cap = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => $payload, signature => $payload, raw => '{}' } )
		->status_is( 201, 'a row with SQL metacharacters still inserts (as data)' )
		->json_is( '/id', 4242, 'the fake insert id is returned' );

	no warnings 'once';
	my @cols = @{ $Lilith::alert_columns{suricata} };
	use warnings 'once';
	like(
		$cap{sql},
		qr/\Ainsert into suricata_alerts \( [\w, ]+ \) VALUES \( \?(?:, \?)* \) returning id;\z/,
		'SQL is a parameterized insert into the fixed table'
	);
	is( scalar @{ $cap{binds} }, scalar @cols, 'one bind value per table column' );
	is( index( $cap{sql}, 'DROP' ),   -1, 'the payload never appears in the SQL text' );
	is( index( $cap{sql}, $payload ), -1, 'no part of the payload is interpolated into the SQL' );
	ok( ( grep { defined && $_ eq $payload } @{ $cap{binds} } ), 'the payload travels only as a bind value' );

	# an injected table name is not in the fixed map: 404, and no SQL runs
	%cap = ();
	$t->post_ok( '/eve/suricata_alerts%3B%20DROP%20TABLE%20x' => $H => json => { instance => 'x' } )
		->status_is( 404, 'an injected table name is rejected' );
	ok( !exists $cap{sql}, 'no statement is prepared for an injected table name' );

	# an injected column name is refused as unknown: no SQL runs
	%cap = ();
	$t->post_ok( '/eve/suricata_alerts' => $H => json => { instance => 'x', q{raw = ''); drop table x; --} => 1 } )
		->status_is( 400, 'an injected column name is rejected' );
	ok( !exists $cap{sql}, 'no statement is prepared for an injected column name' );
}

# ---------------------------------------------------------------------------
# 7.  WebSocket transport: the streaming counterpart to the POST path
#
# App::Lilu (lilith_websocket=1) opens one WebSocket per table and streams each
# parsed alert as a JSON frame. Prove the receiver accepts that connection under
# the same bearer auth, runs each frame through the same validate-and-insert
# path, and answers with a status frame per alert.
# ---------------------------------------------------------------------------

# --- auth at the handshake -------------------------------------------------
{
	my $t = _app();

	no warnings qw(redefine once);
	local *Lilith::receiver_apikey_auth = sub {
		my ( $self, %o ) = @_;
		return ( defined $o{apikey} && $o{apikey} eq 'good' ) ? { id => 1, allowed_instances => undef } : undef;
	};
	local *Lilith::insert_alert = sub { return 1; };
	use warnings qw(redefine once);

	# A bad key must not upgrade. Drive the UA directly (rather than
	# websocket_ok, which asserts the handshake succeeds) so a refused handshake
	# is something we assert, not a failed test.
	my ( $code, $is_ws );
	$t->ua->websocket(
		'/eve/suricata_alerts' => { Authorization => 'Bearer bad' } => sub {
			my ( $ua, $tx ) = @_;
			$is_ws = $tx->is_websocket;
			$code  = $tx->res->code;
			Mojo::IOLoop->stop;
		}
	);
	Mojo::IOLoop->start;
	ok( !$is_ws, 'a bad key does not upgrade to a WebSocket' );
	is( $code, 401, 'a rejected WebSocket handshake reports 401' );

	# a good key upgrades to a WebSocket
	$t->websocket_ok( '/eve/suricata_alerts' => { Authorization => 'Bearer good' } )->finish_ok;
}

# --- streaming inserts and per-frame status --------------------------------
{
	my $t = _app();

	my @seen;
	no warnings qw(redefine once);
	local *Lilith::receiver_apikey_auth = sub { return { id => 1, allowed_instances => ['foo-*'] }; };
	local *Lilith::insert_alert         = sub {
		my ( $self, %o ) = @_;
		push @seen, \%o;
		return 100 + scalar @seen;
	};
	use warnings qw(redefine once);

	my $H = { Authorization => 'Bearer k' };

	$t->websocket_ok( '/eve/suricata_alerts' => $H );

	# a good row inserts and gets an ok frame carrying the new id
	$t->send_ok( { json => { instance => 'foo-pie', signature => 'ET TEST' } } )
		->message_ok('a streamed alert is answered')
		->json_message_is( '/status', 'ok', 'a good frame reports ok' )
		->json_message_is( '/id',     101,  'the new row id comes back on the frame' );
	is( $seen[-1]{type},           'suricata', 'the frame routed to the suricata type' );
	is( $seen[-1]{row}{signature}, 'ET TEST',  'the streamed row reached insert_alert' );

	# the connection stays open: a second alert streams over the same socket
	$t->send_ok( { json => { instance => 'foo-pie', signature => 'ET TWO' } } )
		->message_ok('a second alert over the same connection is answered')
		->json_message_is( '/id', 102, 'the second insert id comes back' );

	# a bad row is reported but does NOT tear the stream down
	$t->send_ok( { json => { instance => 'foo-pie', not_a_column => 1 } } )
		->message_ok('an unknown column is answered')
		->json_message_is( '/status', 'error',           'a bad frame reports an error' )
		->json_message_is( '/error',  'unknown columns', 'the unknown column is reported over the socket' );

	# an instance outside the key scope is refused, still without closing
	$t->send_ok( { json => { instance => 'bar-pie' } } )
		->message_ok('a disallowed instance is answered')
		->json_message_is( '/error', 'instance not permitted for this key', 'the scope refusal names its reason' );

	# ...and a good frame after the bad ones still inserts, proving the stream survived
	$t->send_ok( { json => { instance => 'foo-pie', signature => 'ET THREE' } } )
		->message_ok('the stream survived the bad frames')
		->json_message_is( '/status', 'ok', 'a later good frame is ok' );

	# a frame that is not JSON at all is answered rather than dropped
	$t->send_ok('this is not json')
		->message_ok('a non-JSON frame is answered')
		->json_message_is( '/error', 'frame must be JSON', 'a non-JSON frame is reported' );

	$t->finish_ok;

	# every insert seen was for a permitted instance
	ok( ( !grep { $_->{row}{instance} !~ /^foo-/ } @seen ), 'only permitted instances ever reached insert_alert' );
}

# --- an unknown table closes the socket ------------------------------------
{
	my $t = _app();

	my $inserted = 0;
	no warnings qw(redefine once);
	local *Lilith::receiver_apikey_auth = sub { return { id => 1, allowed_instances => undef }; };
	local *Lilith::insert_alert         = sub { $inserted++; return 1; };
	use warnings qw(redefine once);

	# Auth passes, but an unroutable table refuses the handshake with the same
	# 404 the POST path gives -- no socket is upgraded. Drive the UA directly so
	# the refused handshake is something we assert rather than a failed test.
	my ( $is_ws, $code, $body );
	$t->ua->websocket(
		'/eve/bogus_alerts' => { Authorization => 'Bearer k' } => sub {
			my ( $ua, $tx ) = @_;
			$is_ws = $tx->is_websocket;
			$code  = $tx->res->code;
			$body  = $tx->res->json;
			Mojo::IOLoop->stop;
		}
	);
	Mojo::IOLoop->start;

	ok( !$is_ws, 'an unknown table does not upgrade to a WebSocket' );
	is( $code,          404,                            'an unknown table refuses the handshake with 404' );
	is( $body->{error}, "unknown table 'bogus_alerts'", 'the unknown table is named in the refusal' );
	is( $inserted,      0,                              'no row is inserted for an unknown table' );
}

done_testing();
