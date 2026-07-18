package Lilith::Receiver;

use Mojo::Base 'Mojolicious';
use Mojo::JSON  qw(encode_json decode_json);
use TOML        qw(from_toml);
use File::Slurp qw(read_file);
use Lilith      ();

=head1 NAME

Lilith::Receiver - Mojolicious app that ingests pushed EVE alert rows.

=head1 SYNOPSIS

    # Start via mojo_lilith_receiver script
    mojo_lilith_receiver daemon

    # Or directly
    LILITH_CONFIG=/usr/local/etc/lilith.toml mojo_lilith_receiver daemon -l http://*:8081

=head1 DESCRIPTION

Companion to L<Lilith::Web>. Where the web app reads alerts, this one writes
them: a remote sensor parses its EVE stream with L<Lilith/parse_eve> and pushes
the resulting row hash to C<< /eve/:table >>. The row is validated against the
column set for that table and inserted with L<Lilith/insert_alert>, so the
central database is populated without every sensor needing DB credentials.

The same C</eve/:table> endpoint is offered over two transports, which validate
and insert identically (the shared C<_process_row>); a sensor picks one:

=over 4

=item * B<HTTP POST> -- one request per alert. Simple and stateless.

=item * B<WebSocket> -- the client opens one connection per table and streams
each alert as a JSON frame, avoiding a fresh request per alert for a high-volume
sensor. This is what L<App::Lilu> uses when its C<lilith_websocket> is set.

=back

=head2 REQUEST

    POST /eve/:table
    Authorization: Bearer <apikey>
    Content-Type: application/json

    { "instance": "...", "host": "...", "timestamp": "...", ..., "raw": { ... } }

C<:table> is one of C<suricata_alerts>, C<sagan_alerts>, C<cape_alerts>,
C<baphomet_alerts>. The
body must be a JSON object carrying at most the ingestable columns for that
table (see C<%Lilith::alert_columns>). The generated/derived columns C<id>,
C<escalations>, and C<auto_escalated> are B<not> accepted: a body containing
any of them is rejected rather than silently stripped, so a caller can never
believe it set an escalation state that the receiver dropped. (Note the row
column is C<auto_escalated>; C<auto_escalations> is a separate table.)

=head2 WEBSOCKET

    GET /eve/:table  (Upgrade: websocket)
    Authorization: Bearer <apikey>

    -> {"instance":"...", ..., "raw":{ ... }}   (one JSON frame per alert)
    <- {"status":"ok","id":123}                 (a status frame per alert)

The bearer auth and IP scope are checked at the handshake exactly as for the
POST, and each streamed frame is the same row object the POST body carries.
Every frame gets a JSON status frame back: C<< {status=>"ok",id=>...} >> on a
successful insert, or C<< {status=>"error",error=>...} >> for a rejected/failed
row -- the same bodies the POST renders. A bad frame (malformed JSON, unknown or
forbidden column, disallowed instance, insert failure) is reported but leaves
the connection open so the rest of the batch still flows. A handshake for an
unknown C<:table> is refused with the same C<404> the POST path returns, so no
dead-end socket is ever opened. Idle connections are not timed out, since a
streaming sensor may pause between alerts.

=head2 AUTH

Keys live in the database (the C<receiver_apikeys> table), managed with the
C<lilith receiver_key_*> commands, not in the config file. Each key may be
scoped to a set of client IPs/subnets and to a set of instance names (with
C<*>/C<?> wildcards). A request is authorized only when the bearer token names
an enabled key, the client IP is permitted by that key, and -- once the body is
parsed -- the pushed row's C<instance> is permitted by that key. With no keys
configured the receiver rejects everything.

Behind a reverse proxy set C<MOJO_REVERSE_PROXY=1> so the client IP is taken
from C<X-Forwarded-For> rather than the proxy's own address; otherwise every
request appears to come from the proxy and per-IP scoping is meaningless.

=head2 CONFIG

Reuses the standard C<LILITH_CONFIG> TOML (dsn/user/pass). No receiver-specific
config is required.

=cut

# table param -> parse_eve type. This is the authoritative allow-list of tables
# the receiver will write to; anything else 404s.
my %TABLE_TYPE = (
	suricata_alerts => 'suricata',
	sagan_alerts    => 'sagan',
	cape_alerts     => 'cape',
	baphomet_alerts => 'baphomet',
);

# Columns that exist on the alert tables but are never accepted from a caller:
# id is the serial primary key, escalations/auto_escalated are managed by the
# escalation subsystem. Kept as a name set for O(1) rejection.
my %FORBIDDEN = map { $_ => 1 } qw( id escalations auto_escalated );

sub startup {
	my $self = shift;

	my $config_file = $ENV{LILITH_CONFIG} // '/usr/local/etc/lilith.toml';
	die "Config file '$config_file' does not exist\n" unless -f $config_file;

	my $toml_raw = read_file($config_file)
		or die 'Failed to read "' . $config_file . '"';
	my ( $toml, $err ) = from_toml($toml_raw);
	die "Error parsing toml '$config_file': $err\n" unless $toml;

	my $lilith = Lilith->new(
		dsn  => $toml->{dsn},
		user => $toml->{user},
		pass => $toml->{pass},
	);
	$self->helper( lilith => sub { $lilith } );

	my $r = $self->routes;

	# --- auth: Authorization: Bearer <key>, plus the key's IP scope ---------
	# The matched key row is stashed so the instance scope can be checked in
	# _ingest once the pushed row's instance is known. With no keys in the
	# database nothing matches and every request is refused (fail closed).
	my $auth = $r->under(
		sub {
			my $c     = shift;
			my $hdr   = $c->req->headers->authorization // '';
			my ($tok) = $hdr =~ /^Bearer\s+(\S+)$/;
			my $key
				= defined $tok
				? $c->lilith->receiver_apikey_auth( apikey => $tok, ip => $c->tx->remote_address )
				: undef;
			if ($key) {
				$c->stash( apikey => $key );
				return 1;
			}
			$c->render( json => { status => 'error', error => 'unauthorized' }, status => 401 );
			return undef;
		}
	);

	# --- ingest ------------------------------------------------------------
	# Two transports, one validation/insert path (_process_row): a plain POST
	# per alert for simple clients, and a kept-open WebSocket that streams one
	# JSON frame per alert for a sensor pushing a high volume. Both live under
	# the same /eve/:table path and the same bearer auth; see App::Lilu's
	# send_alert for the pushing side.
	$auth->post('/eve/:table')->to( cb => \&_ingest );
	$auth->websocket('/eve/:table')->to( cb => \&_ingest_ws );
} ## end sub startup

# Validate one pushed row for $type and insert it. Returns ( $status, $body )
# where $status is the HTTP status the POST path renders (and a rough severity
# hint for the WebSocket path) and $body is the JSON response hash. This is the
# single place a row is checked and stored, so the POST and WebSocket transports
# cannot drift in what they accept.
sub _process_row {
	my ( $c, $type, $body ) = @_;

	return ( 400, { status => 'error', error => 'body must be a JSON object' } )
		unless ref $body eq 'HASH';

	# Allowed columns for this type; reject anything outside that set. A
	# forbidden column (id/escalations/auto_escalated) is called out
	# specifically; any other stray key is a typo or schema drift.
	my %allowed = map { $_ => 1 } @{ $Lilith::alert_columns{$type} };
	my ( @forbidden, @unknown );
	for my $k ( keys %$body ) {
		next if $allowed{$k};
		if   ( $FORBIDDEN{$k} ) { push @forbidden, $k }
		else                    { push @unknown,   $k }
	}
	return ( 400, { status => 'error', error => 'rejected columns', forbidden => \@forbidden } ) if @forbidden;
	return ( 400, { status => 'error', error => 'unknown columns',  unknown   => \@unknown } )   if @unknown;

	# The key's instance scope can only be checked now that the row's instance
	# is known. A key restricted to certain instances (with optional wildcards)
	# may not write outside them.
	unless ( $c->lilith->receiver_apikey_instance_ok( $c->stash('apikey'), $body->{instance} ) ) {
		return ( 403, { status => 'error', error => 'instance not permitted for this key' } );
	}

	# Build the row from allowed columns only. raw is a jsonb column; if the
	# caller sent it as structured JSON re-encode it to text for the bind.
	my %row = map { $_ => $body->{$_} } grep { exists $body->{$_} } keys %allowed;
	$row{raw} = encode_json( $row{raw} ) if ref $row{raw};

	my $id = eval { $c->lilith->insert_alert( type => $type, row => \%row ) };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return ( 500, { status => 'error', error => "insert failed: $why" } );
	}

	return ( 201, { status => 'ok', id => $id } );
} ## end sub _process_row

# POST /eve/:table -- validate the pushed row and insert it.
sub _ingest {
	my $c     = shift;
	my $table = $c->stash('table');

	my $type = $TABLE_TYPE{$table};
	return $c->render( json => { status => 'error', error => "unknown table '$table'" }, status => 404 )
		unless defined $type;

	my ( $status, $resp ) = _process_row( $c, $type, $c->req->json );
	return $c->render( json => $resp, status => $status );
} ## end sub _ingest

# GET /eve/:table (WebSocket) -- stream ingest. The sensor opens one connection
# per table and sends each parsed alert as a JSON frame; every frame is run
# through the same _process_row as the POST path, and a JSON status frame is
# sent back per row. Bad rows are reported but do not tear the stream down, so
# one malformed alert does not cost the rest of the batch; an unroutable table
# refuses the handshake with a 404 (like the POST) so no dead-end socket opens.
sub _ingest_ws {
	my $c     = shift;
	my $table = $c->stash('table');

	my $type = $TABLE_TYPE{$table};

	# Unknown table: nothing to route frames to, so fail the handshake with the
	# same 404 the POST path gives rather than upgrading a dead-end socket.
	# Rendering here (before any send/on) means Mojo never sends the 101.
	return $c->render( json => { status => 'error', error => "unknown table '$table'" }, status => 404 )
		unless defined $type;

	# A streaming connection is meant to idle between alerts, so do not let the
	# server time it out; the pushing side (App::Lilu) drops its timeout too.
	$c->inactivity_timeout(0);

	# One frame == one alert row (the JSON body of the POST path). Decode it
	# ourselves so a frame that is not JSON at all gets an error frame back
	# rather than being silently dropped; _process_row then handles JSON that is
	# not an object (array/scalar) with its usual 400.
	$c->on(
		message => sub {
			my ( $c, $bytes ) = @_;
			my $body = eval { decode_json($bytes) };
			if ($@) {
				return $c->tx->send( { json => { status => 'error', error => 'frame must be JSON' } } );
			}
			my ( undef, $resp ) = _process_row( $c, $type, $body );
			$c->tx->send( { json => $resp } );
		}
	);

	return;
} ## end sub _ingest_ws

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
