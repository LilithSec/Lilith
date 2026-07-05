package Lilith::Web::Controller::Event;

use Mojo::Base 'Mojolicious::Controller';
use JSON qw(decode_json);
use MIME::Base64       qw(decode_base64);
use File::Temp         ();
use Time::Piece::Guess ();
use Mojo::IOLoop       ();

=head1 NAME

Lilith::Web::Controller::Event - Event detail controller for Lilith::Web.

=head1 DESCRIPTION

Fetches and displays a single alert event by row ID.

=cut

=head2 view

Renders the detail page for a single event.

=cut

sub view {
	my $self = shift;

	my $table = $self->param('table');
	my $id    = $self->param('id');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape)$/;

	my ( $event, $error ) = $self->_load_event( $table, $id );

	my $pretty_raw;
	if ( $event && ref $event->{raw} eq 'HASH' ) {
		eval {
			my $j = JSON->new->pretty->canonical;
			$pretty_raw = $j->encode( $event->{raw} );
		};
	} elsif ( $event && defined $event->{raw} ) {
		$pretty_raw = $event->{raw};
	}

	# PCAP download availability + the configured Virani remotes to choose from.
	# The default selection is the remote whose name matches the event instance.
	# The filter/start/end are stashed so the UI can also show a local virani
	# command for fetching the same flow on the box holding the PCAPs.
	my @remotes = sort keys %{ $self->virani_remotes };
	my $pcap_available = 0;
	my ( $pcap_filter, $pcap_start, $pcap_end, $pcap_default );
	if ( $self->virani_enabled && $table eq 'suricata' && $event ) {
		my ( $filter, $start, $end );
		eval { ( $filter, $start, $end ) = _virani_fetch_args( $event, 60 ); };
		if ( !$@ && defined $filter ) {
			$pcap_available = 1;
			$pcap_filter    = $filter;
			$pcap_start     = $start->epoch;
			$pcap_end       = $end->epoch;
			if ( defined $event->{instance} && $self->virani_remotes->{ $event->{instance} } ) {
				$pcap_default = $event->{instance};
			}
		}
	}

	$self->stash(
		event          => $event,
		table          => $table,
		id             => $id,
		error          => $error,
		pretty_raw     => $pretty_raw,
		pcap_available => $pcap_available,
		pcap_remotes   => \@remotes,
		pcap_default   => $pcap_default,
		pcap_filter    => $pcap_filter,
		pcap_start     => $pcap_start,
		pcap_end       => $pcap_end,
	);
} ## end sub view

=head2 pcap

Fetches the PCAP for a Suricata event from a configured remote Virani instance
(selected via the C<remote> query parameter) and streams it back as a download.

=cut

sub pcap {
	my $self = shift;

	my $table  = $self->param('table');
	my $id     = $self->param('id');
	my $remote = $self->param('remote');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape)$/;

	unless ( $self->virani_enabled ) {
		return $self->render( text => 'PCAP retrieval is not configured', status => 404 );
	}
	unless ( $table eq 'suricata' ) {
		return $self->render( text => 'PCAP is only available for Suricata events', status => 400 );
	}
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( text => 'invalid id', status => 400 );
	}

	my $cfg    = ( defined $remote ) ? $self->virani_remotes->{$remote} : undef;
	my $client = $self->virani_client_for($remote);
	unless ( $cfg && $client ) {
		return $self->render( text => 'unknown or unusable virani instance', status => 400 );
	}

	# An explicit ?set= overrides the remote's default set. Empty means default.
	my $set = $self->param('set');
	if ( defined $set && $set ne '' ) {
		return $self->render( text => 'invalid set', status => 400 )
			unless $set =~ /^[A-Za-z0-9._-]+$/;
	} else {
		$set = $cfg->{set};
	}

	my ( $event, $error ) = $self->_load_event( $table, $id );
	if ( $error || !$event ) {
		return $self->render( text => 'event not found', status => 404 );
	}

	my ( $filter, $start, $end );
	eval { ( $filter, $start, $end ) = _virani_fetch_args( $event, 60 ); };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( text => 'cannot build PCAP query: ' . $why, status => 400 );
	}

	return $self->virani_stream_pcap(
		sub {
			my $file = shift;
			$client->fetch(
				start  => $start,
				end    => $end,
				filter => $filter,
				file   => $file,
				( ( defined $set && $set ne '' ) ? ( set  => $set )         : () ),
				( defined $cfg->{type}           ? ( type => $cfg->{type} ) : () ),
			);
		},
		'event-' . $id . '.pcap',
	);
} ## end sub pcap

=head2 _virani_fetch_args

Builds the ( BPF filter, start Time::Piece, end Time::Piece ) for a Virani PCAP
fetch from a Suricata event, widening the window by $buffer seconds on each end.
Dies if the event lacks the fields needed to build the query.

=cut

sub _virani_fetch_args {
	my ( $event, $buffer ) = @_;
	$buffer = 60 unless defined $buffer;

	die "event has no source/destination IP\n"
		unless defined $event->{src_ip} && defined $event->{dest_ip};

	my $filter = 'host ' . $event->{src_ip} . ' and host ' . $event->{dest_ip};
	if (   defined $event->{src_port}
		&& defined $event->{dest_port}
		&& $event->{src_port} =~ /^\d+$/
		&& $event->{dest_port} =~ /^\d+$/ )
	{
		$filter .= ' and ( port ' . $event->{src_port} . ' or port ' . $event->{dest_port} . ' )';
	}

	my $start = eval { Time::Piece::Guess->guess_to_object( $event->{flow_start}, 1 ) };
	die "could not parse flow_start\n" unless defined $start;
	$start = $start - $buffer;

	my $end = eval { Time::Piece::Guess->guess_to_object( $event->{timestamp}, 1 ) };
	die "could not parse timestamp\n" unless defined $end;
	$end = $end + $buffer;

	return ( $filter, $start, $end );
} ## end sub _virani_fetch_args

=head2 body_zip

Serves the HTTP request or response body as a password protected zip. The
password is the conventional "infected" used for sharing potentially malicious
samples; it exists only to keep the file from being opened by mistake, so it is
intentionally not a secret.

=cut

sub body_zip {
	my $self = shift;

	my $table = $self->param('table');
	my $id    = $self->param('id');
	my $which = $self->param('which');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape)$/;

	unless ( $which =~ /^(?:request|response)$/ ) {
		return $self->render( text => 'invalid body', status => 400 );
	}
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( text => 'invalid id', status => 400 );
	}

	my ( $event, $error ) = $self->_load_event( $table, $id );
	if ( $error || !$event ) {
		return $self->render( text => 'event not found', status => 404 );
	}

	my $http = ref $event->{raw} eq 'HASH' ? $event->{raw}{http} : undef;
	my $b64 = ref $http eq 'HASH' ? $http->{ 'http_' . $which . '_body' } : undef;
	unless ( defined $b64 && $b64 ne '' ) {
		return $self->render( text => 'no body available', status => 404 );
	}

	my $bytes = decode_base64($b64);

	my $member = $which . '-body-' . $id;
	my $zipdata;
	my $zip_error;
	eval { $zipdata = _zip_with_password( $member, $bytes ); };
	$zip_error = $@ if $@;

	if ( $zip_error || !defined $zipdata ) {
		return $self->render( text => 'failed to build zip', status => 500 );
	}

	$self->res->headers->content_type('application/zip');
	$self->res->headers->content_disposition( 'attachment; filename="' . $member . '.zip"' );
	return $self->render( data => $zipdata );
} ## end sub body_zip

=head2 _load_event

Fetches a single event by table and id, decoding its raw JSON into a hashref
when possible. Returns C<($event, $error)>.

=cut

sub _load_event {
	my ( $self, $table, $id ) = @_;

	my $event;
	my $error;

	eval {
		# Use a large go_back_minutes to bypass the time window when fetching
		# a specific event by ID.
		my $results = $self->lilith->search(
			table           => $table,
			id              => [$id],
			go_back_minutes => 525600,    # ~1 year
			limit           => 1,
		);
		$event = $results->[0];

		if ( $event && defined $event->{raw} ) {
			my $decoded;
			eval { $decoded = decode_json( $event->{raw} ) };
			if ( !$@ && ref $decoded ) {
				$event->{raw} = $decoded;
			}
		}
	};
	$error = $@ if $@;

	return ( $event, $error );
} ## end sub _load_event

=head2 _zip_with_password

Given a member name and raw bytes, returns the bytes of a zip archive
containing the data under that member name, encrypted with the "infected"
password via the system C<zip> command. Dies on failure.

=cut

sub _zip_with_password {
	my ( $member, $bytes ) = @_;

	my $dir     = File::Temp->newdir;
	my $infile  = $dir . '/' . $member;
	my $zipfile = $dir . '/' . $member . '.zip';

	open( my $ifh, '>:raw', $infile ) or die "cannot write temp body: $!";
	print $ifh $bytes;
	close($ifh) or die "cannot close temp body: $!";

	# -j junks the temp path so only the member name is stored, -q keeps it
	# quiet. "infected" is a conventional, non-secret password.
	my $rc = system( 'zip', '-j', '-q', '-P', 'infected', $zipfile, $infile );
	die "zip command failed\n" if ( $rc != 0 || !-e $zipfile );

	open( my $zfh, '<:raw', $zipfile ) or die "cannot read zip: $!";
	local $/;
	my $zipdata = <$zfh>;
	close($zfh);

	return $zipdata;
} ## end sub _zip_with_password

1;
