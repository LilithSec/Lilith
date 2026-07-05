package Lilith::Web::Controller::Event;

use Mojo::Base 'Mojolicious::Controller';
use JSON qw(decode_json);
use MIME::Base64 qw(decode_base64);
use File::Temp   ();

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

	$self->stash(
		event      => $event,
		table      => $table,
		id         => $id,
		error      => $error,
		pretty_raw => $pretty_raw,
	);
} ## end sub view

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
