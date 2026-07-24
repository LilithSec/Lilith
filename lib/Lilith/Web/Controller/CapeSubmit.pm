package Lilith::Web::Controller::CapeSubmit;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::IOLoop ();
use File::Temp   ();

=head1 NAME

Lilith::Web::Controller::CapeSubmit - CAPE submission controller for Lilith::Web.

=head1 DESCRIPTION

An upload page and a JSON API for handing a local file to a configured CAPEv2
box (C<mojo_cape_submit>) for detonation, using L<Lilith::CapeSubmit>. Both the
page and the endpoint are gated by C<cape_submit_enabled> (the C<cape_enable>
config with at least one C<[cape_servers.NAME]> configured); when off they 404,
since a submission pushes a file to an outside service.

The actual POST is a blocking network call, so it runs in a
L<Mojo::IOLoop/subprocess> to keep the worker's event loop responsive, exactly
as the escalation preview and PCAP download do.

=cut

# feature gate; returns 1 when the caller may proceed, else renders the 404 and
# returns 0. CAPE submission is off unless enabled with a server configured.
sub _require_enabled {
	my $self = shift;

	if ( !$self->cape_submit_enabled ) {
		$self->reply->not_found;
		return 0;
	}

	return 1;
} ## end sub _require_enabled

=head2 index

Renders the CAPE submission page: a server picker (the configured
C<[cape_servers.NAME]> names), a slug defaulting to C<cape_slug>, and a file
input.

=cut

sub index {
	my $self = shift;

	return unless $self->_require_enabled;

	$self->stash(
		servers      => [ sort keys %{ $self->cape_servers } ],
		default_slug => $self->cape_slug,
	);

	return;
} ## end sub index

=head2 submit

Accepts a multipart upload with a C<file>, and optional C<server> and C<slug>
form fields, submits it via L<Lilith::CapeSubmit>, and renders the result hash
as JSON. A 2xx from the CAPE box renders 200; a rejected submission renders 502
with the result; a setup problem (unknown server, missing key, ...) renders 400.

=cut

sub submit {
	my $self = shift;

	return unless $self->_require_enabled;

	my $upload = $self->req->upload('file');
	if ( !$upload || $upload->size == 0 ) {
		return $self->render( json => { status => 'error', error => 'no file uploaded' }, status => 400 );
	}

	my $server = $self->param('server');
	my $slug   = $self->param('slug');

	# persist the upload to a temp path to hand the submitter; its real name is
	# passed separately since the temp path is not the name the user uploaded
	my $tmp = File::Temp->new;
	$upload->move_to( $tmp->filename );
	my $orig_name = $upload->filename;

	my $submitter = $self->cape_submitter;

	# the POST blocks (network + up to a 30s LWP timeout), so run it off the event
	# loop. During that wait no bytes flow on the client connection, so raise its
	# inactivity timeout above the submit timeout; otherwise Mojolicious's default
	# 15s closes it mid-submit and the browser's fetch reports a NetworkError.
	$self->render_later;
	$self->inactivity_timeout(120);
	Mojo::IOLoop->subprocess(
		sub {
			my $result = eval {
				$submitter->submit(
					file   => $tmp->filename,
					name   => $orig_name,
					server => $server,
					slug   => $slug,
				);
			};
			return ( $@, $result );
		},
		sub {
			my ( $subprocess, $sp_err, $submit_err, $result ) = @_;
			undef $tmp;    # keep the temp file alive until the child has read it
			if ($sp_err) {
				return $self->render(
					json   => { status => 'error', error => 'submit subprocess failed: ' . $sp_err },
					status => 500
				);
			}
			if ($submit_err) {
				( my $why = $submit_err ) =~ s/\s+\z//;
				return $self->render( json => { status => 'error', error => $why }, status => 400 );
			}
			my $status = ( $result->{status} eq 'ok' ) ? 200 : 502;
			$self->render( json => $result, status => $status );
		},
	);

	return;
} ## end sub submit

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
