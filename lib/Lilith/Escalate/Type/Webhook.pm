package Lilith::Escalate::Type::Webhook;

use 5.006;
use strict;
use warnings;
use POSIX            qw(strftime);
use Lilith::Escalate ();

=head1 NAME

Lilith::Escalate::Type::Webhook - Escalate a event via a HTTP POST of JSON.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

POSTs the event as JSON to a configured URL. When a apikey is set it
is sent as a C<Authorization: Bearer> header. See L<Lilith::Escalate>
for the type interface.

=head1 METHODS

=head2 description

One line description of this type.

=cut

sub description {
	return 'POST the event as JSON to a URL';
}

=head2 config_fields

The config items this type takes.

=cut

sub config_fields {
	return [
		{ name => 'url',     label => 'URL',           type => 'string',  required => 1 },
		{ name => 'apikey',  label => 'API Key',       type => 'secret',  required => 0 },
		{ name => 'timeout', label => 'Timeout (sec)', type => 'integer', required => 0, default => 30 },
	];
}

=head2 check_config

Validates a config hash ref for this type, dieing if it is not usable.

=cut

sub check_config {
	my ( $class, $config ) = @_;

	if ( ref $config ne 'HASH' ) {
		die("config is not a hash ref\n");
	}

	if ( !defined( $config->{url} ) || $config->{url} eq '' ) {
		die( '"url" is required' . "\n" );
	}

	if ( $config->{url} !~ /^https?\:\/\// ) {
		die( '"' . $config->{url} . '" for url does not look like a http(s) URL' . "\n" );
	}

	# zero would disable Mojo::UserAgent's request timeout entirely, hanging
	# the escalation worker indefinitely, so require at least one second
	if ( defined( $config->{timeout} ) && ( $config->{timeout} !~ /^[0-9]+$/ || $config->{timeout} < 1 ) ) {
		die( '"' . $config->{timeout} . '" for timeout is not a positive whole number' . "\n" );
	}

	return 1;
} ## end sub check_config

=head2 escalate

POSTs the event to the configured URL. Returns the URL and body sent,
minus the apikey. Dies on failure.

=cut

sub escalate {
	my ( $class, %args ) = @_;

	my $config = $args{config};
	$class->check_config($config);

	my $event = $args{event};

	# the raw may still be a JSON string depending on where the event came
	# from; decode it so the receiver gets structure instead of a string
	$event = Lilith::Escalate->decode_event_raw($event);

	my $body = {
		source       => 'lilith',
		kind         => 'escalation',
		table        => $args{table},
		note         => $args{note},
		requested_by => $args{requested_by},
		target       => $args{target_name},
		test         => $args{test} ? \1 : \0,
		timestamp    => strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime ),
		event        => $event,
	};

	my $headers = {};
	if ( defined( $config->{apikey} ) && $config->{apikey} ne '' ) {
		$headers->{Authorization} = 'Bearer ' . $config->{apikey};
	}

	require Mojo::UserAgent;
	my $ua = Mojo::UserAgent->new;
	$ua->request_timeout( defined( $config->{timeout} ) ? $config->{timeout} + 0 : 30 );

	my $tx = $ua->post( $config->{url}, $headers, json => $body );

	# a connection level failure (timeout, DNS, refused) has no result;
	# report it with the target URL rather than dying with Mojo's raw error
	if ( my $connection_error = $tx->error ) {
		if ( !defined( $connection_error->{code} ) ) {
			die( 'webhook POST to "' . $config->{url} . '" failed: ' . $connection_error->{message} . "\n" );
		}
	}
	my $res = $tx->result;
	if ( !$res->is_success ) {
		die( 'webhook POST to "' . $config->{url} . '" failed: HTTP ' . $res->code . ' ' . $res->message . "\n" );
	}

	return {
		url  => $config->{url},
		body => $body,
	};
} ## end sub escalate

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
