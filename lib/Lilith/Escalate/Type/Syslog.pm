package Lilith::Escalate::Type::Syslog;

use 5.006;
use strict;
use warnings;
use Sys::Syslog qw( closelog openlog syslog );

=head1 NAME

Lilith::Escalate::Type::Syslog - Escalate a event via syslog.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

Logs a single line summary of the event to syslog. See
L<Lilith::Escalate> for the type interface.

=cut

my %priorities = map { $_ => 1 } qw( emerg alert crit err warning notice info debug );
my %facilities = map { $_ => 1 } qw(
	auth authpriv cron daemon ftp kern local0 local1 local2 local3
	local4 local5 local6 local7 lpr mail news syslog user uucp
);

=head1 METHODS

=head2 description

One line description of this type.

=cut

sub description {
	return 'log a one line summary of the event to syslog';
}

=head2 config_fields

The config items this type takes.

=cut

sub config_fields {
	return [
		{ name => 'priority', label => 'Priority', type => 'string', required => 0, default => 'alert' },
		{ name => 'facility', label => 'Facility', type => 'string', required => 0, default => 'daemon' },
		{ name => 'ident',    label => 'Ident',    type => 'string', required => 0, default => 'lilith' },
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

	if ( defined( $config->{priority} ) && !$priorities{ $config->{priority} } ) {
		die( '"' . $config->{priority} . '" is not a known syslog priority' . "\n" );
	}

	if ( defined( $config->{facility} ) && !$facilities{ $config->{facility} } ) {
		die( '"' . $config->{facility} . '" is not a known syslog facility' . "\n" );
	}

	if ( defined( $config->{ident} ) && $config->{ident} !~ /^[A-Za-z0-9._-]+$/ ) {
		die( '"' . $config->{ident} . '" is not a usable syslog ident' . "\n" );
	}

	return 1;
} ## end sub check_config

=head2 escalate

Logs the summary line to syslog. Returns the ident, facility,
priority, and message logged.

=cut

sub escalate {
	my ( $class, %args ) = @_;

	my $config = $args{config};
	$class->check_config($config);

	my $event = $args{event};

	my $message = 'escalation table=' . ( defined( $args{table} ) ? $args{table} : '' );
	foreach my $key (qw( id event_id instance src_ip src_port dest_ip dest_port classification signature )) {
		if ( defined( $event->{$key} ) && !ref( $event->{$key} ) ) {
			my $value = $event->{$key};
			$value =~ s/\"/\\\"/g;
			$message = $message . ' ' . $key . '="' . $value . '"';
		}
	}
	foreach my $key (qw( note requested_by target_name )) {
		if ( defined( $args{$key} ) && $args{$key} ne '' ) {
			my $value = $args{$key};
			$value =~ s/\"/\\\"/g;
			$message = $message . ' ' . $key . '="' . $value . '"';
		}
	}
	if ( $args{test} ) {
		$message = $message . ' test="1"';
	}

	my $ident    = defined( $config->{ident} )    ? $config->{ident}    : 'lilith';
	my $facility = defined( $config->{facility} ) ? $config->{facility} : 'daemon';
	my $priority = defined( $config->{priority} ) ? $config->{priority} : 'alert';

	openlog( $ident, 'ndelay,pid', $facility );
	syslog( $priority, '%s', $message );
	closelog;

	return {
		ident    => $ident,
		facility => $facility,
		priority => $priority,
		message  => $message,
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
