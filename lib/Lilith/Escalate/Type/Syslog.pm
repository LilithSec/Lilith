package Lilith::Escalate::Type::Syslog;

use 5.006;
use strict;
use warnings;
use Sys::Syslog      qw( closelog openlog syslog );
use Lilith::Escalate ();

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

# the fields pulled off the event by default; expressed as JSONPath so a site
# can trim or extend them per target from the web UI. 'id' is always logged
# separately so a event can be identified even if these are cleared.
my @default_json_paths = (
	{ key => 'event_id',  path => '$.event_id' },
	{ key => 'instance',  path => '$.instance' },
	{ key => 'src_ip',    path => '$.src_ip' },
	{ key => 'src_port',  path => '$.src_port' },
	{ key => 'dest_ip',   path => '$.dest_ip' },
	{ key => 'dest_port', path => '$.dest_port' },
	{ key => 'class',     path => '$.classification' },
	{ key => 'signature', path => '$.signature' },
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
		{
			name     => 'priority',
			label    => 'Priority',
			type     => 'enum',
			required => 0,
			default  => 'alert',
			options  => [qw( emerg alert crit err warning notice info debug )],
		},
		{
			name     => 'facility',
			label    => 'Facility',
			type     => 'enum',
			required => 0,
			default  => 'daemon',
			options  => [ sort keys %facilities ],
		},
		{ name => 'ident', label => 'Ident', type => 'string', required => 0, default => 'lilith' },
		{
			name     => 'json_paths',
			label    => 'JSONPath fields',
			type     => 'list',
			required => 0,
			default  => [
				map {
					{ %{$_} }
				} @default_json_paths
			],
			help => 'JSONPath expressions pulled from the event and appended to the log line as key="value";'
				. ' multiple matches for one path are joined with commas',
			columns => [
				{ name => 'key',  placeholder => 'field name', pattern => '^[A-Za-z0-9._-]+$' },
				{ name => 'path', placeholder => 'JSONPath e.g. $.raw.alert.signature' },
			],
		},
	];
} ## end sub config_fields

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

	if ( defined( $config->{json_paths} ) ) {
		if ( ref( $config->{json_paths} ) ne 'ARRAY' ) {
			die("\"json_paths\" must be a list\n");
		}
		require JSON::Path;
		foreach my $spec ( @{ $config->{json_paths} } ) {
			if ( ref($spec) ne 'HASH' ) {
				die("each json_paths entry must be a key/path object\n");
			}

			# a blank path is a empty row and simply ignored at escalate time
			next if !defined( $spec->{path} ) || $spec->{path} eq '';

			if ( defined( $spec->{key} ) && $spec->{key} ne '' && $spec->{key} !~ /^[A-Za-z0-9._-]+$/ ) {
				die( '"' . $spec->{key} . '" is not a usable json_paths field name' . "\n" );
			}

			# JSON::Path parses lazily, so actually evaluate against a empty
			# document to surface a malformed expression here instead of at
			# escalate time; warnings from odd but harmless paths are muffled
			my $ok = eval {
				local $SIG{__WARN__} = sub { };
				JSON::Path->new( $spec->{path} )->values( {} );
				1;
			};
			if ( !$ok ) {
				( my $err = $@ ) =~ s/\s+\z//;
				die( '"' . $spec->{path} . '" is not a usable JSONPath: ' . $err . "\n" );
			}
		} ## end foreach my $spec ( @{ $config->{json_paths} } )
	} ## end if ( defined( $config->{json_paths} ) )

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
	if ( defined( $event->{id} ) && !ref( $event->{id} ) ) {
		$message = $message . ' id="' . _escape_log_value( $event->{id} ) . '"';
	}
	foreach my $key (qw( note requested_by target_name )) {
		if ( defined( $args{$key} ) && $args{$key} ne '' ) {
			$message = $message . ' ' . $key . '="' . _escape_log_value( $args{$key} ) . '"';
		}
	}
	if ( $args{test} ) {
		$message = $message . ' test="1"';
	}

	# pull the configured JSONPath fields off the event and append them as
	# key="value" pairs; the raw is decoded first so both row columns
	# ($.src_ip) and nested detector fields ($.raw.alert.signature) resolve.
	# A target with no json_paths of its own gets the defaults, matching what
	# was previously hard coded, while an explicitly empty list opts out
	my $json_paths = defined( $config->{json_paths} ) ? $config->{json_paths} : \@default_json_paths;
	if ( ref($json_paths) eq 'ARRAY' && @{$json_paths} ) {
		require JSON::Path;
		my $doc = Lilith::Escalate->decode_event_raw($event);
		foreach my $spec ( @{$json_paths} ) {
			next unless ref($spec) eq 'HASH' && defined( $spec->{path} ) && $spec->{path} ne '';
			my $key    = ( defined( $spec->{key} ) && $spec->{key} ne '' ) ? $spec->{key} : 'jsonpath';
			my @values = eval {
				local $SIG{__WARN__} = sub { };
				JSON::Path->new( $spec->{path} )->values($doc);
			};

			# a path can match more than one scalar; join them into a single
			# key="a,b,c" value and skip the field entirely when nothing matched
			my @scalars = grep { !ref($_) && defined($_) } @values;
			next unless @scalars;
			my $joined = join( ',', map { _escape_log_value($_) } @scalars );
			$message = $message . ' ' . $key . '="' . $joined . '"';
		} ## end foreach my $spec ( @{$json_paths} )
	} ## end if ( ref($json_paths) eq 'ARRAY' && @{$json_paths...})

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

# values land inside key="value" pairs and come from event data; escape
# backslashes and quotes so the quoting cannot be broken out of, and control
# characters so a newline cannot forge additional pairs or split the line
sub _escape_log_value {
	my $value = shift;
	$value =~ s/\\/\\\\/g;
	$value =~ s/\"/\\\"/g;
	$value =~ s/([\x00-\x1f\x7f])/sprintf( '\\x%02x', ord($1) )/ge;
	return $value;
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
