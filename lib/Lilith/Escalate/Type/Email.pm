package Lilith::Escalate::Type::Email;

use 5.006;
use strict;
use warnings;
use Sys::Hostname    qw( hostname );
use Lilith::Escalate ();

=head1 NAME

Lilith::Escalate::Type::Email - Escalate an event via email.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

Sends a plain text summary of the event via SMTP using L<Net::SMTP>.
See L<Lilith::Escalate> for the type interface.

=head1 METHODS

=head2 description

One line description of this type.

=cut

sub description {
	return 'send a plain text summary of the event via SMTP';
}

=head2 config_fields

The config items this type takes.

=cut

sub config_fields {
	return [
		{ name => 'host',       label => 'SMTP Host',       type => 'string',  required => 1 },
		{ name => 'port',       label => 'SMTP Port',       type => 'integer', required => 0, default => 25 },
		{ name => 'starttls',   label => 'STARTTLS',        type => 'boolean', required => 0, default => 0 },
		{ name => 'ssl_verify', label => 'Verify TLS Cert', type => 'boolean', required => 0, default => 1 },
		{ name => 'user',       label => 'SMTP User',       type => 'string',  required => 0 },
		{ name => 'pass',       label => 'SMTP Pass',       type => 'secret',  required => 0 },
		{ name => 'from',       label => 'From',            type => 'string',  required => 1 },
		{ name => 'to',         label => 'To (comma sep)',  type => 'string',  required => 1 },
		{ name => 'timeout',    label => 'Timeout (sec)',   type => 'integer', required => 0, default => 30 },
		{
			name     => 'probe_timeout',
			label    => 'Cert Probe Timeout (sec)',
			type     => 'integer',
			required => 0,
			default  => 10
		},
		{
			name     => 'subject_prefix',
			label    => 'Subject Prefix',
			type     => 'string',
			required => 0,
			default  => '[lilith]'
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

	foreach my $item (qw( host from to )) {
		if ( !defined( $config->{$item} ) || $config->{$item} eq '' ) {
			die( '"' . $item . '" is required' . "\n" );
		}
	}

	if ( defined( $config->{port} ) && $config->{port} !~ /^[0-9]+$/ ) {
		die( '"' . $config->{port} . '" for port is not numeric' . "\n" );
	}

	# zero would disable Net::SMTP's connection timeout entirely, hanging
	# the escalation worker indefinitely, so require at least one second
	foreach my $item (qw( timeout probe_timeout )) {
		if ( defined( $config->{$item} ) && ( $config->{$item} !~ /^[0-9]+$/ || $config->{$item} < 1 ) ) {
			die( '"' . $config->{$item} . '" for ' . $item . ' is not a positive whole number' . "\n" );
		}
	}

	return 1;
} ## end sub check_config

=head2 escalate

Sends the event summary via SMTP. Returns the host, from, to, subject,
and body sent, minus any SMTP pass. Dies on failure.

=cut

sub escalate {
	my ( $class, %args ) = @_;

	my $config = $args{config};
	$class->check_config($config);

	my $event = $args{event};

	# the raw may still be a JSON string depending on where the event came
	# from; decode it so the summary can pretty print it
	$event = Lilith::Escalate->decode_event_raw($event);

	my @to = grep { $_ ne '' } split( /\s*,\s*/, $config->{to} );
	if ( !@to ) {
		die( '"to" contains no usable addresses' . "\n" );
	}

	my $subject
		= ( defined( $config->{subject_prefix} )
			&& $config->{subject_prefix} ne '' ? $config->{subject_prefix} : '[lilith]' )
		. ( $args{test} ? ' test' : '' )
		. ' escalation '
		. ( defined( $args{table} )        ? $args{table}               : '' )
		. ( defined( $event->{id} )        ? ' #' . $event->{id}        : '' )
		. ( defined( $event->{signature} ) ? ': ' . $event->{signature} : '' );

	# the signature comes from sensor data; a CR/LF in it would inject
	# additional headers into the message
	$subject =~ s/[\r\n]+/ /g;

	my $body = Lilith::Escalate->event_summary( $args{table}, $event );
	foreach my $key (qw( note requested_by target_name )) {
		if ( defined( $args{$key} ) && $args{$key} ne '' ) {
			$body = $key . ': ' . $args{$key} . "\n" . $body;
		}
	}

	my $message
		= 'From: '
		. $config->{from} . "\r\n" . 'To: '
		. join( ', ', @to ) . "\r\n"
		. 'Subject: '
		. $subject . "\r\n"
		. 'X-Mailer: Lilith' . "\r\n" . "\r\n"
		. $body;

	require Net::SMTP;
	my $smtp = Net::SMTP->new(
		$config->{host},
		Port    => ( defined( $config->{port} ) ? $config->{port} + 0 : 25 ),
		Hello   => hostname,
		Timeout => ( defined( $config->{timeout} ) ? $config->{timeout} + 0 : 30 ),
	);
	if ( !$smtp ) {
		die( 'failed to connect to SMTP server "' . $config->{host} . '"' . "\n" );
	}

	# each step reports the server's message on failure so a bad config is
	# actually debuggable from the escalation error
	my $fail = sub {
		my $step    = shift;
		my $message = $smtp->message;
		$message =~ s/\s+\z// if defined $message;
		$smtp->quit;
		die( 'SMTP ' . $step . ' failed' . ( defined($message) && $message ne '' ? ': ' . $message : '' ) . "\n" );
	};

	if ( $config->{starttls} ) {
		my %ssl_args;
		# ssl_verify defaults to on; disable peer verification for servers
		# using a self signed cert or a name that does not match the host
		if ( defined( $config->{ssl_verify} ) && !$config->{ssl_verify} ) {
			require IO::Socket::SSL;
			$ssl_args{SSL_verify_mode} = IO::Socket::SSL::SSL_VERIFY_NONE();
		}
		unless ( $smtp->starttls(%ssl_args) ) {
			# the server's "220 Ready to start TLS" reply is the STARTTLS
			# command succeeding; the actual TLS handshake failure lands in
			# $@, so grab that before it or $smtp->message can be clobbered
			my $err = $@;
			$err = $smtp->message if !defined($err) || $err eq '';
			$err =~ s/\s+\z// if defined $err;
			$smtp->quit;

			my $host = $config->{host};
			my $port = ( defined( $config->{port} ) ? $config->{port} + 0 : 25 );
			my $detail
				= 'SMTP STARTTLS failed connecting to '
				. $host . ':'
				. $port
				. ( defined($err) && $err ne '' ? ': ' . $err : '' );

			# reconnect without verification purely to report what
			# certificate the server actually presented, so a name mismatch
			# is obvious from the escalation error without server side digging
			my $probe_timeout = defined( $config->{probe_timeout} ) ? $config->{probe_timeout} + 0 : 10;
			my ( $cn, @sans ) = eval { $class->_peer_cert_names( $host, $port, $probe_timeout ) };
			if ( ( defined($cn) && $cn ne '' ) || @sans ) {
				$detail .= '; server presented certificate with';
				$detail .= ' CN=' . $cn if defined($cn) && $cn ne '';
				$detail .= ( defined($cn) && $cn ne '' ? ' and' : '' ) . ' subjectAltName=' . join( ',', @sans )
					if @sans;
			}
			die( $detail . "\n" );
		} ## end unless ( $smtp->starttls(%ssl_args) )
	} ## end if ( $config->{starttls} )
	if ( defined( $config->{user} ) && $config->{user} ne '' ) {
		$smtp->auth( $config->{user}, defined( $config->{pass} ) ? $config->{pass} : '' ) or $fail->('AUTH');
	}
	$smtp->mail( $config->{from} )     or $fail->('MAIL FROM');
	$smtp->to( @to, { SkipBad => 0 } ) or $fail->('RCPT TO');
	$smtp->data                        or $fail->('DATA');
	$smtp->datasend($message)          or $fail->('DATA send');
	$smtp->dataend                     or $fail->('DATA end');
	$smtp->quit;

	return {
		host    => $config->{host},
		from    => $config->{from},
		to      => \@to,
		subject => $subject,
		body    => $body,
	};
} ## end sub escalate

# The names a mail server's certificate actually presents, so a verification
# failure can say what was found rather than only that it did not match.
# Connects, runs STARTTLS with verification deliberately off -- the point is to
# read a certificate that has already been rejected -- and reports the common
# name and every subjectAltName.
#
# Diagnostic only, and best effort: the caller is already on an error path, so
# a failure here must not replace the real error with one of its own. That is
# why every failure is an empty list rather than a die.
#
# Called as a class method, so the first arg is the class.
#
# Args:
#
#   - $host :: the mail server to connect to, as a hostname or IP.
#   - $port :: the SMTP port, e.g. 25 or 587.
#   - $timeout :: connection timeout in seconds. Optional, 10 when undef.
#
# Returns: a list -- the certificate's common name followed by its
# subjectAltName entries, each an iPAddress prefixed with 'IP:' to tell it
# apart from a dNSName. The common name is undef when the certificate has none,
# so the list can begin with undef and still carry names after it.
#
# Returns the empty list when the host cannot be reached or STARTTLS does not
# negotiate.
#
#     my ( $cn, @sans ) = Lilith::Escalate::Type::Email->_peer_cert_names( 'mail.example.org', 587 );
#     # ( 'mail.example.org', 'mx1.example.org', 'IP:192.0.2.25' )
#
#     # unreachable, so the caller's own error stands
#     my @names = Lilith::Escalate::Type::Email->_peer_cert_names( 'nowhere.invalid', 587, 2 );
#     # ()
sub _peer_cert_names {
	my ( $class, $host, $port, $timeout ) = @_;

	require Net::SMTP;
	require IO::Socket::SSL;

	my $smtp = Net::SMTP->new(
		$host,
		Port    => $port,
		Hello   => hostname,
		Timeout => ( defined($timeout) ? $timeout + 0 : 10 ),
	);
	return unless $smtp;

	unless ( $smtp->starttls( SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE() ) ) {
		$smtp->quit;
		return;
	}

	my $cn        = eval { $smtp->peer_certificate('commonName') };
	my @san_pairs = eval { $smtp->peer_certificate('subjectAltNames') };
	$smtp->quit;

	# subjectAltNames comes back as a flat list of (type, value) pairs;
	# type 2 is a dNSName and type 7 is an iPAddress
	my @sans;
	while (@san_pairs) {
		my ( $type, $value ) = splice( @san_pairs, 0, 2 );
		next unless defined($value) && $value ne '';
		push( @sans, ( defined($type) && $type == 7 ? 'IP:' : '' ) . $value );
	}

	return ( $cn, @sans );
} ## end sub _peer_cert_names

1;
