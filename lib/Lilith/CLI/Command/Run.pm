# run -- follow the configured EVE files into PostgreSQL. The ingest daemon;
# not expected to return.
#
# The startup banner (dsn, user, whether a password is set, and the instances
# resolved out of [eves.*]) goes to both stdout and syslog, so the same detail
# is there whether it was started by hand or by an init system. The password is
# only ever reported as defined or not.
#
# With --daemonize it forks into the background and optionally drops to --user
# and --group, which need read access to the EVE files. Under systemd it is
# usually left in the foreground for the supervisor to watch.
#
#     lilith run
#     lilith run --daemonize --user lilith --group lilith
package Lilith::CLI::Command::Run;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util      qw( eve_instances );
use TOML                   qw( to_toml );
use Sys::Syslog            qw( openlog syslog );
use Net::Server::Daemonize qw( daemonize );

sub abstract { 'start processing the EVE logs and daemonize' }

sub usage_desc { '%c run %o' }

sub opt_spec {
	return (
		[ 'daemonize', 'daemonize after startup' ],
		[ 'user=s',    'user to run as when daemonizing',  { default => 0 } ],
		[ 'group=s',   'group to run as when daemonizing', { default => 0 } ],
	);
}

# Print the startup banner, then hand off to Lilith::run. Does not return.
#
# The banner goes to stdout and syslog both, so the same detail is available
# whether this was started by hand or by an init system that captured neither.
# The password is only ever reported as defined or not.
#
# Daemonizing happens after the banner and after the instances are resolved, so
# a configuration problem is reported to the terminal that started it rather
# than disappearing into the background.
#
# Args:
#
#   - $opt :: the parsed options. --daemonize forks into the background;
#     --user and --group are dropped to when it does, and need read access to
#     the EVE files.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: does not return under normal operation -- Lilith::run is the ingest
# loop. Dies when the config names no usable instances.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;
	my $toml   = $self->config;

	openlog( 'lilith', undef, 'daemon' );
	my $message = 'Lilith starting...';
	syslog( 'info', $message );
	print $message. "\n";

	$message = 'dsn: ';
	if ( defined( $toml->{dsn} ) ) {
		$message = $message . $toml->{dsn};
	} else {
		$message = $message . '***undefined***';
	}
	syslog( 'info', $message );
	print $message. "\n";

	$message = 'user: ';
	if ( defined( $toml->{user} ) ) {
		$message = $message . $toml->{user};
	} else {
		$message = $message . '***undefined***';
	}
	syslog( 'info', $message );
	print $message. "\n";

	$message = 'pass: ';
	if ( defined( $toml->{pass} ) ) {
		$message = $message . '***defined***';
	} else {
		$message = $message . '***undefined***';
	}
	syslog( 'info', $message );
	print $message. "\n\n";

	$message = 'Configured Instances...';
	syslog( 'info', $message );
	print $message. "\n";

	my %files = eve_instances($toml);

	foreach my $line ( split( /\n/, to_toml( \%files ) ) ) {
		syslog( 'info', $line );
		print $line. "\n";
	}

	print "\n\n";

	$message = 'Calling Lilith->run now....';
	syslog( 'info', $message );
	print $message. "\n";

	if ( $opt->{daemonize} ) {
		daemonize( $opt->{user}, $opt->{group}, '/var/run/lilith/pid' );
	}

	$lilith->run( files => \%files, );

	return;
} ## end sub execute

1;
