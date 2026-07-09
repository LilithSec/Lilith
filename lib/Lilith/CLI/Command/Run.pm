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
		$message = $message . $toml->{dsn} . "\n";
	} else {
		$message = $message . "***undefined***\n";
	}
	syslog( 'info', $message );
	print $message. "\n";

	$message = 'user: ';
	if ( defined( $toml->{user} ) ) {
		$message = $message . $toml->{user} . "\n";
	} else {
		$message = $message . "***undefined***\n";
	}
	syslog( 'info', $message );
	print $message. "\n";

	$message = 'pass: ';
	if ( defined( $toml->{pass} ) ) {
		$message = $message . "***defined***\n";
	} else {
		$message = $message . "***undefined***\n";
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
