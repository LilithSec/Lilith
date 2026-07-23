package Lilith::CLI;

use strict;
use warnings;
use App::Cmd::Setup -app;
use Lilith ();

our $VERSION = $Lilith::VERSION;

=head1 NAME

Lilith::CLI - App::Cmd application class behind the C<lilith> command.

=head1 DESCRIPTION

Dispatches C<lilith> subcommands. Each subcommand is what used to be a value
of the old C<-a> action flag and now lives in its own module under
L<Lilith::CLI::Command>. Global options (C<--config>, C<--debug>) come before
the subcommand, e.g.

    lilith --config /etc/lilith.toml search --si 1.2.3.4

A bare C<lilith>, or one whose first argument is an option, runs C<search>,
matching the old default action.

=head1 SEE ALSO

L<Lilith>, L<App::Cmd>

=cut

# Global options are parsed before the subcommand name. --config replaces the
# old --config; -c stays free for the search "class" option, as before.
sub global_opt_spec {
	return (
		[ 'config=s',  'config file to use', { default => '/usr/local/etc/lilith.toml' } ],
		[ 'debug',     'enable debug output' ],
		[ 'version|v', 'print version and exit' ],
	);
}

# --version / -v short circuits before dispatching to any command.
sub get_command {
	my ( $self, @args ) = @_;

	my ( $command, $opt, @rest ) = $self->SUPER::get_command(@args);

	if ( $opt->{version} ) {
		print 'lilith v. ' . $Lilith::VERSION . "\n";
		exit 0;
	}

	return ( $command, $opt, @rest );
} ## end sub get_command

# Default to the search command. A bare `lilith`, or one whose first remaining
# argument is an option (e.g. `lilith --si 1.2.3.4`), runs a search just as the
# old default `-a search` did.
sub _cmd_from_args {
	my ( $self, $args ) = @_;

	if ( !@{$args} || $args->[0] =~ /^-/ ) {
		return ( 'search', $args );
	}

	return $self->SUPER::_cmd_from_args($args);
}

# Set the Lilith_* / NO_COLOR environment defaults once, before any command
# draws colored output, then dispatch as usual.
sub execute_command {
	my ( $self, $cmd, $opt, @args ) = @_;

	$self->set_env_defaults;

	return $self->SUPER::execute_command( $cmd, $opt, @args );
}

# The color/formatting environment defaults, formerly inline in the script.
sub set_env_defaults {
	if ( !$ENV{Lilith_color_enable} ) {
		$ENV{NO_COLOR} = 1;
	}

	if ( !defined( $ENV{Lilith_table_color} ) ) {
		$ENV{Lilith_table_color} = 'Text::ANSITable::Standard::NoGradation';
	}

	if ( !defined( $ENV{Lilith_table_border} ) ) {
		$ENV{Lilith_table_border} = 'ASCII::None';
	}

	if ( !defined( $ENV{Lilith_IP_color} ) ) {
		$ENV{Lilith_IP_color} = '1';
	}

	if ( !defined( $ENV{Lilith_IP_private_color} ) ) {
		$ENV{Lilith_IP_private_color} = 'bright_green';
	}

	if ( !defined( $ENV{Lilith_IP_remote_color} ) ) {
		$ENV{Lilith_IP_remote_color} = 'bright_yellow';
	}

	if ( !defined( $ENV{Lilith_IP_local_color} ) ) {
		$ENV{Lilith_IP_local_color} = 'bright_red';
	}

	if ( !defined( $ENV{Lilith_timestamp_drop_micro} ) ) {
		$ENV{Lilith_timestamp_drop_micro} = '0';
	}

	if ( !defined( $ENV{Lilith_timestamp_drop_offset} ) ) {
		$ENV{Lilith_timestamp_drop_offset} = '0';
	}

	if ( !defined( $ENV{Lilith_instance_color} ) ) {
		$ENV{Lilith_instance_color} = '1';
	}

	if ( !defined( $ENV{Lilith_instance_type_color} ) ) {
		$ENV{Lilith_instance_type_color} = 'bright_blue';
	}

	if ( !defined( $ENV{Lilith_instance_slug_color} ) ) {
		$ENV{Lilith_instance_slug_color} = 'bright_magenta';
	}

	if ( !defined( $ENV{Lilith_instance_loc_color} ) ) {
		$ENV{Lilith_instance_loc_color} = 'bright_cyan';
	}

	return;
} ## end sub set_env_defaults

1;
