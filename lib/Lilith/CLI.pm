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
#
# Args: none.
#
# Returns: the option spec as a list of array refs, in the
# Getopt::Long::Descriptive form App::Cmd expects -- [ $spec, $description,
# \%attributes ]. Reached later as $self->app->global_options->config and so
# on.
#
#     lilith --config /etc/lilith.toml --debug search --si 1.2.3.4
sub global_opt_spec {
	return (
		[ 'config=s',  'config file to use', { default => '/usr/local/etc/lilith.toml' } ],
		[ 'debug',     'enable debug output' ],
		[ 'version|v', 'print version and exit' ],
	);
}

# --version / -v short circuits before dispatching to any command. Handled here
# rather than as its own subcommand so it works in the position a global option
# is written in, and without a config file having to exist.
#
# Args:
#
#   - @args :: the command line as App::Cmd hands it over, subcommand name
#     included. Passed through untouched.
#
# Returns: whatever App::Cmd's own get_command returns -- the ( $command,
# $opt, @rest ) list naming the command to run, its global options, and the
# arguments left for it. Never returns when --version was given: the version
# is printed and the process exits 0.
#
#     lilith --version
#     # lilith v. 4.1.0
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
#
# Args:
#
#   - $args :: array ref of the arguments left after the global options, the
#     first of which App::Cmd would normally read as the subcommand name.
#
# Returns: the two-element list ( $command_name, $args ) -- the command to run
# and the arguments to run it with. Anything not starting with a dash is left
# to App::Cmd to resolve, so an unknown subcommand still errors as usual
# rather than being quietly searched for.
#
#     lilith                  # ( 'search', [] )
#     lilith --si 1.2.3.4     # ( 'search', [ '--si', '1.2.3.4' ] )
#     lilith event --id 42    # left to App::Cmd
sub _cmd_from_args {
	my ( $self, $args ) = @_;

	if ( !@{$args} || $args->[0] =~ /^-/ ) {
		return ( 'search', $args );
	}

	return $self->SUPER::_cmd_from_args($args);
}

# Set the Lilith_* / NO_COLOR environment defaults once, before any command
# draws colored output, then dispatch as usual. Hooked here rather than in each
# command because the defaults have to be in place before Text::ANSITable reads
# them, whichever subcommand ends up running.
#
# Args:
#
#   - $cmd :: the command object App::Cmd resolved.
#   - $opt :: the parsed options for that command.
#   - @args :: the leftover positional arguments.
#
# All three are passed straight through untouched.
#
# Returns: whatever the command's execute returned.
sub execute_command {
	my ( $self, $cmd, $opt, @args ) = @_;

	$self->set_env_defaults;

	return $self->SUPER::execute_command( $cmd, $opt, @args );
}

# The color/formatting environment defaults, formerly inline in the script.
# Every one is set only when the environment does not already carry it, so a
# value exported by the user or the service file always wins. Colour is off
# unless Lilith_color_enable is set, which is why NO_COLOR is set rather than
# cleared. See the environment variables table in docs/usage.md for what each
# one does.
#
# Args: none. Called as a class or instance method; it only touches %ENV.
#
# Returns: nothing meaningful -- called for the side effect on %ENV.
#
#     Lilith::CLI->set_env_defaults;
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
