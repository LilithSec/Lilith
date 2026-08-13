# dump_self -- build the Lilith object from the config file and dump it with
# Data::Dumper. A debugging aid: it shows how the TOML was actually read,
# defaults and all. Note that the dump includes the database password.
#
#     lilith dump_self
package Lilith::CLI::Command::DumpSelf;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Data::Dumper qw( Dumper );

sub command_names { 'dump_self' }

sub abstract { 'init Lilith and dump it via Data::Dumper' }

# Build the Lilith object from the config and dump it.
#
# Args:
#
#   - $opt :: the parsed options. This command has none.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the Data::Dumper output, which includes
# the database password -- so it is a debugging aid rather than something to
# paste into a bug report unedited.
sub execute {
	my ( $self, $opt, $args ) = @_;

	print Dumper( $self->lilith );

	return;
}

1;
