# get_short_class_snmp_list -- print the shortened classification names, one
# per line, in the order the extend emits their counts. This is what a LibreNMS
# application definition is written against, so the two agree on which count is
# which.
#
#     lilith get_short_class_snmp_list
package Lilith::CLI::Command::GetShortClassSnmpList;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'get_short_class_snmp_list' }

sub abstract { 'print the shortened class names for use with SNMP' }

sub usage_desc { '%c get_short_class_snmp_list %o' }

# Print the shortened class names, one per line.
#
# The order matters and is not sorted here: it is the order the extend emits
# its counts in, so a LibreNMS application definition written against this list
# lines each count up with the right name.
#
# Args:
#
#   - $opt :: the parsed options. This command has none.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the names.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $class_list = $self->lilith->get_short_class_snmp_list;

	foreach my $item ( @{$class_list} ) {
		print $item. "\n";
	}

	return;
} ## end sub execute

1;
