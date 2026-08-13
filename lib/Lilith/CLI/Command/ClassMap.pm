# class_map -- print the mapping from a classification's long name to the short
# name search results and the LibreNMS extend use. Reads the map off the Lilith
# object rather than the database, so it shows what this install would apply
# rather than what has been seen.
#
#     lilith class_map
package Lilith::CLI::Command::ClassMap;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'class_map' }

sub abstract { 'print the long name to short name class mapping' }

# Print the classification map as a table, sorted by long name so the output is
# stable between runs.
#
# Args:
#
#   - $opt :: the parsed options. This command has none.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the table.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;

	my $tb = $self->table( 'Class', 'Mapping' );

	my @td;
	foreach my $key ( sort( keys( %{ $lilith->{class_map} } ) ) ) {
		push( @td, [ $key, $lilith->{class_map}{$key} ] );
	}

	$tb->add_rows( \@td );
	print $tb->draw;

	return;
} ## end sub execute

1;
