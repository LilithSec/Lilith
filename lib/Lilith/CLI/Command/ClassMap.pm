package Lilith::CLI::Command::ClassMap;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'class_map' }

sub abstract { 'print the long name to short name class mapping' }

sub usage_desc { '%c class_map %o' }

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
