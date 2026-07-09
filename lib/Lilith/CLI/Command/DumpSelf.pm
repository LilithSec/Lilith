package Lilith::CLI::Command::DumpSelf;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Data::Dumper qw( Dumper );

sub command_names { 'dump_self' }

sub abstract { 'init Lilith and dump it via Data::Dumper' }

sub usage_desc { '%c dump_self %o' }

sub execute {
	my ( $self, $opt, $args ) = @_;

	print Dumper( $self->lilith );

	return;
}

1;
