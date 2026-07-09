package Lilith::CLI::Command::GetShortClassSnmpList;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'get_short_class_snmp_list' }

sub abstract { 'print the shortened class names for use with SNMP' }

sub usage_desc { '%c get_short_class_snmp_list %o' }

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $class_list = $self->lilith->get_short_class_snmp_list;

	foreach my $item ( @{$class_list} ) {
		print $item. "\n";
	}

	return;
} ## end sub execute

1;
