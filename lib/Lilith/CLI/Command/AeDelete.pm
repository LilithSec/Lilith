package Lilith::CLI::Command::AeDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'ae_delete' }

sub abstract { 'delete a auto escalation rule' }

sub usage_desc { '%c ae_delete %o' }

sub opt_spec {
	return ( [ 'id=s@', 'the auto escalation rule ID' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	my @id = @{ $opt->{id} // [] };
	if ( !defined( $id[0] ) ) {
		$self->usage_error('--id is required for deleting a auto escalation rule');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my @id = @{ $opt->{id} // [] };

	$self->lilith->auto_escalation_delete( $id[0] );

	print 'deleted auto escalation ' . $id[0] . "\n";

	return;
} ## end sub execute

1;
