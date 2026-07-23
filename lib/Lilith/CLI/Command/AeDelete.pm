package Lilith::CLI::Command::AeDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'ae_delete' }

sub abstract { 'delete a auto escalation rule' }

sub usage_desc { '%c ae_delete %o' }

sub opt_spec {
	return ( [ 'id=s', 'the auto escalation rule ID' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for deleting a auto escalation rule');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	$self->lilith->auto_escalation_delete( $opt->{id} );

	print 'deleted auto escalation ' . $opt->{id} . "\n";

	return;
}

1;
