# ae_delete -- remove one auto escalation rule, by the numeric --id ae_list
# shows. The escalations the rule already recorded are untouched: they stay in
# the escalations table and on their alert rows, so history stays readable
# after the standing order is gone.
#
#     lilith ae_delete --id 3
package Lilith::CLI::Command::AeDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'ae_delete' }

sub abstract { 'delete a auto escalation rule' }

sub opt_spec {
	return ( [ 'id=s', 'the auto escalation rule ID' ], );
}

# Refuse the run when --id was not given. Checked here rather than with
# App::Cmd's required flag so a missing ID prints the command's usage rather
# than a bare option error.
#
# Args:
#
#   - $opt :: the parsed options. Only --id is looked at.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful when the run may proceed. Calls usage_error,
# which prints the usage and exits non-zero, when --id is missing.
sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for deleting a auto escalation rule');
	}

	return;
}

# Delete the rule.
#
# Args:
#
#   - $opt :: the parsed options. --id is the rule's numeric ID, already known
#     to be present from validate_args.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints 'deleted auto escalation <id>'. A
# non-numeric ID or a database failure dies out of Lilith; deleting an ID that
# does not exist is not an error.
sub execute {
	my ( $self, $opt, $args ) = @_;

	$self->lilith->auto_escalation_delete( $opt->{id} );

	print 'deleted auto escalation ' . $opt->{id} . "\n";

	return;
}

1;
