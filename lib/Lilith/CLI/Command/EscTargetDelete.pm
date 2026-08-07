# esc_target_delete -- remove an escalation target, found by --tid or --name.
# The escalations already recorded against it are kept, and each carries a
# snapshot of the target's name, so history stays readable after the target is
# gone.
#
#     lilith esc_target_delete --name soc-hook
package Lilith::CLI::Command::EscTargetDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target );

sub command_names { 'esc_target_delete' }

sub abstract { 'delete an escalation target' }

sub usage_desc { '%c esc_target_delete %o' }

sub opt_spec {
	return ( [ 'tid=s', 'the escalation target ID' ], [ 'name=s', 'the escalation target name' ], );
}

# Look the target up and delete it.
#
# It is looked up before deleting so the name can be reported back and so a
# --name that matches nothing fails before anything is removed.
#
# Args:
#
#   - $opt :: the parsed options. --tid names the target by ID, --name by name;
#     one or the other.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the ID and name of what it deleted. Dies
# out of the lookup when neither option was given or nothing matched.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = esc_lookup_target( $lilith, $opt->{tid}, $opt->{name} );

	$lilith->escalation_target_delete( $existing->{id} );

	print 'deleted escalation target ' . $existing->{id} . ', "' . $existing->{name} . '"' . "\n";

	return;
} ## end sub execute

1;
