# esc_target_test -- send a synthetic event to one escalation target and print
# the payload it was sent, so a target can be proven before an alert depends on
# it. This really does send: the webhook is POSTed to, the mail is delivered.
#
#     lilith esc_target_test --name soc-hook
package Lilith::CLI::Command::EscTargetTest;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target );

sub command_names { 'esc_target_test' }

sub abstract { 'send a synthetic test event to a escalation target' }

sub usage_desc { '%c esc_target_test %o' }

sub opt_spec {
	return (
		[ 'tid=s',  'the escalation target ID' ],
		[ 'name=s', 'the escalation target name' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

# Look the target up, send it a synthetic event, and print what was sent.
#
# Args:
#
#   - $opt :: the parsed options. --tid names the target by ID, --name by name;
#     one or the other. --pretty indents the output.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the payload the target was sent, so what
# arrived at the far end can be compared against what left. Dies out of the
# lookup when nothing matched, or out of the send when the target refused it.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = esc_lookup_target( $lilith, $opt->{tid}, $opt->{name} );

	my $payload = $lilith->escalation_test( id => $existing->{id} );

	$self->print_json( $payload, $opt->{pretty} );

	return;
} ## end sub execute

1;
