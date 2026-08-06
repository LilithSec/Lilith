# ae_list -- list the auto escalation rules, one per row: ID, name, whether it
# is enabled, its priority and stop_on_match flag, the tables it is scoped to,
# how many times it has matched, and its description. The rule DSL itself is
# not shown; ae_get prints that.
#
#     lilith ae_list
#     lilith ae_list --output json --pretty
package Lilith::CLI::Command::AeList;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'ae_list' }

sub abstract { 'list the auto escalation rules' }

sub usage_desc { '%c ae_list %o' }

sub opt_spec {
	my ($class) = @_;
	return $class->output_opt_spec;
}

# Fetch every rule and render it.
#
# Args:
#
#   - $opt :: the parsed options -- just the shared --output/--pretty pair.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned, which output_dispatch passes
# back. Prints the rules as an ANSI table or as JSON. With no rules defined it
# prints an empty table or an empty array rather than complaining.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rules = $self->lilith->auto_escalations;

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( $rules, $opt->{pretty} ) },
		table => sub {
			my $tb
				= $self->table( 'ID', 'Name', 'Enabled', 'Priority', 'Stop', 'Tables', 'Matches', 'Description' );
			my @td;
			foreach my $rule ( @{$rules} ) {
				push(
					@td,
					[
						$rule->{id},
						$rule->{name},
						$rule->{enabled} ? 'yes' : 'no',
						$rule->{priority},
						$rule->{stop_on_match} ? 'yes' : 'no',
						join( ',', @{ $rule->{tables} } ),
						$rule->{match_count},
						defined( $rule->{description} ) ? $rule->{description} : '',
					]
				);
			} ## end foreach my $rule ( @{$rules} )
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);
} ## end sub execute

1;
