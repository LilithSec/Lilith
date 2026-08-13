# esc_target_get -- print one escalation target as JSON, config included, found
# by --tid or --name. Note that the config carries whatever secret the type
# needs (a webhook key, an SMTP password), so its output is as sensitive as the
# config file.
#
#     lilith esc_target_get --name soc-hook --pretty
package Lilith::CLI::Command::EscTargetGet;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target );

sub command_names { 'esc_target_get' }

sub abstract { 'print a single escalation target as JSON' }

sub opt_spec {
	return (
		[ 'tid=s',  'the escalation target ID' ],
		[ 'name=s', 'the escalation target name' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

# Look the target up and print it as JSON.
#
# Args:
#
#   - $opt :: the parsed options. --tid names the target by ID, --name by name;
#     one or the other. --pretty indents the output.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the target as a JSON object, its config
# included -- which carries whatever secret the type needs. Dies out of the
# lookup when neither option was given or nothing matched.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $target = esc_lookup_target( $self->lilith, $opt->{tid}, $opt->{name} );

	$self->print_json( $target, $opt->{pretty} );

	return;
}

1;
