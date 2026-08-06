# ae_get -- print one auto escalation rule as JSON, including the rule DSL
# itself, which ae_list only summarises. Takes the numeric --id ae_list shows.
# The JSON is always canonical (keys sorted) so two rules can be diffed; --pretty
# only adds the indentation.
#
#     lilith ae_get --id 3 --pretty
package Lilith::CLI::Command::AeGet;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use JSON ();

sub command_names { 'ae_get' }

sub abstract { 'print a single auto escalation rule as JSON' }

sub usage_desc { '%c ae_get %o' }

sub opt_spec {
	return ( [ 'id=s', 'the auto escalation rule ID' ], [ 'pretty', 'pretty print the JSON' ], );
}

# Refuse the run when --id was not given, printing the usage rather than a bare
# option error.
#
# Args:
#
#   - $opt :: the parsed options. Only --id is looked at.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful when the run may proceed; otherwise calls
# usage_error, which prints the usage and exits non-zero.
sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for fetching a auto escalation rule');
	}

	return;
}

# Fetch the rule and print it.
#
# The JSON is encoded here rather than through print_json because this command
# has always emitted canonical JSON whether or not --pretty was given, so two
# rules can be diffed without the key order moving about.
#
# Args:
#
#   - $opt :: the parsed options. --id names the rule; --pretty indents the
#     output.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the rule as a JSON object. Dies out of
# Lilith when no rule has that ID.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rule = $self->lilith->auto_escalation_get( $opt->{id} );

	# ae_get has always emitted canonical JSON, pretty or not
	my $json = JSON->new;
	$json->canonical(1);
	if ( $opt->{pretty} ) {
		$json->pretty(1);
	}
	print $json->encode($rule);
	if ( !$opt->{pretty} ) {
		print "\n";
	}

	return;
} ## end sub execute

1;
