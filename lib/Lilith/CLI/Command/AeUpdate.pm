# ae_update -- change one auto escalation rule, found by the numeric --id.
# Only the options given are touched, so a rule can be re-scoped or renamed
# without restating the rest of it. The paired flags (--stop/--no-stop and
# --enable/--disable) exist because a plain flag cannot express "set this to
# false"; giving both of a pair is refused rather than guessed at.
#
#     lilith ae_update --id 3 --priority 5 --disable
package Lilith::CLI::Command::AeUpdate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( ae_read_rule );

sub command_names { 'ae_update' }

sub abstract { 'update a auto escalation rule' }

sub usage_desc { '%c ae_update %o' }

sub opt_spec {
	return (
		[ 'id=s',       'the auto escalation rule ID' ],
		[ 'name=s',     'the rule name' ],
		[ 'rule=s',     'the rule as a JSON object, or @file' ],
		[ 'tables=s',   'comma separated alert tables the rule applies to' ],
		[ 'priority=s', 'evaluation order, lower first' ],
		[ 'stop',       'set stop_on_match' ],
		[ 'no-stop',    'clear stop_on_match' ],
		[ 'desc=s',     'an optional description' ],
		[ 'enable',     'enable the rule' ],
		[ 'disable',    'disable the rule' ],
	);
} ## end sub opt_spec

# Refuse the run when --id is missing or when either pair of opposing flags was
# given together.
#
# The pairs cannot be resolved by precedence: --stop with --no-stop is a
# contradiction rather than a preference, so it is refused rather than one
# quietly winning.
#
# Args:
#
#   - $opt :: the parsed options. --id, and the --enable/--disable and
#     --stop/--no-stop pairs, are looked at.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful when the run may proceed; otherwise calls
# usage_error, which prints the usage and exits non-zero.
sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for updating a auto escalation rule');
	}

	if ( $opt->{enable} && $opt->{disable} ) {
		$self->usage_error('--enable and --disable are mutually exclusive');
	}

	if ( $opt->{stop} && $opt->{no_stop} ) {
		$self->usage_error('--stop and --no-stop are mutually exclusive');
	}

	return;
} ## end sub validate_args

# Build the update from whichever options were given and apply it.
#
# Only the fields actually passed go into the update, so anything left off is
# untouched rather than reset. --tables is the one exception to the "defined
# and non-empty" test: an empty --tables is meaningful, clearing the scoping
# back to the default set.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them. --id names
#     the rule and is already known to be present from validate_args.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints 'updated auto escalation <id>'. A
# malformed rule, an unknown table, or an ID that does not exist dies out of
# Lilith.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my %update = ( id => $opt->{id} );

	if ( defined( $opt->{name} ) && $opt->{name} ne '' ) {
		$update{name} = $opt->{name};
	}
	if ( defined( $opt->{rule} ) && $opt->{rule} ne '' ) {
		$update{rule} = ae_read_rule( $opt->{rule} );
	}
	if ( defined( $opt->{tables} ) ) {
		my @tables = grep { $_ ne '' } split( /\s*,\s*/, $opt->{tables} );
		$update{tables} = \@tables;
	}
	if ( defined( $opt->{priority} ) ) {
		$update{priority} = $opt->{priority};
	}
	if ( $opt->{stop} ) {
		$update{stop_on_match} = 1;
	}
	if ( $opt->{no_stop} ) {
		$update{stop_on_match} = 0;
	}
	if ( defined( $opt->{desc} ) ) {
		$update{description} = $opt->{desc};
	}
	if ( $opt->{enable} ) {
		$update{enabled} = 1;
	}
	if ( $opt->{disable} ) {
		$update{enabled} = 0;
	}

	$self->lilith->auto_escalation_update(%update);

	print 'updated auto escalation ' . $opt->{id} . "\n";

	return;
} ## end sub execute

1;
