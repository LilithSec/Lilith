# ae_create -- create a auto escalation rule, a standing order the
# auto_escalate timer evaluates against newly ingested alerts.
#
# --name and the rule itself are what matter; everything else has a default.
# --tables scopes the rule to particular alert tables, and a rule that names
# none gets suricata/sagan/cape, leaving baphomet opt-in. --priority orders the
# rules against each other, lower first, and --stop halts later rules for an
# alert this one matched. A rule created with --disable is stored but not
# evaluated until ae_update --enable.
#
#     lilith ae_create --name 'high malscore' --rule @rule.json \
#         --tables cape --priority 10
package Lilith::CLI::Command::AeCreate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( ae_read_rule );

sub command_names { 'ae_create' }

sub abstract { 'create a auto escalation rule' }

sub opt_spec {
	return (
		[ 'name=s',     'the name for the new rule', { required => 1 } ],
		[ 'rule=s',     'the rule as a JSON object, or @file' ],
		[ 'tables=s',   'comma separated alert tables the rule applies to' ],
		[ 'priority=s', 'evaluation order, lower first' ],
		[ 'stop',       'set stop_on_match' ],
		[ 'desc=s',     'an optional description' ],
		[ 'disable',    'create the rule disabled' ],
	);
} ## end sub opt_spec

# Read the rule, work the options into the create arguments, and store it.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them. --rule is
#     JSON inline or, with a leading @, the path to a file holding it.
#   - $args :: array ref of leftover positional arguments. Unused; a rule is
#     described entirely by its options.
#
# Returns: nothing meaningful. Prints 'created auto escalation <id>' with the
# new rule's ID. A malformed rule, an unknown table, or a database failure
# dies out of Lilith with the reason.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rule = ae_read_rule( $opt->{rule} );

	my @tables = grep { $_ ne '' } split( /\s*,\s*/, defined( $opt->{tables} ) ? $opt->{tables} : '' );

	my $new_id = $self->lilith->auto_escalation_create(
		name          => $opt->{name},
		rule          => $rule,
		tables        => ( @tables ? \@tables : undef ),
		priority      => $opt->{priority},
		stop_on_match => ( $opt->{stop} ? 1 : 0 ),
		description   => $opt->{desc},
		enabled       => ( $opt->{disable} ? 0 : 1 ),
	);

	print 'created auto escalation ' . $new_id . "\n";

	return;
} ## end sub execute

1;
