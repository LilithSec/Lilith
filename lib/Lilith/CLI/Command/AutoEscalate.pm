# auto_escalate -- evaluate the enabled rules against alerts ingested in the
# window and escalate what matches. This is the command the systemd timer and
# the cron entry run; see docs/escalation.md.
#
# --m only bounds how far back to scan; the per-alert auto_escalated stamp is
# what stops an alert being escalated twice, so a generous window is safe.
# --dry-run reports what would fire and sends nothing, leaving the alerts
# unstamped so a real run still sees them. Exits 0 either way -- a rule that
# matched nothing is not an error.
#
#     lilith auto_escalate --dry-run
#     lilith auto_escalate -m 60 --tables suricata,cape
package Lilith::CLI::Command::AutoEscalate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'auto_escalate' }

sub abstract { 'evaluate the auto escalation rules against recent alerts' }

sub opt_spec {
	my ($class) = @_;
	return (
		[ 'tables=s', 'comma separated alert tables to scan' ],
		[ 'm=s',      'how far back to look, in minutes', { default => 5 } ],
		[ 'dry-run',  'report what would be escalated without sending' ],
		[ 'by=s',     'who requested each escalation', { default => 'auto' } ],
		$class->output_opt_spec,
	);
} ## end sub opt_spec

# Scan each table in turn and render the summaries.
#
# All four tables are scanned by default, baphomet included, so a rule scoped
# to it can fire. That is not the same as the default a rule with no tables of
# its own gets, which stays suricata/sagan/cape -- scanning baphomet lets an
# opted-in rule see it, without opting every rule in.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned. Prints one row per
# rule/alert match, or a bare per-table row when a table matched nothing.
# Exits 0 whether or not anything was escalated; a database or target failure
# dies out of Lilith.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;

	# --tables scopes which alert tables are scanned; all four by default. baphomet
	# is scanned so a rule scoped to it can fire, but stays out of the rule-tables
	# default, so a rule that names no tables never escalates baphomet.
	my @tables = grep { $_ ne '' } split( /\s*,\s*/, defined( $opt->{tables} ) ? $opt->{tables} : '' );
	if ( !@tables ) {
		@tables = ( 'suricata', 'sagan', 'cape', 'baphomet' );
	}

	my $by = $opt->{by};
	if ( !defined($by) || $by eq '' ) {
		$by = 'auto';
	}

	my @summaries;
	foreach my $ae_table (@tables) {
		my $result = $lilith->auto_escalate(
			table           => $ae_table,
			go_back_minutes => $opt->{m},
			dry_run         => ( $opt->{dry_run} ? 1 : 0 ),
			requested_by    => $by,
		);
		push( @summaries, @{$result} );
	}

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( \@summaries, $opt->{pretty} ) },
		table => sub {
			my $tb = $self->table( 'Table', 'Scanned', 'Rules', 'Matched', 'Alert', 'Rule', 'Targets', 'Status' );
			my @td;
			foreach my $summary (@summaries) {
				if ( !@{ $summary->{escalations} } ) {
					push(
						@td,
						[
							$summary->{table}, $summary->{scanned}, $summary->{rules}, $summary->{matched},
							'',                '',                  '',                ''
						]
					);
					next;
				} ## end if ( !@{ $summary->{escalations} } )
				foreach my $entry ( @{ $summary->{escalations} } ) {
					my @targets = @{ $entry->{target_ids} };
					push( @targets, map { $_ . '?' } @{ $entry->{unknown_targets} } );
					push(
						@td,
						[
							$summary->{table},     $summary->{scanned}, $summary->{rules},
							$summary->{matched},   $entry->{alert_id},  $entry->{rule_name},
							join( ',', @targets ), $entry->{status},
						]
					);
				} ## end foreach my $entry ( @{ $summary->{escalations} ...})
			} ## end foreach my $summary (@summaries)
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);
} ## end sub execute

1;
