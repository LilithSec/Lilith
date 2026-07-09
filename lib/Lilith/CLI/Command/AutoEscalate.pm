package Lilith::CLI::Command::AutoEscalate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'auto_escalate' }

sub abstract { 'evaluate the auto escalation rules against recent alerts' }

sub usage_desc { '%c auto_escalate %o' }

sub opt_spec {
	return (
		[ 'tables=s', 'comma separated alert tables to scan' ],
		[ 'm=s',      'how far back to look, in minutes', { default => 5 } ],
		[ 'dry-run',  'report what would be escalated without sending' ],
		[ 'by=s',     'who requested each escalation', { default => 'auto' } ],
		[ 'output=s', 'output type: table or json',    { default => 'table' } ],
		[ 'pretty',   'pretty print the JSON' ],
	);
} ## end sub opt_spec

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;

	# --tables scopes which alert tables are scanned; all three by default
	my @tables = grep { $_ ne '' } split( /\s*,\s*/, defined( $opt->{tables} ) ? $opt->{tables} : '' );
	if ( !@tables ) {
		@tables = ( 'suricata', 'sagan', 'cape' );
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

	if ( $opt->{output} eq 'json' ) {
		$self->print_json( \@summaries, $opt->{pretty} );
		return;
	}

	my $tb = $self->table( 'Table', 'Scanned', 'Rules', 'Matched', 'Alert', 'Rule', 'Targets', 'Status' );
	my @td;
	foreach my $summary (@summaries) {
		if ( !@{ $summary->{escalations} } ) {
			push( @td,
				[ $summary->{table}, $summary->{scanned}, $summary->{rules}, $summary->{matched}, '', '', '', '' ]
			);
			next;
		}
		foreach my $entry ( @{ $summary->{escalations} } ) {
			my @targets = @{ $entry->{target_ids} };
			push( @targets, map { $_ . '?' } @{ $entry->{unknown_targets} } );
			push(
				@td,
				[
					$summary->{table},  $summary->{scanned}, $summary->{rules},     $summary->{matched},
					$entry->{alert_id}, $entry->{rule_name}, join( ',', @targets ), $entry->{status},
				]
			);
		} ## end foreach my $entry ( @{ $summary->{escalations} ...})
	} ## end foreach my $summary (@summaries)
	$tb->add_rows( \@td );
	print $tb->draw;

	return;
} ## end sub execute

1;
