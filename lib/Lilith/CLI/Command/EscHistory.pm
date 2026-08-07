# esc_history -- print the escalations recorded for one event, newest first:
# when, to which target, by whom, with what note, and whether it was sent.
#
# The JSON output also carries the payload actually sent, decoded unless --raw
# is given. That payload is the audit trail -- it is what the target received,
# not a reconstruction.
#
#     lilith esc_history --id 42
#     lilith esc_history --id 42 --output json --pretty
package Lilith::CLI::Command::EscHistory;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use JSON qw( decode_json );

sub command_names { 'esc_history' }

sub abstract { 'print the escalations recorded for an event' }

sub usage_desc { '%c esc_history %o' }

sub opt_spec {
	my ($class) = @_;
	return (
		[ 't=s',  'table to operate on', { default => 'suricata' } ],
		[ 'id=s', 'the row ID of the event' ],
		[ 'raw',  'do not decode the raw payload' ],
		$class->output_opt_spec,
	);
}

# Refuse the run when --id was not given.
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
		$self->usage_error('--id is required for fetching the escalations for an event');
	}

	return;
}

# Fetch the escalations recorded for the event and render them.
#
# The stored payload is only carried in the JSON output, decoded unless --raw
# was given, since it is far too wide for a terminal table. A payload that will
# not decode is left as the string it was rather than dropped -- what was
# actually sent matters more than it being pretty.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned. An event that was never
# escalated prints an empty table or an empty array.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $escalations = $self->lilith->escalations_for(
		table => $opt->{t},
		id    => $opt->{id},
	);

	return $self->output_dispatch(
		$opt,
		json => sub {
			# mirror the event action; the raw is decoded unless --raw is given
			if ( !$opt->{raw} ) {
				foreach my $escalation ( @{$escalations} ) {
					if ( defined( $escalation->{raw} ) && !ref( $escalation->{raw} ) ) {
						my $decoded;
						eval { $decoded = decode_json( $escalation->{raw} ) };
						if ( !$@ && ref($decoded) ) {
							$escalation->{raw} = $decoded;
						}
					}
				}
			} ## end if ( !$opt->{raw} )

			$self->print_json( $escalations, $opt->{pretty} );
			return;
		},
		table => sub {
			my $tb = $self->table( 'ID', 'Time', 'Target', 'Status', 'By', 'Note', 'Error' );
			my @td;
			foreach my $escalation ( @{$escalations} ) {
				push(
					@td,
					[
						$escalation->{id},
						defined( $escalation->{timestamp} )   ? $escalation->{timestamp}   : '',
						defined( $escalation->{target_name} ) ? $escalation->{target_name} : '',
						$escalation->{status},
						defined( $escalation->{requested_by} ) ? $escalation->{requested_by} : '',
						defined( $escalation->{note} )         ? $escalation->{note}         : '',
						defined( $escalation->{error} )        ? $escalation->{error}        : '',
					]
				);
			} ## end foreach my $escalation ( @{$escalations} )
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);
} ## end sub execute

1;
