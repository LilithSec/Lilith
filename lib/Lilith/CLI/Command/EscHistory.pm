package Lilith::CLI::Command::EscHistory;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use JSON qw( decode_json );

sub command_names { 'esc_history' }

sub abstract { 'print the escalations recorded for a event' }

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

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for fetching the escalations for a event');
	}

	return;
}

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
