package Lilith::CLI::Command::Esc;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_resolve_targets );

sub abstract { 'escalate a event to one or more escalation targets' }

sub usage_desc { '%c esc %o' }

sub opt_spec {
	my ($class) = @_;
	return (
		[ 't=s',    'table to operate on', { default => 'suricata' } ],
		[ 'id=s',   'the row ID of the event to escalate' ],
		[ 'to=s',   'comma separated escalation target IDs or names' ],
		[ 'note=s', 'a optional note to record with the escalation' ],
		[ 'by=s',   'who requested the escalation' ],
		$class->output_opt_spec,
	);
} ## end sub opt_spec

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for escalating a event');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;

	my $target_ids = esc_resolve_targets( $lilith, $opt->{to} );

	my $by = $opt->{by};
	if ( !defined($by) || $by eq '' ) {
		$by = getlogin || getpwuid($<) || 'unknown';
	}

	my $results = $lilith->escalate(
		table        => $opt->{t},
		id           => $opt->{id},
		target_ids   => $target_ids,
		note         => $opt->{note},
		requested_by => $by,
	);

	my $failed = scalar( grep { $_->{status} ne 'sent' } @{$results} );

	$self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( $results, $opt->{pretty} ) },
		table => sub {
			my $tb = $self->table( 'Target', 'Status', 'Escalation ID', 'Error' );
			my @td;
			foreach my $result ( @{$results} ) {
				push(
					@td,
					[
						defined( $result->{target_name} ) ? $result->{target_name} : ( 'id ' . $result->{target_id} ),
						$result->{status},
						defined( $result->{escalation_id} ) ? $result->{escalation_id} : '',
						defined( $result->{error} )         ? $result->{error}         : '',
					]
				);
			} ## end foreach my $result ( @{$results} )
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);

	exit( $failed ? 1 : 0 );
} ## end sub execute

1;
