package Lilith::Web::Controller::Event;

use Mojo::Base 'Mojolicious::Controller';
use JSON qw(decode_json);

=head1 NAME

Lilith::Web::Controller::Event - Event detail controller for Lilith::Web.

=head1 DESCRIPTION

Fetches and displays a single alert event by row ID.

=cut

sub view {
	my $self = shift;

	my $table = $self->param('table');
	my $id    = $self->param('id');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape)$/;

	my $event;
	my $pretty_raw;
	my $error;

	eval {
		# Use a large go_back_minutes to bypass the time window when fetching
		# a specific event by ID.
		my $results = $self->lilith->search(
			table           => $table,
			id              => [$id],
			go_back_minutes => 525600,    # ~1 year
			limit           => 1,
		);
		$event = $results->[0];

		if ( $event && defined $event->{raw} ) {
			my $decoded;
			eval { $decoded = decode_json( $event->{raw} ) };
			if ( !$@ && ref $decoded ) {
				$event->{raw} = $decoded;
				eval {
					my $j = JSON->new->pretty->canonical;
					$pretty_raw = $j->encode($decoded);
				};
			} else {
				$pretty_raw = $event->{raw};
			}
		}
	};
	$error = $@ if $@;

	$self->stash(
		event      => $event,
		table      => $table,
		id         => $id,
		error      => $error,
		pretty_raw => $pretty_raw,
	);
}

1;
