package Lilith::CLI::Command::Esc;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_resolve_targets );

sub abstract { 'escalate a event to one or more escalation targets' }

sub usage_desc { '%c esc %o' }

sub opt_spec {
	return (
		[ 't=s',      'table to operate on', { default => 'suricata' } ],
		[ 'id=s@',    'the row ID of the event to escalate' ],
		[ 'to=s',     'comma separated escalation target IDs or names' ],
		[ 'note=s',   'a optional note to record with the escalation' ],
		[ 'by=s',     'who requested the escalation' ],
		[ 'output=s', 'output type: table or json', { default => 'table' } ],
		[ 'pretty',   'pretty print the JSON' ],
	);
} ## end sub opt_spec

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	my @id = @{ $opt->{id} // [] };
	if ( !defined( $id[0] ) ) {
		$self->usage_error('--id is required for escalating a event');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;
	my @id     = @{ $opt->{id} // [] };

	my $target_ids = esc_resolve_targets( $lilith, $opt->{to} );

	my $by = $opt->{by};
	if ( !defined($by) || $by eq '' ) {
		$by = getlogin || getpwuid($<) || 'unknown';
	}

	my $results = $lilith->escalate(
		table        => $opt->{t},
		id           => $id[0],
		target_ids   => $target_ids,
		note         => $opt->{note},
		requested_by => $by,
	);

	my $failed = scalar( grep { $_->{status} ne 'sent' } @{$results} );

	if ( $opt->{output} eq 'json' ) {
		$self->print_json( $results, $opt->{pretty} );
		exit( $failed ? 1 : 0 );
	}

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

	exit( $failed ? 1 : 0 );
} ## end sub execute

1;
