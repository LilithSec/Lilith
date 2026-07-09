package Lilith::CLI::Command::EscTargets;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'esc_targets' }

sub abstract { 'list the configured escalation targets' }

sub usage_desc { '%c esc_targets %o' }

sub opt_spec {
	return (
		[ 'output=s', 'output type: table or json', { default => 'table' } ],
		[ 'pretty',   'pretty print the JSON' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $targets = $self->lilith->escalation_targets;

	if ( $opt->{output} eq 'json' ) {
		$self->print_json( $targets, $opt->{pretty} );
		return;
	}

	my $tb = $self->table( 'ID', 'Name', 'Type', 'Enabled', 'Description', 'Updated' );
	my @td;
	foreach my $item ( @{$targets} ) {
		push(
			@td,
			[
				$item->{id}, $item->{name}, $item->{type},
				( $item->{enabled} ? '1' : '0' ),
				defined( $item->{description} ) ? $item->{description} : '',
				defined( $item->{updated} )     ? $item->{updated}     : '',
			]
		);
	} ## end foreach my $item ( @{$targets} )
	$tb->add_rows( \@td );
	print $tb->draw;

	return;
} ## end sub execute

1;
