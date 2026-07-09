package Lilith::CLI::Command::AeList;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'ae_list' }

sub abstract { 'list the auto escalation rules' }

sub usage_desc { '%c ae_list %o' }

sub opt_spec {
	return (
		[ 'output=s', 'output type: table or json', { default => 'table' } ],
		[ 'pretty',   'pretty print the JSON' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rules = $self->lilith->auto_escalations;

	if ( $opt->{output} eq 'json' ) {
		$self->print_json( $rules, $opt->{pretty} );
		return;
	}

	my $tb = $self->table( 'ID', 'Name', 'Enabled', 'Priority', 'Stop', 'Tables', 'Matches', 'Description' );
	my @td;
	foreach my $rule ( @{$rules} ) {
		push(
			@td,
			[
				$rule->{id},
				$rule->{name},
				$rule->{enabled} ? 'yes' : 'no',
				$rule->{priority},
				$rule->{stop_on_match} ? 'yes' : 'no',
				join( ',', @{ $rule->{tables} } ),
				$rule->{match_count},
				defined( $rule->{description} ) ? $rule->{description} : '',
			]
		);
	} ## end foreach my $rule ( @{$rules} )
	$tb->add_rows( \@td );
	print $tb->draw;

	return;
} ## end sub execute

1;
