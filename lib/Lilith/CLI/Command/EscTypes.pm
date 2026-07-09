package Lilith::CLI::Command::EscTypes;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'esc_types' }

sub abstract { 'list the available escalation types and their config fields' }

sub usage_desc { '%c esc_types %o' }

sub opt_spec {
	return (
		[ 'output=s', 'output type: table or json', { default => 'table' } ],
		[ 'pretty',   'pretty print the JSON' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;
	my $types  = $lilith->escalation_types;

	if ( $opt->{output} eq 'json' ) {
		my @infos = map { $lilith->escalation_type_info($_) } @{$types};
		$self->print_json( \@infos, $opt->{pretty} );
		return;
	}

	foreach my $type ( @{$types} ) {
		my $info = $lilith->escalation_type_info($type);
		print $type . ' :: ' . $info->{description} . "\n";

		my $tb = $self->table( 'Field', 'Label', 'Type', 'Req', 'Default' );
		my @td;
		foreach my $field ( @{ $info->{fields} } ) {
			push(
				@td,
				[
					$field->{name},
					defined( $field->{label} )   ? $field->{label}   : '',
					defined( $field->{type} )    ? $field->{type}    : '',
					$field->{required}           ? '1'               : '0',
					defined( $field->{default} ) ? $field->{default} : '',
				]
			);
		} ## end foreach my $field ( @{ $info->{fields} } )
		$tb->add_rows( \@td );
		print $tb->draw . "\n";
	} ## end foreach my $type ( @{$types} )

	return;
} ## end sub execute

1;
