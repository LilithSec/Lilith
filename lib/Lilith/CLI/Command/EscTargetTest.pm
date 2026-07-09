package Lilith::CLI::Command::EscTargetTest;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target );

sub command_names { 'esc_target_test' }

sub abstract { 'send a synthetic test event to a escalation target' }

sub usage_desc { '%c esc_target_test %o' }

sub opt_spec {
	return (
		[ 'tid=s',  'the escalation target ID' ],
		[ 'name=s', 'the escalation target name' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = esc_lookup_target( $lilith, $opt->{tid}, $opt->{name} );

	my $payload = $lilith->escalation_test( id => $existing->{id} );

	$self->print_json( $payload, $opt->{pretty} );

	return;
} ## end sub execute

1;
