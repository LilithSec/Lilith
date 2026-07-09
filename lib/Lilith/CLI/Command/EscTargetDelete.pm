package Lilith::CLI::Command::EscTargetDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target );

sub command_names { 'esc_target_delete' }

sub abstract { 'delete a escalation target' }

sub usage_desc { '%c esc_target_delete %o' }

sub opt_spec {
	return ( [ 'tid=s', 'the escalation target ID' ], [ 'name=s', 'the escalation target name' ], );
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = esc_lookup_target( $lilith, $opt->{tid}, $opt->{name} );

	$lilith->escalation_target_delete( $existing->{id} );

	print 'deleted escalation target ' . $existing->{id} . ', "' . $existing->{name} . '"' . "\n";

	return;
} ## end sub execute

1;
