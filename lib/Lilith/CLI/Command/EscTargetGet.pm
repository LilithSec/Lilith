package Lilith::CLI::Command::EscTargetGet;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target );

sub command_names { 'esc_target_get' }

sub abstract { 'print a single escalation target as JSON' }

sub usage_desc { '%c esc_target_get %o' }

sub opt_spec {
	return (
		[ 'tid=s',  'the escalation target ID' ],
		[ 'name=s', 'the escalation target name' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $target = esc_lookup_target( $self->lilith, $opt->{tid}, $opt->{name} );

	$self->print_json( $target, $opt->{pretty} );

	return;
}

1;
