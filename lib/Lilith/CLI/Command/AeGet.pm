package Lilith::CLI::Command::AeGet;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use JSON ();

sub command_names { 'ae_get' }

sub abstract { 'print a single auto escalation rule as JSON' }

sub usage_desc { '%c ae_get %o' }

sub opt_spec {
	return ( [ 'id=s', 'the auto escalation rule ID' ], [ 'pretty', 'pretty print the JSON' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for fetching a auto escalation rule');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rule = $self->lilith->auto_escalation_get( $opt->{id} );

	# ae_get has always emitted canonical JSON, pretty or not
	my $json = JSON->new;
	$json->canonical(1);
	if ( $opt->{pretty} ) {
		$json->pretty(1);
	}
	print $json->encode($rule);
	if ( !$opt->{pretty} ) {
		print "\n";
	}

	return;
} ## end sub execute

1;
