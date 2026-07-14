package Lilith::CLI::Command::ReceiverKeyDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( receiver_key_lookup );

sub command_names { 'receiver_key_delete' }

sub abstract { 'delete a receiver API key' }

sub usage_desc { '%c receiver_key_delete %o' }

sub opt_spec {
	return ( [ 'id=s', 'the receiver API key ID' ], [ 'name=s', 'the receiver API key name' ], );
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = receiver_key_lookup( $lilith, $opt->{id}, $opt->{name} );

	$lilith->receiver_apikey_delete( $existing->{id} );

	print 'deleted receiver api key ' . $existing->{id} . ', "' . $existing->{name} . '"' . "\n";

	return;
} ## end sub execute

1;
