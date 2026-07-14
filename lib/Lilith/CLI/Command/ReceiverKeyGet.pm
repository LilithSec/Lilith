package Lilith::CLI::Command::ReceiverKeyGet;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( receiver_key_lookup );

sub command_names { 'receiver_key_get' }

sub abstract { 'show a receiver API key' }

sub usage_desc { '%c receiver_key_get %o' }

sub opt_spec {
	return (
		[ 'id=s',   'the receiver API key ID' ],
		[ 'name=s', 'the receiver API key name' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $key = receiver_key_lookup( $self->lilith, $opt->{id}, $opt->{name} );

	$self->print_json( $key, $opt->{pretty} );

	return;
}

1;
