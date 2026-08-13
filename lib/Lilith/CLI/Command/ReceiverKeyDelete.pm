# receiver_key_delete -- remove a receiver API key, found by --id or --name.
# The sensor holding it starts getting 401s at once. Rotating a key is this
# plus receiver_key_create: there is no re-issue, since the plaintext was never
# kept.
#
#     lilith receiver_key_delete --name sensor1
package Lilith::CLI::Command::ReceiverKeyDelete;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( receiver_key_lookup );

sub command_names { 'receiver_key_delete' }

sub abstract { 'delete a receiver API key' }

sub opt_spec {
	return ( [ 'id=s', 'the receiver API key ID' ], [ 'name=s', 'the receiver API key name' ], );
}

# Look the key up and delete it.
#
# Args:
#
#   - $opt :: the parsed options. --id names the key by ID, --name by name; one
#     or the other.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the ID and name of what it deleted. Dies
# out of the lookup when neither option was given or nothing matched.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = receiver_key_lookup( $lilith, $opt->{id}, $opt->{name} );

	$lilith->receiver_apikey_delete( $existing->{id} );

	print 'deleted receiver api key ' . $existing->{id} . ', "' . $existing->{name} . '"' . "\n";

	return;
} ## end sub execute

1;
