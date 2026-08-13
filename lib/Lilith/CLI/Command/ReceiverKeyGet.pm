# receiver_key_get -- print one receiver API key as JSON, found by --id or
# --name: its scopes, whether it is enabled, and when it was last used. The key
# itself is not shown and cannot be -- only its hash was stored.
#
#     lilith receiver_key_get --name sensor1 --pretty
package Lilith::CLI::Command::ReceiverKeyGet;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( receiver_key_lookup );

sub command_names { 'receiver_key_get' }

sub abstract { 'show a receiver API key' }

sub opt_spec {
	return (
		[ 'id=s',   'the receiver API key ID' ],
		[ 'name=s', 'the receiver API key name' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

# Look the key up and print it as JSON.
#
# Args:
#
#   - $opt :: the parsed options. --id names the key by ID, --name by name; one
#     or the other. --pretty indents the output.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the key's record as a JSON object --
# scopes, enabled flag, last use. The key itself is not among it. Dies out of
# the lookup when nothing matched.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $key = receiver_key_lookup( $self->lilith, $opt->{id}, $opt->{name} );

	$self->print_json( $key, $opt->{pretty} );

	return;
}

1;
