# receiver_key_create -- mint a bearer key for the EVE receiver and print it
# once. Only the SHA-256 is stored, so the printed key cannot be recovered
# afterwards; losing it means creating another.
#
# --ip and --instance are each repeatable and each optional, and an axis left
# unset is unrestricted. Give each sensor its own key so one can be revoked
# without disturbing the rest.
#
#     lilith receiver_key_create --name sensor1 \
#         --ip 10.0.0.0/8 --instance 'foo-*'
package Lilith::CLI::Command::ReceiverKeyCreate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'receiver_key_create' }

sub abstract { 'create a receiver API key' }

sub opt_spec {
	return (
		[ 'name=s',      'the name for the new key', { required => 1 } ],
		[ 'ip=s@',       'an allowed IP or CIDR subnet (repeatable); omit for any' ],
		[ 'instance=s@', 'an allowed instance name or glob e.g. foo-* (repeatable); omit for any' ],
		[ 'desc=s',      'an optional description' ],
		[ 'disable',     'create the key disabled' ],
	);
}

# Create the key and print it, once.
#
# The plaintext is printed here and nowhere else: only its SHA-256 was stored,
# so there is no command that can show it again. Hence the warning line.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them. --ip and
#     --instance are each repeatable, and an axis left unset is unrestricted.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the new key's ID, the key itself, and a
# note that it cannot be shown again. A duplicate name or a malformed CIDR dies
# out of Lilith.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $result = $self->lilith->receiver_apikey_create(
		name              => $opt->{name},
		allowed_ips       => $opt->{ip},
		allowed_instances => $opt->{instance},
		description       => $opt->{desc},
		enabled           => ( $opt->{disable} ? 0 : 1 ),
	);

	print 'created receiver api key ' . $result->{id} . "\n";
	print 'apikey: ' . $result->{apikey} . "\n";
	print "store this now -- only its hash is kept and it cannot be shown again.\n";

	return;
} ## end sub execute

1;
