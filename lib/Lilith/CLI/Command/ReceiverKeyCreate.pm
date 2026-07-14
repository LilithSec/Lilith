package Lilith::CLI::Command::ReceiverKeyCreate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'receiver_key_create' }

sub abstract { 'create a receiver API key' }

sub usage_desc { '%c receiver_key_create %o' }

sub opt_spec {
	return (
		[ 'name=s',      'the name for the new key', { required => 1 } ],
		[ 'ip=s@',       'an allowed IP or CIDR subnet (repeatable); omit for any' ],
		[ 'instance=s@', 'an allowed instance name or glob e.g. foo-* (repeatable); omit for any' ],
		[ 'desc=s',      'an optional description' ],
		[ 'disable',     'create the key disabled' ],
	);
}

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
