package Lilith::CLI::Command::ReceiverKeyUpdate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( receiver_key_lookup );

sub command_names { 'receiver_key_update' }

sub abstract { 'update a receiver API key' }

sub usage_desc { '%c receiver_key_update %o' }

sub opt_spec {
	return (
		[ 'id=s',            'the receiver API key ID' ],
		[ 'name=s',          'the receiver API key name (for lookup)' ],
		[ 'rename=s',        'a new name for the key' ],
		[ 'enable',          'enable the key' ],
		[ 'disable',         'disable the key' ],
		[ 'ip=s@',           'replace the allowed IPs/subnets with these (repeatable)' ],
		[ 'clear-ips',       'clear the IP restriction (allow any)' ],
		[ 'instance=s@',     'replace the allowed instances with these globs (repeatable)' ],
		[ 'clear-instances', 'clear the instance restriction (allow any)' ],
		[ 'desc=s',          'a new description' ],
	);
} ## end sub opt_spec

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( $opt->{enable} && $opt->{disable} ) {
		$self->usage_error('--enable and --disable are mutually exclusive');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $existing = receiver_key_lookup( $lilith, $opt->{id}, $opt->{name} );

	my %update = ( id => $existing->{id} );
	$update{name}        = $opt->{rename} if defined $opt->{rename};
	$update{description} = $opt->{desc}   if defined $opt->{desc};
	$update{enabled}     = 1              if $opt->{enable};
	$update{enabled}     = 0              if $opt->{disable};

	# --clear-* wins over --ip/--instance for the same axis; an explicit empty
	# list clears the restriction.
	if    ( $opt->{clear_ips} ) { $update{allowed_ips} = []; }
	elsif ( $opt->{ip} )        { $update{allowed_ips} = $opt->{ip}; }

	if    ( $opt->{clear_instances} ) { $update{allowed_instances} = []; }
	elsif ( $opt->{instance} )        { $update{allowed_instances} = $opt->{instance}; }

	$lilith->receiver_apikey_update(%update);

	print 'updated receiver api key ' . $existing->{id} . ', "' . $existing->{name} . '"' . "\n";

	return;
} ## end sub execute

1;
