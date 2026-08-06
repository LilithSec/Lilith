# receiver_key_update -- change a receiver API key, found by --id or --name:
# rename it, enable or disable it, or re-scope it. The key itself cannot be
# changed; delete and create instead.
#
# --ip and --instance replace an axis outright rather than adding to it, and
# --clear-ips/--clear-instances widen an axis back to unrestricted. Disabling
# is the gentler alternative to deleting, since it can be undone.
#
#     lilith receiver_key_update --name sensor1 --ip 10.1.0.0/16
#     lilith receiver_key_update --name sensor1 --disable
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

# Refuse the run when --enable and --disable were both given.
#
# Args:
#
#   - $opt :: the parsed options. Only the --enable/--disable pair is looked
#     at; the key is identified in execute.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful when the run may proceed; otherwise calls
# usage_error, which prints the usage and exits non-zero.
sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( $opt->{enable} && $opt->{disable} ) {
		$self->usage_error('--enable and --disable are mutually exclusive');
	}

	return;
}

# Look the key up, build the update from whichever options were given, and
# apply it.
#
# A scope axis is replaced outright rather than added to, so re-scoping a key
# means stating the whole list. --clear-* wins over --ip/--instance for the
# same axis: clearing is the more drastic of the two, so asking for both is
# read as meaning it.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them. --id or
#     --name identifies the key; --rename is what changes it.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the ID and name of the key it updated.
# Dies out of the lookup when nothing matched.
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
