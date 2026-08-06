# receiver_key_list -- list the receiver API keys: ID, name, whether enabled,
# the IP and instance scopes, when each was last used, and its description. The
# keys themselves are not shown and cannot be. Last used is the quickest way to
# spot a sensor that has stopped pushing, or a key nothing uses any more.
#
#     lilith receiver_key_list
package Lilith::CLI::Command::ReceiverKeyList;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'receiver_key_list' }

sub abstract { 'list the receiver API keys' }

sub usage_desc { '%c receiver_key_list %o' }

sub opt_spec {
	my ($class) = @_;
	return $class->output_opt_spec;
}

# A Postgres array column comes back as an array ref; render it for the table,
# using 'any' for the unrestricted (NULL/empty) case. Plain function, not a
# method.
#
# 'any' rather than a blank cell because an unset axis means unrestricted, and a
# blank would read as "nothing allowed" -- the opposite.
#
# Args:
#
#   - $list :: the column as read back -- an array ref of scope entries, or
#     undef/[] when the axis is unrestricted.
#
# Returns: the entries joined with ', ' as a string, or 'any' when there is no
# restriction.
#
#     _scope( [ '10.0.0.0/8', '192.0.2.5/32' ] );    # '10.0.0.0/8, 192.0.2.5/32'
#     _scope(undef);                                 # 'any'
sub _scope {
	my ($list) = @_;
	return 'any' if ref $list ne 'ARRAY' || !@{$list};
	return join( ', ', @{$list} );
}

# Fetch every key and render it.
#
# Args:
#
#   - $opt :: the parsed options -- just the shared --output/--pretty pair.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned. With no keys created it
# prints an empty table or an empty array -- which is also the state in which
# the receiver refuses every request.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $keys = $self->lilith->receiver_apikeys;

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( $keys, $opt->{pretty} ) },
		table => sub {
			my $tb
				= $self->table( 'ID', 'Name', 'Enabled', 'Allowed IPs', 'Allowed Instances', 'Last Used',
					'Description' );
			my @td;
			foreach my $item ( @{$keys} ) {
				push(
					@td,
					[
						$item->{id},
						$item->{name},
						( $item->{enabled} ? '1' : '0' ),
						_scope( $item->{allowed_ips} ),
						_scope( $item->{allowed_instances} ),
						defined( $item->{last_used} )   ? $item->{last_used}   : '',
						defined( $item->{description} ) ? $item->{description} : '',
					]
				);
			} ## end foreach my $item ( @{$keys} )
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);
} ## end sub execute

1;
