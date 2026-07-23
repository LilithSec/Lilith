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
# using 'any' for the unrestricted (NULL/empty) case.
sub _scope {
	my ($list) = @_;
	return 'any' if ref $list ne 'ARRAY' || !@{$list};
	return join( ', ', @{$list} );
}

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
