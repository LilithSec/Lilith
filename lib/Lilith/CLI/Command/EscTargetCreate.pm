package Lilith::CLI::Command::EscTargetCreate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_parse_set );

sub command_names { 'esc_target_create' }

sub abstract { 'create a escalation target' }

sub usage_desc { '%c esc_target_create %o' }

sub opt_spec {
	return (
		[ 'name=s',  'the name for the new target', { required => 1 } ],
		[ 'type=s',  'the escalation type',         { required => 1 } ],
		[ 'set=s@',  'a config item, key=value' ],
		[ 'desc=s',  'a optional description' ],
		[ 'disable', 'create the target disabled' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $config = esc_parse_set( @{ $opt->{set} // [] } );

	# empty values make no sense on create; drop them so type defaults apply
	foreach my $key ( keys( %{$config} ) ) {
		if ( $config->{$key} eq '' ) {
			delete( $config->{$key} );
		}
	}

	my $new_id = $self->lilith->escalation_target_create(
		name        => $opt->{name},
		type        => $opt->{type},
		config      => $config,
		description => $opt->{desc},
		enabled     => ( $opt->{disable} ? 0 : 1 ),
	);

	print 'created escalation target ' . $new_id . "\n";

	return;
} ## end sub execute

1;
