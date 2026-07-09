package Lilith::CLI::Command::EscTargetUpdate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target esc_parse_set );

sub command_names { 'esc_target_update' }

sub abstract { 'update a escalation target' }

sub usage_desc { '%c esc_target_update %o' }

sub opt_spec {
	return (
		[ 'tid=s',   'the escalation target ID' ],
		[ 'name=s',  'the target name (or, with --tid, the new name)' ],
		[ 'set=s@',  'a config item, key=value (empty value removes the key)' ],
		[ 'desc=s',  'a optional description' ],
		[ 'enable',  'enable the target' ],
		[ 'disable', 'disable the target' ],
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

	my $lilith = $self->lilith;

	my $existing = esc_lookup_target( $lilith, $opt->{tid}, $opt->{name} );

	my %update = ( id => $existing->{id} );

	# --set items are merged over the current config; a empty value removes
	# that key so the type default applies again
	if ( $opt->{set} && @{ $opt->{set} } ) {
		my $set    = esc_parse_set( @{ $opt->{set} } );
		my $config = { %{ $existing->{config} } };
		foreach my $key ( keys( %{$set} ) ) {
			if ( $set->{$key} eq '' ) {
				delete( $config->{$key} );
			} else {
				$config->{$key} = $set->{$key};
			}
		}
		$update{config} = $config;
	} ## end if ( $opt->{set} && @{ $opt->{set} } )

	# when picked via --tid, --name is the new name
	if ( defined( $opt->{tid} ) && $opt->{tid} ne '' && defined( $opt->{name} ) && $opt->{name} ne '' ) {
		$update{name} = $opt->{name};
	}
	if ( defined( $opt->{desc} ) ) {
		$update{description} = $opt->{desc};
	}
	if ( $opt->{enable} ) {
		$update{enabled} = 1;
	}
	if ( $opt->{disable} ) {
		$update{enabled} = 0;
	}

	$lilith->escalation_target_update(%update);

	print 'updated escalation target ' . $existing->{id} . "\n";

	return;
} ## end sub execute

1;
