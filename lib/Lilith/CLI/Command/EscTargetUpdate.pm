# esc_target_update -- change one escalation target, found by --tid or --name.
#
# --set items merge over the current config rather than replacing it, so one
# field can be changed without restating the rest; an empty value removes the
# key, letting the type's default apply again. When the target was found by
# --tid, --name is read as the new name rather than as a lookup.
#
#     lilith esc_target_update --name soc-hook --set url=https://new.example.net/hook
#     lilith esc_target_update --tid 3 --name soc-hook-old --disable
package Lilith::CLI::Command::EscTargetUpdate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_lookup_target esc_parse_set );

sub command_names { 'esc_target_update' }

sub abstract { 'update an escalation target' }

sub opt_spec {
	return (
		[ 'tid=s',   'the escalation target ID' ],
		[ 'name=s',  'the target name (or, with --tid, the new name)' ],
		[ 'set=s@',  'a config item, key=value (empty value removes the key)' ],
		[ 'desc=s',  'an optional description' ],
		[ 'enable',  'enable the target' ],
		[ 'disable', 'disable the target' ],
	);
} ## end sub opt_spec

# Refuse the run when --enable and --disable were both given, since that is a
# contradiction rather than a preference.
#
# Args:
#
#   - $opt :: the parsed options. Only the --enable/--disable pair is looked
#     at; the target is identified in execute.
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

# Look the target up, merge the changes over what it already has, and save it.
#
# The config is merged rather than replaced so one field can be changed without
# restating the credentials alongside it, and an empty value removes its key so
# the type's default applies again. When --tid identified the target, --name is
# free to mean the new name.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints 'updated escalation target <id>'. Dies
# out of the lookup when nothing matched, or out of Lilith when the update was
# refused.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;

	my $existing = esc_lookup_target( $lilith, $opt->{tid}, $opt->{name} );

	my %update = ( id => $existing->{id} );

	# --set items are merged over the current config; an empty value removes
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
