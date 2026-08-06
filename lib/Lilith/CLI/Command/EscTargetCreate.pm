# esc_target_create -- create an escalation target: a name, a type
# (Webhook/Email/Syslog, or a site-local one), and the per-type config as
# repeated --set key=value items. esc_types lists the types and the fields each
# takes.
#
# A target created with --disable is stored but refuses sends until enabled,
# which is a way to stage one before it is live.
#
#     lilith esc_target_create --name soc-hook --type Webhook \
#         --set url=https://soc.example.net/hook --set apikey=xyz
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

# Parse the --set items into a config and create the target.
#
# An empty value is dropped rather than stored: on create there is nothing to
# remove, so an empty --set item can only have meant "leave it alone", and
# storing the empty string would shadow the type's own default.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them. --set is
#     repeatable, each item a key=value pair.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints 'created escalation target <id>'. A
# malformed --set item, an unknown type, or a duplicate name dies out of
# Lilith.
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
