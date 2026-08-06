# esc_targets -- list the configured escalation targets: ID, name, type,
# whether enabled, description, and when last changed. The table output leaves
# the per-type config out, since it holds secrets; --output json includes it.
#
#     lilith esc_targets
package Lilith::CLI::Command::EscTargets;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'esc_targets' }

sub abstract { 'list the configured escalation targets' }

sub usage_desc { '%c esc_targets %o' }

sub opt_spec {
	my ($class) = @_;
	return $class->output_opt_spec;
}

# Fetch every target and render it.
#
# The table output leaves the per-type config out on purpose -- it holds
# webhook keys and SMTP passwords -- so listing targets over someone's shoulder
# is safe. --output json includes it.
#
# Args:
#
#   - $opt :: the parsed options -- just the shared --output/--pretty pair.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $targets = $self->lilith->escalation_targets;

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( $targets, $opt->{pretty} ) },
		table => sub {
			my $tb = $self->table( 'ID', 'Name', 'Type', 'Enabled', 'Description', 'Updated' );
			my @td;
			foreach my $item ( @{$targets} ) {
				push(
					@td,
					[
						$item->{id},
						$item->{name},
						$item->{type},
						( $item->{enabled} ? '1' : '0' ),
						defined( $item->{description} ) ? $item->{description} : '',
						defined( $item->{updated} )     ? $item->{updated}     : '',
					]
				);
			} ## end foreach my $item ( @{$targets} )
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);
} ## end sub execute

1;
