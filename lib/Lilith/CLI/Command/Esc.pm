# esc -- escalate one event to one or more escalation targets by hand, the CLI
# counterpart to the web event view's Escalate button. Never gated by the
# escalation_enable options: those exist for the unauthenticated web frontend,
# and the CLI already holds the database credentials.
#
# --to takes target IDs or names, comma separated. --by records who asked,
# defaulting to the invoking user. Every attempt lands in the escalations table
# whether it succeeded or not.
#
# Exits non-zero when any target failed, so a script can tell.
#
#     lilith esc --id 42 --to soc-hook,mail-oncall --note 'C2 traffic'
package Lilith::CLI::Command::Esc;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( esc_resolve_targets );

sub abstract { 'escalate a event to one or more escalation targets' }

sub usage_desc { '%c esc %o' }

sub opt_spec {
	my ($class) = @_;
	return (
		[ 't=s',    'table to operate on', { default => 'suricata' } ],
		[ 'id=s',   'the row ID of the event to escalate' ],
		[ 'to=s',   'comma separated escalation target IDs or names' ],
		[ 'note=s', 'a optional note to record with the escalation' ],
		[ 'by=s',   'who requested the escalation' ],
		$class->output_opt_spec,
	);
} ## end sub opt_spec

# Refuse the run when --id was not given.
#
# --to is not checked here: an escalation with no targets resolves to an empty
# list and is reported as such, which is different from not naming an event at
# all.
#
# Args:
#
#   - $opt :: the parsed options. Only --id is looked at.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful when the run may proceed; otherwise calls
# usage_error, which prints the usage and exits non-zero.
sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) ) {
		$self->usage_error('--id is required for escalating a event');
	}

	return;
}

# Resolve the targets, escalate the event to each, and render the results.
#
# --by defaults to the invoking user rather than a fixed string, so the audit
# trail records who actually asked. getlogin is tried first and the passwd
# entry second, since neither is reliable alone -- under a service manager or a
# bare container both can fail, hence the final 'unknown'.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them. --to is a
#     comma separated list of target IDs or names.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: does not return. Renders a row per target -- its name, whether the
# send succeeded, the escalation ID recorded, and any error -- then exits 1
# when any target failed and 0 otherwise. Every attempt is recorded in the
# escalations table either way.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;

	my $target_ids = esc_resolve_targets( $lilith, $opt->{to} );

	my $by = $opt->{by};
	if ( !defined($by) || $by eq '' ) {
		$by = getlogin || getpwuid($<) || 'unknown';
	}

	my $results = $lilith->escalate(
		table        => $opt->{t},
		id           => $opt->{id},
		target_ids   => $target_ids,
		note         => $opt->{note},
		requested_by => $by,
	);

	my $failed = scalar( grep { $_->{status} ne 'sent' } @{$results} );

	$self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( $results, $opt->{pretty} ) },
		table => sub {
			my $tb = $self->table( 'Target', 'Status', 'Escalation ID', 'Error' );
			my @td;
			foreach my $result ( @{$results} ) {
				push(
					@td,
					[
						defined( $result->{target_name} )
						? $result->{target_name}
						: ( 'id ' . $result->{target_id} ),
						$result->{status},
						defined( $result->{escalation_id} ) ? $result->{escalation_id} : '',
						defined( $result->{error} )         ? $result->{error}         : '',
					]
				);
			} ## end foreach my $result ( @{$results} )
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);

	exit( $failed ? 1 : 0 );
} ## end sub execute

1;
