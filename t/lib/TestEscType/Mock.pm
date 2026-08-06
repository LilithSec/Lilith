package TestEscType::Mock;

# A minimal escalation type living outside the Lilith::Escalate::Type
# namespace, used by t/escalate.t to prove site-supplied types work via
# escalation_type_namespaces.

use strict;
use warnings;

our $VERSION = '0.0.1';

# The one line description of this type, shown by esc_types and by the web
# UI's target form.
#
# Args: none.
#
# Returns: the description as a string.
sub description {
	return 'mock escalation type for testing';
}

# The config fields this type takes, in the same shape a real
# Lilith::Escalate::Type module returns. One field is enough to prove the
# form generation and the check_config path.
#
# Args: none.
#
# Returns: an array ref of field hash refs, each with name, label, type, and
# required -- here a single required string field named 'flag'.
sub config_fields {
	return [ { name => 'flag', label => 'Flag', type => 'string', required => 1 }, ];
}

# Check a target's stored config before it is used, exactly as a real type
# would.
#
# Args:
#
#   - $config :: the target's per-type config as a hash ref, expected to carry
#     a non-empty 'flag'.
#
# Returns: 1 when the config is usable. Dies with 'config is not a hash ref'
# or '"flag" is required' otherwise, so the tests can assert on both.
sub check_config {
	my ( $class, $config ) = @_;
	die "config is not a hash ref\n" unless ref $config eq 'HASH';
	die "\"flag\" is required\n"     unless defined $config->{flag} && $config->{flag} ne '';
	return 1;
}

# Stand in for a real send: check the config, then hand back what would have
# gone out instead of putting it anywhere.
#
# Args:
#
#   - config :: the target's per-type config, as check_config expects it.
#   - table :: the short table type the event came from, e.g. 'suricata'.
#   - event :: the alert row as a hash ref; only its id is used.
#   - note :: the note recorded with the escalation, or undef.
#
# Returns: a hash ref of { flag, table, id, note } echoing what it was given,
# which is what the escalation is recorded as having sent -- so a test can
# assert the type received what it should have.
sub escalate {
	my ( $class, %args ) = @_;
	$class->check_config( $args{config} );
	return {
		flag  => $args{config}{flag},
		table => $args{table},
		id    => $args{event}{id},
		note  => $args{note},
	};
} ## end sub escalate

1;
