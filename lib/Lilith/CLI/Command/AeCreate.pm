package Lilith::CLI::Command::AeCreate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( ae_read_rule );

sub command_names { 'ae_create' }

sub abstract { 'create a auto escalation rule' }

sub usage_desc { '%c ae_create %o' }

sub opt_spec {
	return (
		[ 'name=s',     'the name for the new rule', { required => 1 } ],
		[ 'rule=s',     'the rule as a JSON object, or @file' ],
		[ 'tables=s',   'comma separated alert tables the rule applies to' ],
		[ 'priority=s', 'evaluation order, lower first' ],
		[ 'stop',       'set stop_on_match' ],
		[ 'desc=s',     'a optional description' ],
		[ 'disable',    'create the rule disabled' ],
	);
} ## end sub opt_spec

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rule = ae_read_rule( $opt->{rule} );

	my @tables = grep { $_ ne '' } split( /\s*,\s*/, defined( $opt->{tables} ) ? $opt->{tables} : '' );

	my $new_id = $self->lilith->auto_escalation_create(
		name          => $opt->{name},
		rule          => $rule,
		tables        => ( @tables ? \@tables : undef ),
		priority      => $opt->{priority},
		stop_on_match => ( $opt->{stop} ? 1 : 0 ),
		description   => $opt->{desc},
		enabled       => ( $opt->{disable} ? 0 : 1 ),
	);

	print 'created auto escalation ' . $new_id . "\n";

	return;
} ## end sub execute

1;
