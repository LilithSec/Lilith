package Lilith::CLI::Command::AeUpdate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CLI::Util qw( ae_read_rule );

sub command_names { 'ae_update' }

sub abstract { 'update a auto escalation rule' }

sub usage_desc { '%c ae_update %o' }

sub opt_spec {
	return (
		[ 'id=s@',      'the auto escalation rule ID' ],
		[ 'name=s',     'the rule name' ],
		[ 'rule=s',     'the rule as a JSON object, or @file' ],
		[ 'tables=s',   'comma separated alert tables the rule applies to' ],
		[ 'priority=s', 'evaluation order, lower first' ],
		[ 'stop',       'set stop_on_match' ],
		[ 'desc=s',     'a optional description' ],
		[ 'enable',     'enable the rule' ],
		[ 'disable',    'disable the rule' ],
	);
} ## end sub opt_spec

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	my @id = @{ $opt->{id} // [] };
	if ( !defined( $id[0] ) ) {
		$self->usage_error('--id is required for updating a auto escalation rule');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my @id = @{ $opt->{id} // [] };

	my %update = ( id => $id[0] );

	if ( defined( $opt->{name} ) && $opt->{name} ne '' ) {
		$update{name} = $opt->{name};
	}
	if ( defined( $opt->{rule} ) && $opt->{rule} ne '' ) {
		$update{rule} = ae_read_rule( $opt->{rule} );
	}
	if ( defined( $opt->{tables} ) ) {
		my @tables = grep { $_ ne '' } split( /\s*,\s*/, $opt->{tables} );
		$update{tables} = \@tables;
	}
	if ( defined( $opt->{priority} ) ) {
		$update{priority} = $opt->{priority};
	}
	if ( $opt->{stop} ) {
		$update{stop_on_match} = 1;
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

	$self->lilith->auto_escalation_update(%update);

	print 'updated auto escalation ' . $id[0] . "\n";

	return;
} ## end sub execute

1;
