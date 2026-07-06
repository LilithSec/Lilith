package TestEscType::Mock;

# A minimal escalation type living outside the Lilith::Escalate::Type
# namespace, used by t/escalate.t to prove site-supplied types work via
# escalation_type_namespaces.

use strict;
use warnings;

our $VERSION = '0.0.1';

sub description {
	return 'mock escalation type for testing';
}

sub config_fields {
	return [ { name => 'flag', label => 'Flag', type => 'string', required => 1 }, ];
}

sub check_config {
	my ( $class, $config ) = @_;
	die "config is not a hash ref\n" unless ref $config eq 'HASH';
	die "\"flag\" is required\n" unless defined $config->{flag} && $config->{flag} ne '';
	return 1;
}

sub escalate {
	my ( $class, %args ) = @_;
	$class->check_config( $args{config} );
	return {
		flag  => $args{config}{flag},
		table => $args{table},
		id    => $args{event}{id},
		note  => $args{note},
	};
}

1;
