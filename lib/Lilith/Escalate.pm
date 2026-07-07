package Lilith::Escalate;

use 5.006;
use strict;
use warnings;
use JSON ();

=head1 NAME

Lilith::Escalate - Pluggable escalation type handling for Lilith.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Lilith::Escalate;

    # every installed type under Lilith::Escalate::Type::*
    my $types = Lilith::Escalate->types;

    # resolve a type name to its module, loading it if needed
    my $module = Lilith::Escalate->type_module('Webhook');

    $module->check_config( \%config );
    my $payload = $module->escalate(
        event  => \%event,
        table  => 'suricata',
        config => \%config,
        note   => 'looks nasty',
    );

=head1 DESCRIPTION

Escalation types are modules under the C<Lilith::Escalate::Type::>
namespace. A type module is expected to provide the following class
methods.

    - description :: A one line description of the type.

    - config_fields :: A array ref of hash refs describing the config
      items the type takes. Each item has the keys 'name', 'label',
      'type', and optionally 'required' and 'default'. The web UI
      renders the config form for a target from this, so new types
      require no UI changes. The supported types are:

        - string  :: a single line of text.
        - secret  :: like string, but write only; never returned to
          the browser and kept as stored when left blank on a update.
        - integer :: a string constrained to digits in the UI.
        - boolean :: a checkbox, stored as 1 or 0.
        - enum    :: a drop down. The item also carries an 'options'
          array ref of the allowed string values.
        - list    :: a repeatable set of rows, stored as a array ref.
          With no 'columns' it is a list of strings; with a 'columns'
          array ref of { name, placeholder, pattern } descriptors each
          row is a hash ref keyed by the column names.

    - check_config :: Validates a config hash ref for the type,
      dieing with a message if it is not usable.

    - escalate :: Performs the escalation. Takes the args 'event'
      (the alert row hash ref, with 'raw' decoded when possible),
      'table' (short table type), 'config' (the target's config hash
      ref), and optionally 'note', 'requested_by', 'target_name',
      and 'test'. Returns a hash ref of what was actually sent,
      which is stored as the escalation's 'raw'. Secrets must not be
      included in the returned payload. Dies on failure.

Additional namespaces to search may be passed to the methods below,
allowing sites to ship their own types outside of the dist.

=head1 METHODS

=head2 namespaces

Returns the namespaces to search for type modules as a array ref. The
optional arg is a array ref of additional namespaces, searched after
the default C<Lilith::Escalate::Type>.

    my $namespaces = Lilith::Escalate->namespaces( ['My::Escalate'] );

=cut

sub namespaces {
	my ( $class, $extra ) = @_;

	my @namespaces = ('Lilith::Escalate::Type');
	if ( ref $extra eq 'ARRAY' ) {
		push( @namespaces, grep { defined($_) && /^[A-Za-z][A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)*$/ } @{$extra} );
	}

	return \@namespaces;
} ## end sub namespaces

=head2 type_module

Resolves a type name to its module, requiring it if not already
loaded, and returns the module name. The optional second arg is a
array ref of additional namespaces to search. Dies if the name is not
a valid type name or no usable module is found.

    my $module = Lilith::Escalate->type_module( 'Webhook', \@extra_namespaces );

=cut

sub type_module {
	my ( $class, $type, $extra ) = @_;

	if ( !defined($type) || $type eq '' ) {
		die("no escalation type specified\n");
	}

	# the type name becomes part of a module name, so keep it to a single
	# clean component
	if ( $type !~ /^[A-Za-z][A-Za-z0-9_]*$/ ) {
		die( '"' . $type . '" is not a valid escalation type name' . "\n" );
	}

	my @errors;
	foreach my $namespace ( @{ $class->namespaces($extra) } ) {
		my $module = $namespace . '::' . $type;
		my $file   = $module;
		$file =~ s/\:\:/\//g;
		$file = $file . '.pm';

		if ( !$INC{$file} ) {
			eval { require $file; };
			if ($@) {
				push( @errors, $@ );
				next;
			}
		}

		if ( $module->can('escalate') ) {
			return $module;
		}
		push( @errors, $module . ' does not implement escalate' );
	} ## end foreach my $namespace ( @{ $class->namespaces($extra...)})

	die( 'unknown escalation type "' . $type . '"' . ( @errors ? ': ' . join( '; ', @errors ) : '' ) . "\n" );
} ## end sub type_module

=head2 types

Returns a array ref of the names of every type module found under the
searched namespaces, sorted. The optional arg is a array ref of
additional namespaces to search.

    my $types = Lilith::Escalate->types;

=cut

sub types {
	my ( $class, $extra ) = @_;

	my %found;
	foreach my $namespace ( @{ $class->namespaces($extra) } ) {
		my $fragment = $namespace;
		$fragment =~ s/\:\:/\//g;

		foreach my $inc_dir (@INC) {
			next if ref $inc_dir;
			my $dir = $inc_dir . '/' . $fragment;
			next unless -d $dir;

			opendir( my $dh, $dir ) or next;
			foreach my $entry ( readdir($dh) ) {
				if ( $entry =~ /^([A-Za-z][A-Za-z0-9_]*)\.pm$/ ) {
					$found{$1} = 1;
				}
			}
			closedir($dh);
		} ## end foreach my $inc_dir (@INC)
	} ## end foreach my $namespace ( @{ $class->namespaces($extra...)})

	my @types = sort( keys(%found) );
	return \@types;
} ## end sub types

=head2 type_info

Returns a hash ref describing a type: its name, description, and
config fields. The optional second arg is a array ref of additional
namespaces to search. Dies if the type can not be resolved.

    my $info = Lilith::Escalate->type_info('Webhook');
    # { type => 'Webhook', description => '...', fields => [ ... ] }

=cut

sub type_info {
	my ( $class, $type, $extra ) = @_;

	my $module = $class->type_module( $type, $extra );

	return {
		type        => $type,
		description => $module->can('description')   ? $module->description   : '',
		fields      => $module->can('config_fields') ? $module->config_fields : [],
	};
} ## end sub type_info

=head2 event_summary

Builds a multi-line plain text summary of an event for use in
escalation payloads, one "key: value" line per set field, followed by
the pretty printed raw JSON when the raw is a hash ref.

    my $summary = Lilith::Escalate->event_summary( $table, \%event );

=cut

sub event_summary {
	my ( $class, $table, $event ) = @_;

	my $summary = 'table: ' . ( defined($table) ? $table : '' ) . "\n";
	foreach my $key (
		qw( id event_id instance host instance_host timestamp src_ip src_port dest_ip dest_port
		proto app_proto classification signature malscore target )
		)
	{
		if ( defined( $event->{$key} ) && !ref( $event->{$key} ) ) {
			$summary = $summary . $key . ': ' . $event->{$key} . "\n";
		}
	}

	if ( ref $event->{raw} eq 'HASH' ) {
		my $pretty;
		eval { $pretty = JSON->new->pretty->canonical->encode( $event->{raw} ); };
		if ( defined($pretty) ) {
			$summary = $summary . "\nraw:\n" . $pretty;
		}
	}

	return $summary;
} ## end sub event_summary

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
