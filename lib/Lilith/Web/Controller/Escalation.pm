package Lilith::Web::Controller::Escalation;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::JSON   qw(to_json);
use Mojo::IOLoop ();
use JSON         qw(decode_json);

=head1 NAME

Lilith::Web::Controller::Escalation - Escalation controller for Lilith::Web.

=head1 DESCRIPTION

Management page and JSON API for the escalation system. Escalation
targets live in the escalation_targets SQL table; their 'type' selects
a L<Lilith::Escalate> type module and their 'config' is that module's
config. Every action 404s unless escalation_enable is set in the
config, as these endpoints can push data at outside services and
change target config.

Secret config fields (per the type's config_fields spec) are never
sent to the browser; they are returned masked as empty strings with
the field name listed in secrets_set, and a empty secret submitted on
a update means "keep the current value".

=cut

=head2 index

Renders the escalation target management page.

=cut

sub index {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $targets = [];
	my $types   = [];
	my $error;

	eval { $targets = $self->_masked_targets; };
	$error = $@ if $@;

	eval { $types = $self->_type_infos; };
	$error = $@ if $@ && !$error;

	$self->stash(
		targets      => $targets,
		error        => $error,
		targets_json => to_json($targets),
		types_json   => to_json($types),
	);
} ## end sub index

=head2 types

Returns the available escalation types and their config field specs as
JSON. The web UI builds config forms from this, so new types need no
UI changes.

=cut

sub types {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $types;
	eval { $types = $self->_type_infos; };
	if ($@) {
		return $self->render( json => { error => $@ }, status => 500 );
	}

	$self->render( json => { types => $types } );
} ## end sub types

=head2 targets

Returns every escalation target as JSON, with secret config fields
masked.

=cut

sub targets {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $targets;
	eval { $targets = $self->_masked_targets; };
	if ($@) {
		return $self->render( json => { error => $@ }, status => 500 );
	}

	$self->render( json => { targets => $targets } );
} ## end sub targets

=head2 target_save

Creates or updates a escalation target from a JSON body with the keys
name, type, config, description, enabled, and optionally id (update
when present). On a update, empty secret fields keep their stored
value.

=cut

sub target_save {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $json = $self->req->json;
	if ( ref $json ne 'HASH' ) {
		return $self->render( json => { error => 'a JSON object body is required' }, status => 400 );
	}

	my $config = ref $json->{config} eq 'HASH' ? $json->{config} : {};

	# drop empty values so type defaults apply instead of empty strings
	foreach my $key ( keys %$config ) {
		delete $config->{$key} if !defined( $config->{$key} ) || $config->{$key} eq '';
	}

	my $id;
	eval {
		if ( defined $json->{id} && $json->{id} ne '' ) {
			$id = $json->{id};
			die "invalid id\n" unless $id =~ /^[0-9]+$/;

			# a secret field the browser left blank means keep what is stored
			my $existing = $self->lilith->escalation_target_get($id);
			my $type = defined( $json->{type} ) && $json->{type} ne '' ? $json->{type} : $existing->{type};
			foreach my $field ( @{ $self->lilith->escalation_type_info($type)->{fields} } ) {
				next unless $field->{type} && $field->{type} eq 'secret';
				my $name = $field->{name};
				if ( !defined( $config->{$name} ) && defined( $existing->{config}{$name} ) ) {
					$config->{$name} = $existing->{config}{$name};
				}
			}

			$self->lilith->escalation_target_update(
				id          => $id,
				name        => $json->{name},
				type        => $json->{type},
				config      => $config,
				description => $json->{description},
				enabled     => $json->{enabled} ? 1 : 0,
			);
		} else {
			$id = $self->lilith->escalation_target_create(
				name        => $json->{name},
				type        => $json->{type},
				config      => $config,
				description => $json->{description},
				enabled     => $json->{enabled} ? 1 : 0,
			);
		}
	};
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}

	$self->render( json => { ok => 1, id => $id } );
} ## end sub target_save

=head2 target_delete

Deletes a escalation target by ID.

=cut

sub target_delete {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	eval { $self->lilith->escalation_target_delete($id); };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}

	$self->render( json => { ok => 1 } );
} ## end sub target_delete

=head2 target_test

Sends a synthetic test event to a escalation target. The blocking
send runs in a subprocess so the event loop stays responsive.

=cut

sub target_test {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	my $lilith = $self->lilith;
	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub {
			my $payload = eval { $lilith->escalation_test( id => $id ); };
			return ( $@, $payload );
		},
		sub {
			my ( $subprocess, $sp_err, $test_err, $payload ) = @_;
			if ($sp_err) {
				return $self->render( json => { error => 'test subprocess failed: ' . $sp_err }, status => 500 );
			}
			if ($test_err) {
				( my $why = $test_err ) =~ s/\s+\z//;
				return $self->render( json => { error => $why }, status => 502 );
			}
			$self->render( json => { ok => 1, payload => $payload } );
		},
	);
	return;
} ## end sub target_test

=head2 escalate

Escalates a event to one or more targets from a JSON body with the
keys table, id, target_ids, and optionally note and requested_by. The
blocking sends run in a subprocess so the event loop stays responsive.

=cut

sub escalate {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $json = $self->req->json;
	if ( ref $json ne 'HASH' ) {
		return $self->render( json => { error => 'a JSON object body is required' }, status => 400 );
	}

	my $table = $json->{table};
	unless ( defined $table && $table =~ /^(?:suricata|sagan|cape)$/ ) {
		return $self->render( json => { error => 'invalid table' }, status => 400 );
	}

	my $id = $json->{id};
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	my $target_ids = $json->{target_ids};
	unless ( ref $target_ids eq 'ARRAY'
		&& @$target_ids
		&& !grep { !defined($_) || $_ !~ /^[0-9]+$/ } @$target_ids )
	{
		return $self->render( json => { error => 'target_ids must be a non-empty array of IDs' }, status => 400 );
	}

	my $note         = $json->{note};
	my $requested_by = $json->{requested_by};

	my $lilith = $self->lilith;
	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub {
			my $results = eval {
				$lilith->escalate(
					table        => $table,
					id           => $id,
					target_ids   => $target_ids,
					note         => $note,
					requested_by => $requested_by,
				);
			};
			return ( $@, $results );
		},
		sub {
			my ( $subprocess, $sp_err, $esc_err, $results ) = @_;
			if ($sp_err) {
				return $self->render( json => { error => 'escalate subprocess failed: ' . $sp_err }, status => 500 );
			}
			if ($esc_err) {
				( my $why = $esc_err ) =~ s/\s+\z//;
				return $self->render( json => { error => $why }, status => 400 );
			}
			$self->render( json => { results => $results } );
		},
	);
	return;
} ## end sub escalate

=head2 history

Returns the escalations recorded for a event as JSON, newest first,
with the raw payload decoded.

=cut

sub history {
	my $self = shift;

	return $self->reply->not_found unless $self->escalation_enable;

	my $table = $self->param('table');
	unless ( defined $table && $table =~ /^(?:suricata|sagan|cape)$/ ) {
		return $self->render( json => { error => 'invalid table' }, status => 400 );
	}

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	my $escalations;
	eval { $escalations = $self->lilith->escalations_for( table => $table, id => $id ); };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 500 );
	}

	foreach my $escalation (@$escalations) {
		if ( defined $escalation->{raw} && !ref $escalation->{raw} ) {
			my $decoded;
			eval { $decoded = decode_json( $escalation->{raw} ) };
			$escalation->{raw} = $decoded if !$@ && ref $decoded;
		}
	}

	$self->render( json => { escalations => $escalations } );
} ## end sub history

=head2 _masked_targets

Fetches every escalation target with secret config values (per the
type's config_fields) replaced by empty strings and listed under
secrets_set.

=cut

sub _masked_targets {
	my $self = shift;

	my $targets = $self->lilith->escalation_targets;

	foreach my $target (@$targets) {
		my @secrets_set;
		my $fields = eval { $self->lilith->escalation_type_info( $target->{type} )->{fields} };
		if ( ref $fields eq 'ARRAY' ) {
			foreach my $field (@$fields) {
				next unless $field->{type} && $field->{type} eq 'secret';
				my $name = $field->{name};
				if ( defined( $target->{config}{$name} ) && $target->{config}{$name} ne '' ) {
					$target->{config}{$name} = '';
					push( @secrets_set, $name );
				}
			}
		}
		$target->{secrets_set} = \@secrets_set;
		$target->{enabled}     = $target->{enabled} ? 1 : 0;
	} ## end foreach my $target (@$targets)

	return $targets;
} ## end sub _masked_targets

=head2 _type_infos

Returns the type_info for every available escalation type, skipping
any that fail to load.

=cut

sub _type_infos {
	my $self = shift;

	my @infos;
	foreach my $type ( @{ $self->lilith->escalation_types } ) {
		my $info = eval { $self->lilith->escalation_type_info($type) };
		push( @infos, $info ) if $info;
	}

	return \@infos;
}

1;
