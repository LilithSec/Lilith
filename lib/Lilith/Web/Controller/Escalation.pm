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
config. The read tier (viewing targets, listing types, escalating an
event, history) 404s unless escalation_enable is set. The write tier
(create/update/delete/test a target) additionally requires
escalation_manage_enable, so a site can expose the target list without
letting the web UI change where alerts are sent.

Secret config fields (per the type's config_fields spec) are never
sent to the browser; they are returned masked as empty strings with
the field name listed in secrets_set, and an empty secret submitted on
an update means "keep the current value".

=cut

# write tier gate: the require_escalation_manage helper in Lilith::Web (which
# documents the two refusal tiers), bound to this controller's management flag
# and refusal message. Renders the refusal and returns 0, so a caller reads as
#
#     return unless $self->_require_manage;
sub _require_manage {
	my $self = shift;

	return $self->require_escalation_manage( $self->escalation_manage_enable,
		'escalation target management is disabled' );
}

=head2 index

Renders the escalation target page. The /escalation route is read only;
the /escalation/edit route (mode => 'edit') exposes the add/edit/test/
delete controls and 404s unless escalation_manage_enable is set.

=cut

sub index {
	my $self = shift;

	return unless $self->require_escalation_view;

	# the edit page only exists when management is enabled; the read only view
	# is always reachable with escalation_enable
	my $can_edit = ( ( $self->stash('mode') // '' ) eq 'edit' ) ? 1 : 0;
	if ( $can_edit && !$self->escalation_manage_enable ) {
		return $self->reply->not_found;
	}

	my $targets = [];
	my $types   = [];
	my $error;

	eval { $targets = $self->_masked_targets; };
	$error = $@ if $@;

	eval { $types = $self->_type_infos; };
	$error = $@ if $@ && !$error;

	$self->stash(
		can_edit     => $can_edit,
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

	return unless $self->require_escalation_view;

	my $types;
	eval { $types = $self->_type_infos; };
	return $self->render_error( $@, 500 ) if $@;

	$self->render( json => { types => $types } );
} ## end sub types

=head2 targets

Returns every escalation target as JSON, with secret config fields
masked.

=cut

sub targets {
	my $self = shift;

	return unless $self->require_escalation_view;

	my $targets;
	eval { $targets = $self->_masked_targets; };
	return $self->render_error( $@, 500 ) if $@;

	$self->render( json => { targets => $targets } );
} ## end sub targets

=head2 target_save

Creates or updates an escalation target from a JSON body with the keys
name, type, config, description, enabled, and optionally id (update
when present). On an update, empty secret fields keep their stored
value.

=cut

sub target_save {
	my $self = shift;

	return unless $self->_require_manage;

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
			my $type     = defined( $json->{type} ) && $json->{type} ne '' ? $json->{type} : $existing->{type};
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
	return $self->render_error($@) if $@;

	$self->render( json => { ok => 1, id => $id } );
} ## end sub target_save

=head2 target_delete

Deletes an escalation target by ID.

=cut

sub target_delete {
	my $self = shift;

	return unless $self->_require_manage;

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	eval { $self->lilith->escalation_target_delete($id); };
	return $self->render_error($@) if $@;

	$self->render( json => { ok => 1 } );
} ## end sub target_delete

=head2 target_test

Sends a synthetic test event to an escalation target. The blocking
send runs in a subprocess so the event loop stays responsive.

=cut

sub target_test {
	my $self = shift;

	return unless $self->_require_manage;

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
				return $self->render_error( $test_err, 502 );
			}
			$self->render( json => { ok => 1, payload => $payload } );
		},
	);
	return;
} ## end sub target_test

=head2 escalate

Escalates an event to one or more targets from a JSON body with the
keys table, id, target_ids, and optionally note and requested_by. The
blocking sends run in a subprocess so the event loop stays responsive.

=cut

sub escalate {
	my $self = shift;

	return unless $self->require_escalation_view;

	my $json = $self->req->json;
	if ( ref $json ne 'HASH' ) {
		return $self->render( json => { error => 'a JSON object body is required' }, status => 400 );
	}

	my $table = $json->{table};
	unless ( $self->valid_alert_table($table) ) {
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
				return $self->render(
					json   => { error => 'escalate subprocess failed: ' . $sp_err },
					status => 500
				);
			}
			if ($esc_err) {
				return $self->render_error($esc_err);
			}
			$self->render( json => { results => $results } );
		},
	);
	return;
} ## end sub escalate

=head2 history

Returns the escalations recorded for an event as JSON, newest first,
with the raw payload decoded.

=cut

sub history {
	my $self = shift;

	return unless $self->require_escalation_view;

	my $table = $self->param('table');
	unless ( $self->valid_alert_table($table) ) {
		return $self->render( json => { error => 'invalid table' }, status => 400 );
	}

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	my $escalations;
	eval { $escalations = $self->lilith->escalations_for( table => $table, id => $id ); };
	return $self->render_error( $@, 500 ) if $@;

	foreach my $escalation (@$escalations) {
		if ( defined $escalation->{raw} && !ref $escalation->{raw} ) {
			my $decoded;
			eval { $decoded = decode_json( $escalation->{raw} ) };
			$escalation->{raw} = $decoded if !$@ && ref $decoded;
		}
	}

	$self->render( json => { escalations => $escalations } );
} ## end sub history

# Every escalation target, safe to hand to the browser: each config value the
# target's type declares as a secret is blanked, and the names of the ones that
# were set are listed separately.
#
# The frontend needs both halves. Blanking alone would make a configured
# password indistinguishable from an empty one, so the edit form could not show
# that a secret is already in place, and saving the form back would silently
# wipe it. secrets_set is what lets the form say "set, leave blank to keep".
#
# A type whose module will not load is left alone rather than skipped: its
# fields cannot be read, so nothing is known to be a secret. That errs toward
# showing a target that cannot be edited rather than leaking a value.
#
# Args: none beyond the controller.
#
# Returns: an array ref of target hash refs, as escalation_targets returns them
# but with two changes -- every secret in config is now the empty string, and
# secrets_set holds the names of those that had a value. enabled is forced to
# 1 or 0 so it encodes as a JSON number rather than whatever the database gave.
#
#     my $targets = $self->_masked_targets;
#     # [ {
#     #     name        => 'soc-webhook',
#     #     type        => 'webhook',
#     #     enabled     => 1,
#     #     config      => { url => 'https://soc.example.org/hook', token => '' },
#     #     secrets_set => [ 'token' ],
#     # } ]
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
		} ## end if ( ref $fields eq 'ARRAY' )
		$target->{secrets_set} = \@secrets_set;
		$target->{enabled}     = $target->{enabled} ? 1 : 0;
	} ## end foreach my $target (@$targets)

	return $targets;
} ## end sub _masked_targets

# What the escalation type picker and its per-type config form are built from:
# the type_info of every escalation type that can be loaded.
#
# A type that dies on load is dropped rather than fatal. The type list comes
# from scanning namespaces, so a half-installed or third-party module is a
# normal thing to meet, and one bad module must not cost the page every other
# type.
#
# Args: none beyond the controller.
#
# Returns: an array ref of type_info hash refs, in the order escalation_types
# gave them. Each carries at least the type name and its fields -- the config
# the type accepts, which the form renders from. Empty when nothing loads.
#
#     my $infos = $self->_type_infos;
#     # [ {
#     #     type   => 'webhook',
#     #     fields => [
#     #         { name => 'url',   type => 'string' },
#     #         { name => 'token', type => 'secret' },
#     #     ],
#     # }, { type => 'email', fields => [ ... ] } ]
sub _type_infos {
	my $self = shift;

	my @infos;
	foreach my $type ( @{ $self->lilith->escalation_types } ) {
		my $info = eval { $self->lilith->escalation_type_info($type) };
		push( @infos, $info ) if $info;
	}

	return \@infos;
} ## end sub _type_infos

1;
