package Lilith::Web::Controller::AutoEscalation;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::JSON   qw(to_json);
use Mojo::IOLoop ();

=head1 NAME

Lilith::Web::Controller::AutoEscalation - Auto escalation rule controller for Lilith::Web.

=head1 DESCRIPTION

Management page and JSON API for auto escalation rules. Rules live in
the auto_escalations SQL table; each holds a match/actions DSL (see
L<Lilith::AutoEscalate>) that auto_escalate() evaluates against alerts
on a timer, escalating matches to the named escalation targets.

Gating is two tiered, both off by default:

    - escalation_enable gates the page and the read/preview endpoints
      (index, rules, preview). When off every action 404s, exactly like
      the rest of the escalation UI.

    - auto_escalation_manage_enable additionally gates the mutating
      endpoints (save, delete, toggle). When it is off those return 403
      and the page renders read only: a saved+enabled rule escalates
      automatically with no human in the loop, so editing rules from the
      web UI is opt in separately from viewing them.

Preview never sends and never marks any alert as considered, so it is
safe in the read tier.

=cut

# read tier gate; returns 1 when the caller may proceed, else renders the
# 404 and returns 0. The shared logic lives in the require_escalation_view
# helper in Lilith::Web.
sub _require_view {
	return $_[0]->require_escalation_view;
}

# write tier gate; view must be allowed and management explicitly enabled.
# Renders a 404 (view off) or 403 (management off) and returns 0 on refusal.
# The shared logic lives in the require_escalation_manage helper in
# Lilith::Web.
sub _require_manage {
	my $self = shift;

	return $self->require_escalation_manage( $self->auto_escalation_manage_enable,
		'auto escalation management is disabled' );
}

=head2 index

Renders the auto escalation rule management page. Read only unless
auto_escalation_manage_enable is set.

=cut

sub index {
	my $self = shift;

	return unless $self->_require_view;

	my $rules   = [];
	my $targets = [];
	my $error;

	eval { $rules = $self->lilith->auto_escalations; };
	$error = $@ if $@;

	# the escalate_to picker offers the configured target names
	eval { $targets = $self->lilith->escalation_targets; };
	$error = $@ if $@ && !$error;

	my $can_manage = $self->auto_escalation_manage_enable;

	$self->stash(
		rules        => $rules,
		can_manage   => $can_manage,
		error        => $error,
		rules_json   => to_json($rules),
		targets_json => to_json( [ map { { id => $_->{id}, name => $_->{name}, enabled => ( $_->{enabled} ? 1 : 0 ) } } @$targets ] ),
	);
} ## end sub index

=head2 rules

Returns every auto escalation rule as JSON.

=cut

sub rules {
	my $self = shift;

	return unless $self->_require_view;

	my $rules;
	eval { $rules = $self->lilith->auto_escalations; };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 500 );
	}

	$self->render( json => { rules => $rules } );
} ## end sub rules

=head2 save

Creates or updates a rule from a JSON body with the keys name, rule,
tables, priority, stop_on_match, enabled, description, and optionally id
(update when present). The rule DSL is validated by check_rule, so a bad
rule comes back as a 400 with the reason.

=cut

sub save {
	my $self = shift;

	return unless $self->_require_manage;

	my $json = $self->req->json;
	if ( ref $json ne 'HASH' ) {
		return $self->render( json => { error => 'a JSON object body is required' }, status => 400 );
	}

	my $tables = ref $json->{tables} eq 'ARRAY' ? $json->{tables} : undef;

	my $id;
	eval {
		if ( defined $json->{id} && $json->{id} ne '' ) {
			$id = $json->{id};
			die "invalid id\n" unless $id =~ /^[0-9]+$/;
			$self->lilith->auto_escalation_update(
				id            => $id,
				name          => $json->{name},
				rule          => $json->{rule},
				tables        => $tables,
				priority      => $json->{priority},
				stop_on_match => ( $json->{stop_on_match} ? 1 : 0 ),
				enabled       => ( $json->{enabled} ? 1 : 0 ),
				description   => $json->{description},
			);
		} else {
			$id = $self->lilith->auto_escalation_create(
				name          => $json->{name},
				rule          => $json->{rule},
				tables        => $tables,
				priority      => $json->{priority},
				stop_on_match => ( $json->{stop_on_match} ? 1 : 0 ),
				enabled       => ( $json->{enabled} ? 1 : 0 ),
				description   => $json->{description},
			);
		}
	};
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}

	$self->render( json => { ok => 1, id => $id } );
} ## end sub save

=head2 delete

Deletes a rule by ID.

=cut

sub delete {
	my $self = shift;

	return unless $self->_require_manage;

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	eval { $self->lilith->auto_escalation_delete($id); };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}

	$self->render( json => { ok => 1 } );
} ## end sub delete

=head2 toggle

Enables or disables a rule from a JSON body with a boolean 'enabled'.

=cut

sub toggle {
	my $self = shift;

	return unless $self->_require_manage;

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	my $json    = $self->req->json;
	my $enabled = ( ref $json eq 'HASH' && $json->{enabled} ) ? 1 : 0;

	eval { $self->lilith->auto_escalation_update( id => $id, enabled => $enabled ); };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}

	$self->render( json => { ok => 1, enabled => $enabled } );
} ## end sub toggle

=head2 preview

Dry runs a rule from a JSON body with the keys rule, table, and
optionally go_back_minutes, returning which recent alerts would match.
Nothing is escalated and no alert is marked as considered. The
evaluation runs in a subprocess so a pathological regex can not hang the
worker's event loop.

=cut

sub preview {
	my $self = shift;

	return unless $self->_require_view;

	my $json = $self->req->json;
	if ( ref $json ne 'HASH' || ref $json->{rule} ne 'HASH' ) {
		return $self->render( json => { error => 'a JSON object body with a "rule" object is required' }, status => 400 );
	}

	my $table = defined $json->{table} ? $json->{table} : 'suricata';
	unless ( $table =~ /^(?:suricata|sagan|cape|baphomet)$/ ) {
		return $self->render( json => { error => 'invalid table' }, status => 400 );
	}

	my $minutes = defined $json->{go_back_minutes} ? $json->{go_back_minutes} : 60;
	unless ( $minutes =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'go_back_minutes must be numeric' }, status => 400 );
	}

	my $rule   = $json->{rule};
	my $lilith = $self->lilith;
	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub {
			# guard against a runaway regex in a rule leaf
			my $result = eval {
				local $SIG{ALRM} = sub { die "preview timed out\n" };
				alarm 20;
				my $r = $lilith->auto_escalation_preview(
					rule            => $rule,
					table           => $table,
					go_back_minutes => $minutes,
				);
				alarm 0;
				$r;
			};
			my $err = $@;
			alarm 0;
			return ( $err, $result );
		},
		sub {
			my ( $subprocess, $sp_err, $preview_err, $result ) = @_;
			if ($sp_err) {
				return $self->render( json => { error => 'preview subprocess failed: ' . $sp_err }, status => 500 );
			}
			if ($preview_err) {
				( my $why = $preview_err ) =~ s/\s+\z//;
				return $self->render( json => { error => $why }, status => 400 );
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub preview

1;
