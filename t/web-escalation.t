#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub _make_app {
	my ($extra_toml) = @_;
	$extra_toml //= '';

	my ( $fh, $config_file ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
	print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
	print $fh $extra_toml;
	close $fh;

	local $ENV{LILITH_CONFIG} = $config_file;
	return Test::Mojo->new('Lilith::Web');
} ## end sub _make_app

# ---------------------------------------------------------------------------
# 1.  Disabled (default): everything is a 404 and no UI hooks show
# ---------------------------------------------------------------------------

{
	my $t = _make_app();

	$t->get_ok('/escalation')->status_is( 404, 'management page is 404 when disabled' );
	$t->get_ok('/api/escalation/types')->status_is( 404, 'types API is 404 when disabled' );
	$t->get_ok('/api/escalation/targets')->status_is( 404, 'targets API is 404 when disabled' );
	$t->post_ok('/api/escalation/targets')->status_is( 404, 'target save is 404 when disabled' );
	$t->post_ok('/api/escalation/targets/1/delete')->status_is( 404, 'target delete is 404 when disabled' );
	$t->post_ok('/api/escalation/targets/1/test')->status_is( 404, 'target test is 404 when disabled' );
	$t->post_ok('/api/escalation/escalate')->status_is( 404, 'escalate is 404 when disabled' );
	$t->get_ok('/api/escalation/history/suricata/1')->status_is( 404, 'history is 404 when disabled' );

	$t->get_ok('/search')->status_is(200)->element_exists_not( 'a#nav-escalation', 'no navbar link when disabled' );

	no warnings qw(redefine once);
	local *Lilith::search = sub {
		return [ { id => 5, src_ip => '1.1.1.1', raw => '{}' } ];
	};
	use warnings qw(redefine once);
	$t->get_ok('/event/suricata/5')
		->status_is(200)
		->element_exists_not( 'button#escalate-btn',    'no escalate button when disabled' )
		->element_exists_not( 'div#escalation-history', 'no escalation history when disabled' );
}

my $sample_target = sub {
	return [
		{
			id          => 1,
			name        => 'soc-hook',
			type        => 'Webhook',
			enabled     => 1,
			description => 'SOC webhook',
			updated     => '2026-07-05',
			config      => { url => 'https://soc.example/hook', apikey => 'sekritvalue' },
		}
	];
}; ## end $sample_target = sub

# ---------------------------------------------------------------------------
# 2.  View tier (escalation_enable): read only page, plain navbar link, masking
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\n");

	$t->get_ok('/search')
		->status_is(200)
		->element_exists( 'a#nav-escalation', 'plain navbar link when viewing only' )
		->element_exists_not( 'a#nav-escalation-edit', 'no edit menu item without manage' );

	no warnings qw(redefine once);
	local *Lilith::escalation_targets = $sample_target;
	use warnings qw(redefine once);

	# the read only view lists targets but exposes no mutation controls
	my $body
		= $t->get_ok('/escalation')
		->status_is( 200, 'view page renders' )
		->element_exists( 'table#esc-targets-table', 'target table present' )
		->element_exists_not( 'button#target-add-btn',    'no add button in view mode' )
		->element_exists_not( 'div#target-modal',         'no target modal in view mode' )
		->element_exists_not( 'button.target-edit-btn',   'no edit button in view mode' )
		->element_exists_not( 'button.target-delete-btn', 'no delete button in view mode' )
		->content_like( qr/soc-hook/, 'target name shown' )
		->tx->res->body;
	unlike( $body, qr/sekritvalue/, 'secret config value never reaches the browser' );

	# the edit page 404s and mutating endpoints 403 while management is disabled
	$t->get_ok('/escalation/edit')->status_is( 404, 'edit page 404s without manage' );
	$t->post_ok('/api/escalation/targets')->status_is( 403, 'target save 403s without manage' );
	$t->post_ok('/api/escalation/targets/1/delete')->status_is( 403, 'target delete 403s without manage' );
	$t->post_ok('/api/escalation/targets/1/test')->status_is( 403, 'target test 403s without manage' );

	# targets API masks secrets and flags them via secrets_set (view tier)
	my $targets = $t->get_ok('/api/escalation/targets')->status_is(200)->tx->res->json->{targets};
	is( $targets->[0]{config}{apikey}, '', 'apikey masked in the targets API' );
	is_deeply( $targets->[0]{secrets_set}, ['apikey'], 'masked secret listed in secrets_set' );
	is( $targets->[0]{config}{url}, 'https://soc.example/hook', 'non-secret config passes through' );

	# types API drives the dynamic config form (view tier)
	my $types = $t->get_ok('/api/escalation/types')->status_is(200)->tx->res->json->{types};
	my ($webhook) = grep { $_->{type} eq 'Webhook' } @$types;
	ok( $webhook, 'types API lists Webhook' );
	my ($url_field) = grep { $_->{name} eq 'url' } @{ $webhook->{fields} };
	ok( $url_field && $url_field->{required}, 'types API carries the config field spec' );
}

# ---------------------------------------------------------------------------
# 2b. Manage tier (escalation_manage_enable): View/Edit dropdown + editable page
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\nescalation_manage_enable = true\n");

	$t->get_ok('/search')
		->status_is(200)
		->element_exists( 'button#nav-escalation-toggle', 'escalation dropdown present with manage' )
		->element_exists( 'a#nav-escalation-view',        'view menu item present' )
		->element_exists( 'a#nav-escalation-edit',        'edit menu item present' )
		->element_exists_not( 'a#nav-escalation', 'no plain link when the dropdown is shown' );

	no warnings qw(redefine once);
	local *Lilith::escalation_targets = $sample_target;
	use warnings qw(redefine once);

	# /escalation stays read only even with manage on; only /escalation/edit edits
	$t->get_ok('/escalation')
		->status_is( 200, 'view page still renders with manage' )
		->element_exists_not( 'button#target-add-btn', 'view page has no add button' );

	my $body
		= $t->get_ok('/escalation/edit')
		->status_is( 200, 'edit page renders with manage' )
		->element_exists( 'table#esc-targets-table',  'target table present' )
		->element_exists( 'button#target-add-btn',    'add button present' )
		->element_exists( 'div#target-modal',         'target modal present' )
		->element_exists( 'select#target-type',       'type select present' )
		->element_exists( 'button.target-edit-btn',   'edit button present' )
		->element_exists( 'button.target-test-btn',   'test button present' )
		->element_exists( 'button.target-delete-btn', 'delete button present' )
		->content_like( qr/soc-hook/, 'target name shown' )
		->tx->res->body;
	unlike( $body, qr/sekritvalue/, 'secret still masked on the edit page' );
}

# ---------------------------------------------------------------------------
# 3.  Target save: create, update with secret keep, validation
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\nescalation_manage_enable = true\n");

	my %created;
	no warnings qw(redefine once);
	local *Lilith::escalation_target_create = sub {
		my ( $self, %opts ) = @_;
		# validate the type like the real method so bad types still die
		Lilith::Escalate->type_module( $opts{type} );
		%created = %opts;
		return 5;
	};
	use warnings qw(redefine once);

	$t->post_ok(
		'/api/escalation/targets' => json => {
			name    => 'hook',
			type    => 'Webhook',
			config  => { url => 'https://e/x', timeout => '', apikey => 'k' },
			enabled => 1,
		}
	)->status_is( 200, 'create renders 200' )->json_is( '/ok', 1 )->json_is( '/id', 5 );
	is( $created{name}, 'hook', 'create passes the name through' );
	ok( !exists $created{config}{timeout}, 'empty config values are dropped' );
	is( $created{config}{apikey}, 'k', 'submitted secret passes through on create' );

	# update: an empty secret keeps the stored value
	my %updated;
	no warnings qw(redefine once);
	local *Lilith::escalation_target_get = sub {
		return {
			id     => 5,
			name   => 'hook',
			type   => 'Webhook',
			config => { url => 'https://e/x', apikey => 'storedsecret' },
		};
	};
	local *Lilith::escalation_target_update = sub {
		my ( $self, %opts ) = @_;
		%updated = %opts;
		return 1;
	};
	use warnings qw(redefine once);

	$t->post_ok(
		'/api/escalation/targets' => json => {
			id      => 5,
			name    => 'hook',
			type    => 'Webhook',
			config  => { url => 'https://e/y', apikey => '' },
			enabled => 0,
		}
	)->status_is( 200, 'update renders 200' )->json_is( '/ok', 1 );
	is( $updated{config}{apikey}, 'storedsecret', 'empty secret keeps the stored value' );
	is( $updated{config}{url},    'https://e/y',  'changed config value is used' );
	is( $updated{enabled},        0,              'enabled flag passes through' );

	# a fresh secret replaces the stored one
	$t->post_ok(
		'/api/escalation/targets' => json => {
			id     => 5,
			name   => 'hook',
			type   => 'Webhook',
			config => { url => 'https://e/y', apikey => 'newsecret' },
		}
	)->status_is(200);
	is( $updated{config}{apikey}, 'newsecret', 'submitted secret replaces the stored value' );

	# validation errors surface as a 400
	$t->post_ok( '/api/escalation/targets' => json => { name => 'x', type => 'DoesNotExist' } )
		->status_is( 400, 'unknown type is a 400' )
		->json_like( '/error', qr/unknown escalation type/, 'error message passed through' );
	$t->post_ok( '/api/escalation/targets', form => { a => 'b' } )->status_is( 400, 'non-JSON body is a 400' );
}

# ---------------------------------------------------------------------------
# 4.  Target delete + test
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\nescalation_manage_enable = true\n");

	my $deleted;
	no warnings qw(redefine once);
	local *Lilith::escalation_target_delete = sub {
		my ( $self, $id ) = @_;
		$deleted = $id;
		return 1;
	};
	# the test runs in a subprocess; the mock is inherited by the fork
	local *Lilith::escalation_test = sub {
		my ( $self, %opts ) = @_;
		die "boom\n" if $opts{id} == 99;
		return { message => 'test payload for ' . $opts{id} };
	};
	use warnings qw(redefine once);

	$t->post_ok('/api/escalation/targets/7/delete')->status_is(200)->json_is( '/ok', 1 );
	is( $deleted, 7, 'delete passes the id through' );
	$t->post_ok('/api/escalation/targets/abc/delete')->status_is( 400, 'non-numeric delete id is a 400' );

	$t->post_ok('/api/escalation/targets/7/test')
		->status_is( 200, 'test renders 200' )
		->json_is( '/ok', 1 )
		->json_is( '/payload/message', 'test payload for 7', 'test payload streamed back' );
	$t->post_ok('/api/escalation/targets/99/test')
		->status_is( 502, 'failed test is a 502' )
		->json_is( '/error', 'boom', 'test error passed through' );
	$t->post_ok('/api/escalation/targets/abc/test')->status_is( 400, 'non-numeric test id is a 400' );
}

# ---------------------------------------------------------------------------
# 5.  Escalate endpoint
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\n");

	no warnings qw(redefine once);
	# runs in a subprocess; the mock is inherited by the fork
	local *Lilith::escalate = sub {
		my ( $self, %opts ) = @_;
		return [
			map {
				{
					target_id     => $_,
					target_name   => 'target-' . $_,
					escalation_id => 100 + $_,
					status        => 'sent',
					error         => undef,
				}
			} @{ $opts{target_ids} }
		];
	}; ## end *Lilith::escalate = sub
	use warnings qw(redefine once);

	$t->post_ok(
		'/api/escalation/escalate' => json => {
			table      => 'suricata',
			id         => 42,
			target_ids => [ 1, 2 ],
			note       => 'bad traffic',
		}
		)
		->status_is( 200, 'escalate renders 200' )
		->json_is( '/results/0/status',      'sent',     'first result status' )
		->json_is( '/results/1/target_name', 'target-2', 'second result target name' );

	# baphomet is a valid escalation table (manual escalation is enabled for it)
	$t->post_ok( '/api/escalation/escalate' => json => { table => 'baphomet', id => 7, target_ids => [1] } )
		->status_is( 200, 'escalate accepts the baphomet table' )
		->json_is( '/results/0/status', 'sent', 'baphomet escalate result status' );

	$t->post_ok( '/api/escalation/escalate' => json => { table => 'bad', id => 1, target_ids => [1] } )
		->status_is( 400, 'bad table is a 400' );
	$t->post_ok( '/api/escalation/escalate' => json => { table => 'suricata', id => 'x', target_ids => [1] } )
		->status_is( 400, 'bad id is a 400' );
	$t->post_ok( '/api/escalation/escalate' => json => { table => 'suricata', id => 1, target_ids => [] } )
		->status_is( 400, 'empty target_ids is a 400' );
	$t->post_ok( '/api/escalation/escalate' => json => { table => 'suricata', id => 1, target_ids => ['x'] } )
		->status_is( 400, 'non-numeric target id is a 400' );
}

# ---------------------------------------------------------------------------
# 6.  History endpoint
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\n");

	no warnings qw(redefine once);
	local *Lilith::escalations_for = sub {
		my ( $self, %opts ) = @_;
		return [
			{
				id           => 3,
				table_name   => $opts{table},
				alert_id     => $opts{id},
				target_id    => 1,
				target_name  => 'soc-hook',
				target_type  => 'Webhook',
				status       => 'sent',
				note         => 'n',
				requested_by => 'kitsune',
				error        => undef,
				raw          => '{"url":"https://e/x"}',
				timestamp    => '2026-07-05',
			}
		];
	}; ## end *Lilith::escalations_for = sub
	use warnings qw(redefine once);

	$t->get_ok('/api/escalation/history/suricata/9')
		->status_is( 200, 'history renders 200' )
		->json_is( '/escalations/0/target_name', 'soc-hook',    'history row present' )
		->json_is( '/escalations/0/raw/url',     'https://e/x', 'raw payload decoded to structure' );

	$t->get_ok('/api/escalation/history/bad/9')->status_is( 400, 'bad table is a 400' );
	$t->get_ok('/api/escalation/history/suricata/x')->status_is( 400, 'bad id is a 400' );
}

# ---------------------------------------------------------------------------
# 7.  Event view + search results UI hooks
# ---------------------------------------------------------------------------

{
	my $t = _make_app("escalation_enable = true\n");

	no warnings qw(redefine once);
	# the escalations array on the row is what drives the badge; no extra
	# query is made for it
	local *Lilith::search = sub {
		return [
			{
				id             => 42,
				timestamp      => 't',
				src_ip         => '8.8.8.8',
				classification => 'Misc Attack',
				raw            => '{}',
				escalations    => [ 101, 102 ],
			}
		];
	}; ## end *Lilith::search = sub
	use warnings qw(redefine once);

	$t->get_ok('/event/suricata/42')
		->status_is(200)
		->element_exists( 'button#escalate-btn',    'escalate button present when enabled' )
		->element_exists( 'div#escalate-modal',     'escalate modal present' )
		->element_exists( 'div#escalation-history', 'escalation history card present' )
		->element_exists( 'textarea#esc-note',      'note field present' )
		->element_exists( 'button#esc-send-btn',    'send button present' );

	$t->get_ok('/search?search=1&table=suricata')
		->status_is(200)
		->element_exists( 'span.esc-badge', 'escalated badge shown in search results' )
		->text_like( 'span.esc-badge', qr/E/, 'badge is the E marker' )
		->element_exists( 'span.esc-badge[title="escalated 2 times"]', 'badge count comes from the escalations array' );

	# the event view renders the escalations array as a joined list, not
	# a stringified array ref
	my $event_body = $t->get_ok('/event/suricata/42')->status_is(200)->tx->res->body;
	like( $event_body, qr/101, 102/, 'event view joins the escalations array' );
	unlike( $event_body, qr/ARRAY\(0x/, 'no raw array ref leaks into the event view' );

	# partial render carries the badge too (auto-refresh path)
	$t->get_ok('/search?search=1&table=suricata&partial=1')
		->status_is(200)
		->element_exists( 'span.esc-badge', 'escalated badge in the partial render' );
}

done_testing();
