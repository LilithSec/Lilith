package Lilith::Web::Controller::Search;

use Mojo::Base 'Mojolicious::Controller';

=head1 NAME

Lilith::Web::Controller::Search - Search controller for Lilith::Web.

=head1 DESCRIPTION

Handles the search form and results for Suricata, Sagan, and CAPE alerts.

=cut

sub index {
	my $self = shift;

	my $table           = $self->param('table')           // 'suricata';
	my $go_back_minutes = $self->param('go_back_minutes') // 1440;
	my $limit           = $self->param('limit')           // 100;
	my $offset          = $self->param('offset')          // 0;
	my $order_dir       = $self->param('order_dir')       // 'DESC';
	my $order_by        = $self->param('order_by')        // '';

	# Sanitize
	$table     = 'suricata'                                  unless $table     =~ /^(?:suricata|sagan|cape)$/;
	$order_dir = 'DESC'                                      unless $order_dir =~ /^(?:ASC|DESC)$/;
	$order_by  = ( $table eq 'cape' ? 'stop' : 'timestamp' ) unless $order_by;

	my $results;
	my $error;

	# Always run a search. With no query parameters this yields the default
	# search (Suricata, last 1440 minutes), so results are shown as soon as the
	# page is pulled up rather than an empty form.
	{
		my @src_port  = _split_list( $self->param('src_port') );
		my @dest_port = _split_list( $self->param('dest_port') );
		my @gid       = _split_list( $self->param('gid') );
		my @sid       = _split_list( $self->param('sid') );
		my @rev       = _split_list( $self->param('rev') );
		my @malscore  = _split_list( $self->param('malscore') );
		my @size      = _split_list( $self->param('size') );
		my @task      = _split_list( $self->param('task') );
		my @class     = grep { defined($_) && $_ ne '' } @{ $self->every_param('class') };
		my @class_not = grep { defined($_) && $_ ne '' } @{ $self->every_param('class_not') };

		# On a fresh form (nothing submitted yet) default to excluding GPCD. This
		# mirrors the default selection shown by the template's class_not dropdown
		# so the actual query matches the filter the user sees -- and, crucially,
		# so auto-refresh (which re-fetches this same URL) keeps excluding it
		# rather than streaming in new GPCD events.
		if ( !$self->param('search') ) {
			push( @class_not, 'Generic Protocol Command Decode' )
				unless grep { $_ eq 'Generic Protocol Command Decode' } @class_not;
		}

		push( @class, map { '!' . $_ } @class_not );

		eval {
			$results = $self->lilith->search(
				table            => $table,
				go_back_minutes  => $go_back_minutes,
				start            => $self->param('start') || undef,
				end              => $self->param('end')   || undef,
				order_by         => $order_by,
				order_dir        => $order_dir,
				limit            => $limit,
				offset           => $offset,
				src_ip           => $self->param('src_ip')        || undef,
				dest_ip          => $self->param('dest_ip')       || undef,
				ip               => $self->param('ip')            || undef,
				port             => $self->param('port')          || undef,
				host             => $self->param('host')          || undef,
				instance_host    => $self->param('instance_host') || undef,
				instance         => $self->param('instance')      || undef,
				class            => \@class,
				signature        => $self->param('signature')        || undef,
				app_proto        => $self->param('app_proto')        || undef,
				proto            => $self->param('proto')            || undef,
				in_iface         => $self->param('in_iface')         || undef,
				event_id         => $self->param('event_id')         || undef,
				md5              => $self->param('md5')              || undef,
				sha1             => $self->param('sha1')             || undef,
				sha256           => $self->param('sha256')           || undef,
				subbed_from_ip   => $self->param('subbed_from_ip')   || undef,
				subbed_from_host => $self->param('subbed_from_host') || undef,
				slug             => $self->param('slug')             || undef,
				pkg              => $self->param('pkg')              || undef,
				target           => $self->param('target')           || undef,
				src_port         => \@src_port,
				dest_port        => \@dest_port,
				gid              => \@gid,
				sid              => \@sid,
				rev              => \@rev,
				malscore         => \@malscore,
				size             => \@size,
				task             => \@task,
			);
		};
		$error = $@ if $@;
	}

	# Escalation counts for badging escalated events, read straight off each
	# row's escalations array (maintained by Lilith::escalate), so no extra
	# query is needed.
	my $escalated = {};
	if ( $self->escalation_enable && ref $results eq 'ARRAY' ) {
		foreach my $row (@$results) {
			if ( ref $row->{escalations} eq 'ARRAY' && @{ $row->{escalations} } ) {
				$escalated->{ $row->{id} } = scalar @{ $row->{escalations} };
			}
		}
	}

	$self->stash(
		results         => $results,
		escalated       => $escalated,
		error           => $error,
		table           => $table,
		go_back_minutes => $go_back_minutes,
		order_by        => $order_by,
		order_dir       => $order_dir,
		limit           => $limit,
		offset          => $offset,
	);

	# Auto-refresh fetches partial=1 to get just the results fragment (no layout
	# or filter form), which is far smaller than the full page.
	if ( $self->param('partial') && defined $results ) {
		return $self->render( 'search/_results', layout => undef );
	}
} ## end sub index

sub _split_list {
	my $str = shift;
	return () unless defined $str && $str ne '';
	return split /\s*,\s*/, $str;
}

1;
