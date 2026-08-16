package Lilith::Web::Controller::Search;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::JSON ();

use Lilith;

# How many values a filter field's dropdown is offered. The list is fetched
# once per field and filtered in the browser as someone types, so this is the
# whole vocabulary they get: enough to cover the values worth clicking, short
# of shipping a column with thousands of them down the wire.
my $VALUE_SUGGESTION_LIMIT = 200;

=head1 NAME

Lilith::Web::Controller::Search - Search controller for Lilith::Web.

=head1 DESCRIPTION

Handles the search form and results for Suricata, Sagan, and CAPE alerts.

=cut

# GET /search -- the filter form and its results. Reads every filter off the
# query string, sanitizes the few that are spliced rather than passed to
# Lilith::search (the table, sort column, and direction), and renders. Running
# with no parameters at all is the landing page: the defaults are a day of
# suricata alerts, newest first.
#
# The same action serves the auto-refresh: with partial=1 only the results
# fragment is rendered, without the layout or the filter form, so a refreshing
# page pulls a fraction of the bytes.
#
# Args: none beyond the controller. Everything comes off the query string.
#
# Returns: nothing meaningful; renders the page (or the results fragment).
# A search that dies -- a bad time value, an unreachable database -- is caught
# and shown as an error on the page rather than becoming a 500.
sub index {
	my $self = shift;

	my $table           = $self->param('table')           // 'suricata';
	my $go_back_minutes = $self->param('go_back_minutes') // 1440;
	my $limit           = $self->param('limit')           // 100;
	my $offset          = $self->param('offset')          // 0;
	my $order_dir       = $self->param('order_dir')       // 'DESC';
	my $order_by        = $self->param('order_by')        // '';
	my $bucket          = $self->param('bucket') ? 1 : 0;

	# Sanitize
	$table     = 'suricata' unless $self->valid_alert_table($table);
	$order_dir = 'DESC'     unless $order_dir =~ /^(?:ASC|DESC)$/;
	$order_by  = ( $table eq 'cape' ? 'stop' : 'timestamp' )
		unless grep { $_ eq $order_by } ( @{ $Lilith::alert_columns{$table} }, qw(id escalations auto_escalated) );

	my $results;
	my $error;

	# Always run a search. With no query parameters this yields the default
	# search (Suricata, last 1440 minutes), so results are shown as soon as the
	# page is pulled up rather than an empty form.
	{
		my @src_port  = _split_list( @{ $self->every_param('src_port') } );
		my @dest_port = _split_list( @{ $self->every_param('dest_port') } );
		my @gid       = _split_list( @{ $self->every_param('gid') } );
		my @sid       = _split_list( @{ $self->every_param('sid') } );
		my @rev       = _split_list( @{ $self->every_param('rev') } );
		my @malscore  = _split_list( @{ $self->every_param('malscore') } );
		my @size      = _split_list( @{ $self->every_param('size') } );
		my @task      = _split_list( @{ $self->every_param('task') } );
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

		# What the active filter chips show for class_not. Taken from here rather
		# than from the query string because of the GPCD default above: on a
		# fresh form the search runs with it excluded without the URL saying so,
		# and a chip row that left it out would be describing a different search
		# than the one whose results are on the page.
		$self->stash( effective_class_not => [@class_not] );

		push( @class, map { '!' . $_ } @class_not );

		eval {
			$results = $self->lilith->search(
				table => $table,

				# baphomet only; Lilith::search ignores it elsewhere, so a
				# checked box surviving a table switch does not error
				bucket => $bucket,

				go_back_minutes  => $go_back_minutes,
				start            => $self->param('start') || undef,
				end              => $self->param('end')   || undef,
				order_by         => $order_by,
				order_dir        => $order_dir,
				limit            => $limit,
				offset           => $offset,
				src_ip           => _param_list( $self, 'src_ip' ),
				dest_ip          => _param_list( $self, 'dest_ip' ),
				ip               => _param_list( $self, 'ip' ),
				port             => _param_list( $self, 'port' ),
				host             => _param_list( $self, 'host' ),
				instance_host    => _param_list( $self, 'instance_host' ),
				instance         => _param_list( $self, 'instance' ),
				class            => \@class,
				signature        => _param_list( $self, 'signature' ),
				subjects         => _param_list( $self, 'subjects' ),
				app_proto        => _param_list( $self, 'app_proto' ),
				proto            => _param_list( $self, 'proto' ),
				in_iface         => _param_list( $self, 'in_iface' ),
				event_id         => _param_list( $self, 'event_id' ),
				md5              => _param_list( $self, 'md5' ),
				sha1             => _param_list( $self, 'sha1' ),
				sha256           => _param_list( $self, 'sha256' ),
				subbed_from_ip   => _param_list( $self, 'subbed_from_ip' ),
				subbed_from_host => _param_list( $self, 'subbed_from_host' ),
				slug             => _param_list( $self, 'slug' ),
				pkg              => _param_list( $self, 'pkg' ),
				target           => _param_list( $self, 'target' ),
				username         => _param_list( $self, 'username' ),

				# which side of the deployment's own networks each end sits
				# on; the CIDR list itself is the config's, not the request's
				src_locality   => _param_list( $self, 'src_locality' ),
				dest_locality  => _param_list( $self, 'dest_locality' ),
				local_networks => $self->local_networks,

				# what the Shodan cache says about the alert's ends, and the
				# ids the rule names -- the enrichment filters
				shodan_src_tag    => _param_list( $self, 'shodan_src_tag' ),
				shodan_dest_tag   => _param_list( $self, 'shodan_dest_tag' ),
				shodan_src_known  => _param_list( $self, 'shodan_src_known' ),
				shodan_dest_known => _param_list( $self, 'shodan_dest_known' ),
				shodan_src_cvss   => _param_list( $self, 'shodan_src_cvss' ),
				shodan_dest_cvss  => _param_list( $self, 'shodan_dest_cvss' ),
				cve               => _param_list( $self, 'cve' ),

				shodan_src_cve_match  => _param_list( $self, 'shodan_src_cve_match' ),
				shodan_dest_cve_match => _param_list( $self, 'shodan_dest_cve_match' ),
				src_port              => \@src_port,
				dest_port             => \@dest_port,
				gid                   => \@gid,
				sid                   => \@sid,
				rev                   => \@rev,
				malscore              => \@malscore,
				size                  => \@size,
				task                  => \@task,
			);
		};
		$error = $@ if $@;
	}

	# The Subjects column of the baphomet results table shows each subject var
	# with the value it was seen as and the score it reached. That detail lives in
	# raw rather than in columns of its own, so decode it here and hand the
	# template the combined map to render its cell from. A row with no subject
	# vars at all gets an empty map and renders empty.
	if ( $table eq 'baphomet' && ref $results eq 'ARRAY' ) {
		foreach my $row (@$results) {
			my $decoded = eval { Mojo::JSON::from_json( $row->{raw} ) };
			$row->{subjects} = $self->baphomet_subjects($decoded);

			# What the Count cell's drill-down link filters subjects by: the
			# raw subject_vars re-encoded as JSON, which jsonb equality reads
			# as exactly the key the bucket was grouped on, or 'none' for a
			# record carrying no subject_vars (whose key is SQL NULL).
			if ($bucket) {
				$row->{subjects_key}
					= ( ref $decoded eq 'HASH' && exists $decoded->{subject_vars} )
					? Mojo::JSON::to_json( $decoded->{subject_vars} )
					: 'none';
			}
		} ## end foreach my $row (@$results)
	} ## end if ( $table eq 'baphomet' && ref $results ...)

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

	# What the Shodan cache already holds for the addresses on this page, for
	# the badges on their cells. One query for the page, and never a lookup --
	# an address with no cached entry simply gets no badges.
	my $shodan_badges = $self->shodan_badges($results);

	$self->stash(
		results   => $results,
		escalated => $escalated,

		shodan_badges => $shodan_badges,

		# Which rows fired a rule naming a CVE their destination's cached Shodan
		# entry says it is vulnerable to -- computed from the badges just
		# fetched, no query of its own.
		cve_matches => $self->cve_matches( $table, $results, $shodan_badges ),

		error           => $error,
		table           => $table,
		bucket          => $bucket,
		go_back_minutes => $go_back_minutes,
		order_by        => $order_by,
		order_dir       => $order_dir,
		limit           => $limit,
		offset          => $offset,

		# the sort picker's options, so the page does not keep its own copy of
		# which columns each table has
		order_by_columns_json => Mojo::JSON::to_json( $self->order_by_columns ),
	);

	# Auto-refresh fetches partial=1 to get just the results fragment (no layout
	# or filter form), which is far smaller than the full page.
	if ( $self->param('partial') && defined $results ) {
		return $self->render( 'search/_results', layout => undef );
	}
} ## end sub index

# GET /api/search/values -- what a filter field's dropdown offers: the most
# common values of that column over the window the search itself covers, most
# common first, as JSON. Fetched once per field when it is focused and filtered
# in the browser from there, so the whole list comes down in one request.
#
# The column is not vetted here. Lilith::Stats knows which columns each table
# may be grouped by and dies on anything else, and render_json_or_400 turns
# that into a 400 naming the problem -- so a field whose column the selected
# table cannot group by (the Sagan instance host on a CAPE search, say) gets a
# 400 and simply offers nothing, rather than needing its own list of what
# applies where.
#
# Args: none beyond the controller. The table, the column, and the window
# (go_back_minutes, or an explicit start/end) come off the query string. They
# are the same parameters the search ran with, so what is offered describes the
# rows the page is showing rather than all of history.
#
# Returns: nothing meaningful; renders
#
#     { table => 'suricata', column => 'instance',
#       values => [ { value => 'nibbles04', count => 812 }, ... ] }
#
# or, when Lilith::Stats dies, a 400 of { error => ... }.
sub filter_values {
	my $self = shift;

	my $table = $self->param('table') // 'suricata';
	$table = 'suricata' unless $self->valid_alert_table($table);

	my $column = $self->param('column');

	my $minutes = $self->param('go_back_minutes');
	$minutes = 1440 unless defined($minutes) && $minutes =~ /^[0-9]+$/;

	# An explicit range wins over the relative window, the same way it does for
	# the search, so the two describe the same rows.
	my @window;
	foreach my $bound (qw( start end )) {
		my $value = $self->param($bound);
		push( @window, $bound => $value ) if defined($value) && $value ne '';
	}

	return $self->render_json_or_400(
		sub {
			my $rows = $self->lilith->stats->top(
				table           => $table,
				column          => $column,
				go_back_minutes => $minutes,
				limit           => $VALUE_SUGGESTION_LIMIT,
				@window,
			);

			return { table => $table, column => $column, values => $rows };
		}
	);
} ## end sub filter_values

# Flatten the values submitted for a numeric filter into the list
# Lilith::search wants. The filter fields are multi valued, so a filter arrives
# as one query parameter per value, but a value may itself still be a comma
# separated list -- both because that is what the fields accepted before and
# because someone may paste one in. Whitespace either side of a comma is
# dropped, so the spacing someone typed does not become part of a value. Plain
# function, not a method.
#
# Args:
#
#   - @values :: the values as submitted, e.g. ( '22', '80' ) or ( '22, 80' ).
#     An empty list, or values that are undef or empty, mean the filter was
#     left blank.
#
# Returns: the values as a flat list, or the empty list for a blank field -- so
# the caller can assign straight into a filter hash and have a blank field add
# nothing rather than an empty-string filter that would match nothing.
#
#     _split_list('22, 80');       # ( '22', '80' )
#     _split_list( '22', '80' );   # ( '22', '80' )
#     _split_list('');             # ()
sub _split_list {
	return grep { $_ ne '' } map { split( /\s*,\s*/, $_ ) } grep { defined($_) && $_ ne '' } @_;
}

# Every value submitted for a filter, as the argument Lilith::search takes for
# it. The filter fields are multi valued -- one query parameter per value -- so
# a filter that used to be one string is now a list, which the search side ORs
# the positives of and ANDs the negations of. Plain function, not a method.
#
# Args:
#
#   - $controller :: the controller the request is on, for reading the
#     parameters. $self at every call site.
#
#   - $name :: the query parameter, e.g. 'instance'.
#
# Returns: an array ref of the non-empty values, or undef when the filter was
# left blank -- Lilith::search skips an undef filter, so a blank field adds
# nothing to the query.
#
#     _param_list( $self, 'instance' );
#     # on /search?instance=nibbles0%25&instance=inari-pie
#     # [ 'nibbles0%', 'inari-pie' ]
sub _param_list {
	my ( $controller, $name ) = @_;

	my @values = grep { defined($_) && $_ ne '' } @{ $controller->every_param($name) };

	return @values ? \@values : undef;
}

1;
