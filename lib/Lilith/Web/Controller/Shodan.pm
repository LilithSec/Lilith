package Lilith::Web::Controller::Shodan;

use Mojo::Base 'Mojolicious::Controller';

# How many values a filter field's dropdown is offered, matching the search
# page's cap: the list is fetched once per field and filtered in the browser
# as someone types.
my $VALUE_SUGGESTION_LIMIT = 200;

=head1 NAME

Lilith::Web::Controller::Shodan - browse the Shodan cache.

=head1 DESCRIPTION

Serves the C</shodan> cache browser: search and display of what the
C<shodan_cache> table holds, through C<Lilith::shodan_cache_search>. Every
other view of the cache starts from an address on an alert; this page starts
from the cache itself -- which cached hosts carry a tag, a port, a CVE. The
page (and its nav entry) exists only when C<shodan_enable> is set, since the
cache is that feature's; it never looks anything up.

=cut

# The filters the page offers, in the names shodan_cache_search takes them
# by. The controller forwards each as one array ref of the submitted values,
# and the template renders its form fields and filter chips from the same
# names, so a new filter is an edit to the search method and the template's
# field list rather than here.
my @FILTERS = qw( ip hostname tag port cve cpe os org isp asn found source max_cvss );

# GET /shodan -- the filter form and its results. Reads every filter off the
# query string, sanitizes the two that are spliced rather than bound (the
# sort column and direction) plus the numerics, and renders. With no
# parameters at all the landing page is the whole cache, newest fetch first.
#
# Args: none beyond the controller. Everything comes off the query string.
#
# Returns: nothing meaningful; renders the page. A search that dies -- a bad
# filter value, an unreachable database, a missing shodan_cache table -- is
# caught and shown as an error on the page rather than becoming a 500.
sub index {
	my $self = shift;

	# The whole page describes the Shodan enrichment's cache; with the feature
	# off there is nothing behind it, so it 404s the same way the escalation
	# views do without theirs.
	return $self->reply->not_found unless $self->shodan_enable;

	my $order_by       = $self->param('order_by')               // 'fetched';
	my $order_dir      = $self->param('order_dir')              // 'DESC';
	my $limit          = $self->param('limit')                  // 100;
	my $offset         = $self->param('offset')                 // 0;
	my $fetched_within = $self->param('fetched_within_minutes') // 0;

	# Sanitize. order_by's vocabulary is the search method's; anything else
	# falls back rather than dying, the same as the alert search page.
	$order_by = 'fetched'
		unless grep { $_ eq $order_by } qw( fetched ip source found last_update max_cvss os org isp asn );
	$order_dir      = 'DESC' unless $order_dir      =~ /^(?:ASC|DESC)$/;
	$limit          = 100    unless $limit          =~ /^[0-9]+$/ && $limit > 0;
	$offset         = 0      unless $offset         =~ /^[0-9]+$/;
	$fetched_within = 0      unless $fetched_within =~ /^[0-9]+$/;

	# Each filter as an array ref of its non-empty values -- the fields are
	# multi valued, one query parameter per value -- absent entirely when
	# blank, so a blank field adds nothing to the query.
	my %filters;
	for my $name (@FILTERS) {
		my @values = grep { defined($_) && $_ ne '' } @{ $self->every_param($name) };
		$filters{$name} = \@values if @values;
	}

	my ( $results, $error );
	eval {
		$results = $self->lilith->shodan_cache_search(
			%filters,
			fetched_within_minutes => $fetched_within,
			order_by               => $order_by,
			order_dir              => $order_dir,
			limit                  => $limit,
			offset                 => $offset,
		);
	};
	$error = $@ if $@;

	$self->stash(
		results                => $results,
		error                  => $error,
		order_by               => $order_by,
		order_dir              => $order_dir,
		limit                  => $limit,
		offset                 => $offset,
		fetched_within_minutes => $fetched_within,
	);

	return;
} ## end sub index

# GET /api/shodan/values -- what a filter field's dropdown offers: the most
# common values of that column across the cache, most common first, as JSON.
# Fetched once per field when it is focused and filtered in the browser from
# there, the same contract as /api/search/values.
#
# The column is not vetted here. shodan_cache_values knows which columns have
# values to offer and dies on anything else, and render_json_or_400 turns that
# into a 400 naming the problem.
#
# Args: none beyond the controller. The column and the optional fetched window
# come off the query string; the window is the same parameter the search ran
# with, so what is offered describes the rows the page is showing.
#
# Returns: nothing meaningful; renders
#
#     { column => 'tag', values => [ { value => 'cloud', count => 41 }, ... ] }
#
# or, when shodan_cache_values dies, a 400 of { error => ... }. 404s with the
# feature off, the same as the page itself.
sub filter_values {
	my $self = shift;

	return $self->reply->not_found unless $self->shodan_enable;

	my $column = $self->param('column');

	my $minutes = $self->param('fetched_within_minutes') // 0;
	$minutes = 0 unless $minutes =~ /^[0-9]+$/;

	return $self->render_json_or_400(
		sub {
			my $rows = $self->lilith->shodan_cache_values(
				column                 => $column,
				fetched_within_minutes => $minutes,
				limit                  => $VALUE_SUGGESTION_LIMIT,
			);

			return { column => $column, values => $rows };
		}
	);
} ## end sub filter_values

1;
