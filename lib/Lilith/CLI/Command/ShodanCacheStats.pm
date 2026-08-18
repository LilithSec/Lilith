# shodan_cache_stats -- summarize the shodan_cache table: how much it holds,
# how it breaks down by source and answer, how fresh it is, and how far the
# enrichment columns have been filled. That last is what says whether a
# `lilith shodan_cache` backfill still has rows to reach after a schema upgrade.
#
# Reads only; nothing is looked up and nothing is written, so it is safe against
# a live database.
#
#     lilith shodan_cache_stats
#     lilith shodan_cache_stats --top 10
#     lilith shodan_cache_stats -o json --pretty
package Lilith::CLI::Command::ShodanCacheStats;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';

sub command_names { 'shodan_cache_stats' }

sub abstract { 'summarize the shodan_cache table: size, breakdown, freshness, and backfill coverage' }

sub description {
	return
		  "Summarizes the shodan_cache table: total cached addresses, the found/not-found\n"
		. "and api/internetdb breakdowns, how many rows are still fresh, and how far the\n"
		. "callout and product columns have been backfilled since the last schema upgrade.\n"
		. "Also lists the most common tags, products, ports, orgs, and callouts. Reads\n"
		. "dsn/user/pass from the config file and changes nothing.";
}

sub opt_spec {
	my ($class) = @_;
	return (
		[ 'ttl=s', 'freshness window in seconds; defaults to the config shodan_cache_ttl' ],
		[ 'top=s', 'how many top values to show per facet; 0 for none', { default => 5 } ],
		$class->output_opt_spec,
	);
} ## end sub opt_spec

# Gather the summary and the top facet values, and render them.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned. Prints a metric/value table
# and, unless --top 0, a short table of the most common values of each facet the
# schema carries. Reads only; exits 0 unless the database or config is unusable.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;
	my $toml   = $self->config;

	# --ttl wins, then the config, then the same month the cache defaults to.
	my $ttl
		= ( defined $opt->{ttl} && $opt->{ttl} =~ /^[0-9]+$/ ) ? $opt->{ttl} + 0
		: ( defined $toml->{shodan_cache_ttl} && $toml->{shodan_cache_ttl} =~ /^[0-9]+$/ )
		? $toml->{shodan_cache_ttl} + 0
		:   2592000;

	my $top = ( defined $opt->{top} && $opt->{top} =~ /^[0-9]+$/ ) ? $opt->{top} + 0 : 5;

	my $stats = $lilith->shodan_cache_stats( ttl => $ttl );

	# The most common values of each facet the schema supports. shodan_cache_values
	# dies naming a column an older schema lacks; that is caught so the stats still
	# print, just without that facet.
	my @facets = (
		[ tag     => 'tags' ],
		[ product => 'products' ],
		[ port    => 'ports' ],
		[ org     => 'orgs' ],
		[ callout => 'callouts' ],
	);
	my %top_values;
	if ( $top > 0 ) {
		for my $facet (@facets) {
			my $rows = eval { $lilith->shodan_cache_values( column => $facet->[0], limit => $top ); };
			$top_values{ $facet->[0] } = $rows if ref $rows eq 'ARRAY' && @{$rows};
		}
	}

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( { ttl => $ttl, summary => $stats, top => \%top_values }, $opt->{pretty} ) },
		table => sub {
			my $tb   = $self->table( 'Metric', 'Value' );
			my @rows = (
				[ 'cached addresses',          $stats->{total} ],
				[ 'found',                     $stats->{found} ],
				[ 'not found (nothing known)', $stats->{not_found} ],
				[ 'source: api',               $stats->{by_source}{api} ],
				[ 'source: internetdb',        $stats->{by_source}{internetdb} ],
			);
			push( @rows, [ 'fresh (within ' . $ttl . 's)', $stats->{fresh} ] ) if exists $stats->{fresh};
			push( @rows, [ 'with CVEs',     $stats->{with_vulns} ] );
			push( @rows, [ 'max CVSS >= 9', $stats->{high_cvss} ] );
			push( @rows, [ 'with callouts (v18)', $stats->{with_callouts} . ' / ' . $stats->{total} ] )
				if exists $stats->{with_callouts};
			push( @rows, [ 'with products (v19)', $stats->{with_products} . ' / ' . $stats->{total} ] )
				if exists $stats->{with_products};
			push( @rows, [ 'oldest fetch', defined $stats->{oldest} ? $stats->{oldest} : '(none)' ] );
			push( @rows, [ 'newest fetch', defined $stats->{newest} ? $stats->{newest} : '(none)' ] );
			$tb->add_rows( \@rows );
			print $tb->draw;

			for my $facet (@facets) {
				my $rows = $top_values{ $facet->[0] };
				next unless $rows;
				print "\ntop " . $facet->[1] . ":\n";
				my $ft = $self->table( 'Value', 'Count' );
				$ft->add_rows( [ map { [ $_->{value}, $_->{count} ] } @{$rows} ] );
				print $ft->draw;
			} ## end for my $facet (@facets)

			return;
		},
	);
} ## end sub execute

1;
