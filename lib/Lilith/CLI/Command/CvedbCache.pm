# cvedb_cache -- look up the CVE ids the Shodan cache names and store what
# CVEDB knows about each, so the web UI can annotate the CVEs it shows -- the
# score, the EPSS exploitation probability, the CISA KEV flag, known
# ransomware use -- without asking anyone per render.
#
# Built to run on a timer, like shodan_cache, and windowed the same way: -s
# only bounds how far back in shodan_cache each run reads, against each row's
# fetched time -- a newly cached or freshly refreshed address is what
# introduces new ids. What stops an id being fetched twice is its own cache
# entry, so a window wider than the interval is safe. The default is twice
# shodan_cache's own default window, so a run of this sees everything a run
# of that cached between the two; -s 0 reads the whole table, for a first
# pass.
#
# Within the window, ids the CVEDB cache has never seen go first, then rows
# older than cvedb_cache_ttl, oldest first. Stale rows are still served in
# the meantime -- CVE detail only firms up, so the refresh is about drift
# (EPSS moves a little daily, KEV grows), not correctness. An id whose row
# has gone stale re-enters a run when an address naming it is fetched or
# refreshed inside the window, which shodan_cache's own TTL cycle sees to;
# a -s 0 run sweeps everything on demand.
#
# CVEDB is free and keyless, and the pacing here is a lookup a second out of
# politeness -- so a run costs roughly a second per id it has to fetch. In
# steady state that is a handful; a -s 0 pass over a cache that has been
# filling for a while is every id it holds, which is what --limit is for.
#
#     lilith cvedb_cache
#     lilith cvedb_cache --dry-run
#     lilith cvedb_cache -s 1200            # for a fifteen minute timer
#     lilith cvedb_cache -s 0 --limit 200   # backfill, 200 at a time
package Lilith::CLI::Command::CvedbCache;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CVEDB ();

sub command_names { 'cvedb_cache' }

sub abstract { 'look up the CVE ids the Shodan cache names and cache what CVEDB knows' }

sub opt_spec {
	my ($class) = @_;
	return (
		[ 's=s',     'how far back to read shodan_cache, in seconds; 0 for everything', { default => 360 } ],
		[ 'limit=s', 'stop after this many lookups; 0 for no limit',                    { default => 0 } ],
		[ 'dry-run', 'report what would be looked up without asking CVEDB' ],
		$class->output_opt_spec,
	);
}

# Read the ids, work out which are worth asking about, ask, and store the
# answers.
#
# Two things are dropped before anything leaves the machine: anything that is
# not a CVE id in canonical form (the ids come out of other people's data, and
# what is not understood is not sent anywhere), and anything the cache already
# holds fresh -- one query for the whole set. --limit then truncates what is
# left, and says how much it left.
#
# Not gated on anything but cvedb_cache_ttl having a sane value: CVEDB needs
# no key, and running this command is already the operator saying so, the
# same reasoning as shodan_cache.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned. Prints a row per id looked
# up, and a summary line accounting for every id scanned -- including the ones
# dropped, so a run that did nothing says why rather than printing nothing.
# Exits 0 unless the database or the config is unusable; an id CVEDB cannot
# answer for is a row, not a failure.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;
	my $toml   = $self->config;

	my $ttl
		= defined $toml->{cvedb_cache_ttl} && $toml->{cvedb_cache_ttl} =~ /^[0-9]+$/
		? $toml->{cvedb_cache_ttl} + 0
		: 604800;
	die("cvedb_cache_ttl is 0, so every run would refetch everything; set it before running this\n") unless $ttl > 0;

	my $ids     = $lilith->shodan_cache_cves( go_back_seconds => $opt->{s} );
	my $scanned = scalar @{$ids};

	# Canonical CVE ids only.
	my @cves     = grep { Lilith::CVEDB::is_cve_id($_) } @{$ids};
	my $not_cves = $scanned - scalar @cves;

	# What the cache does not hold fresh, in one statement rather than one per
	# id: never-seen ids first, then stale rows oldest first, so a capped run
	# spends its lookups on what the cache knows least about.
	my @wanted = @{ $lilith->cvedb_cache_stale( cves => \@cves, ttl => $ttl ) };
	my $fresh  = scalar(@cves) - scalar(@wanted);

	# --limit truncates, and says how much it left -- a run that quietly covered
	# part of the backlog would read as one that covered all of it.
	my $limit  = ( defined $opt->{limit} && $opt->{limit} =~ /^[0-9]+$/ ) ? $opt->{limit} + 0 : 0;
	my $capped = 0;
	if ( $limit > 0 && scalar(@wanted) > $limit ) {
		$capped = scalar(@wanted) - $limit;
		@wanted = @wanted[ 0 .. $limit - 1 ];
	}

	my @results;
	my $failed = 0;
	my $first  = 1;
	foreach my $cve (@wanted) {
		if ( $opt->{dry_run} ) {
			push( @results,
				{ cve => $cve, status => 'would look up', cvss => '', epss => '', kev => '', ransomware => '' } );
			next;
		}

		# A lookup a second out of politeness. Sleeping before each but the
		# first keeps a run of one id instant.
		sleep(1) unless $first;
		$first = 0;

		my ( $info, $error, $raw ) = Lilith::CVEDB::gather($cve);
		if ( $error ne '' ) {
			$failed++;
			push( @results, { cve => $cve, status => $error, cvss => '', epss => '', kev => '', ransomware => '' } );
			next;
		}

		$lilith->cvedb_cache_put( cve => $cve, raw => $raw, info => $info );

		push(
			@results,
			{
				cve        => $cve,
				status     => ( keys %{$raw} ? 'cached' : 'cached, nothing known' ),
				cvss       => $info->{cvss},
				epss       => $info->{epss},
				kev        => ( $info->{kev}        ? 'yes' : '' ),
				ransomware => ( $info->{ransomware} ? 'yes' : '' ),
			}
		);
	} ## end foreach my $cve (@wanted)

	# A dry run has looked nothing up, so it must not be counted as having done
	# so; what it produced is a list of what a real run would ask about.
	my %summary = (
		scanned       => $scanned,
		not_cves      => $not_cves,
		fresh         => $fresh,
		looked_up     => ( $opt->{dry_run} ? 0                : scalar(@results) - $failed ),
		would_look_up => ( $opt->{dry_run} ? scalar(@results) : 0 ),
		failed        => $failed,
		not_reached   => $capped,
	);

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( { summary => \%summary, results => \@results }, $opt->{pretty} ) },
		table => sub {
			if (@results) {
				my $tb = $self->table( 'CVE', 'Status', 'CVSS', 'EPSS', 'KEV', 'Ransomware' );
				$tb->add_rows(
					[
						map { [ $_->{cve}, $_->{status}, $_->{cvss}, $_->{epss}, $_->{kev}, $_->{ransomware} ] }
							@results
					]
				);
				print $tb->draw;
			} ## end if (@results)

			print 'scanned: '
				. $summary{scanned}
				. '  not CVE ids: '
				. $summary{not_cves}
				. '  already fresh: '
				. $summary{fresh}
				. ( $opt->{dry_run} ? '  would look up: ' . $summary{would_look_up} : '' )
				. '  looked up: '
				. $summary{looked_up}
				. '  failed: '
				. $summary{failed}
				. '  not reached: '
				. $summary{not_reached} . "\n";

			return;
		},
	);
} ## end sub execute

1;
