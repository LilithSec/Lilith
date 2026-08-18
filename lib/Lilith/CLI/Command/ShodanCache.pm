# shodan_cache -- fill the Shodan cache from the addresses recent alerts name,
# so the web UI's IP info modal and its results-table badges have something to
# show without anyone having looked each address up by hand first.
#
# Built to run on a timer. -s only bounds how far back each run reads; what
# stops an address being looked up twice is its own cache entry, so a window
# wider than the interval is safe and is what keeps an alert ingested between
# runs from being missed. -s 0 reads the whole table, for a first pass over a
# database that has been running a while.
#
# Shodan allows about one request a second, and this obeys that -- so a run
# costs roughly a second per address it has to look up. In steady state that is
# a handful; the first run against a busy sensor is not, which is what --limit
# is for.
#
#     lilith shodan_cache
#     lilith shodan_cache -s 900 --tables suricata,sagan
#     lilith shodan_cache -s 0 --limit 500      # backfill, 500 at a time
#     lilith shodan_cache -s 0 --force          # refetch everything held
#     lilith shodan_cache --ip 8.8.8.8          # refetch one address now
package Lilith::CLI::Command::ShodanCache;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::Shodan ();

sub command_names { 'shodan_cache' }

sub abstract { 'look up the addresses recent alerts name and cache what Shodan knows' }

sub opt_spec {
	my ($class) = @_;
	return (
		[ 'tables=s', 'comma separated alert tables to read' ],
		[ 's=s',      'how far back to read, in seconds; 0 for everything', { default => 180 } ],
		[ 'limit=s',  'stop after this many lookups; 0 for no limit',       { default => 0 } ],
		[ 'force',    'look up even addresses the cache already holds fresh' ],
		[ 'ip=s',     'update just this address instead of reading the alert tables; implies --force' ],
		[ 'dry-run',  'report what would be looked up without asking Shodan' ],
		$class->output_opt_spec,
	);
} ## end sub opt_spec

# Read the window, work out which addresses are worth asking about, ask, and
# store the answers.
#
# Three things are dropped before anything leaves the machine, in this order,
# because each is cheaper than the one after it: addresses that are not public
# (nothing to learn, and nothing that should be handed to a third party),
# addresses already held fresh in the cache (one query for the whole set), and
# anything past --limit.
#
# --force skips the freshness drop, refetching everything the window names --
# for after a schema change or a Shodan plan change, when what is held is
# stale in shape rather than in age. --ip skips the window read instead,
# taking the one named address as the whole candidate list; it implies
# --force, since asking to update an address that is held fresh would
# otherwise do nothing. The public-only drop is never skipped.
#
# Not gated on enable_shodan. That switch exists for the unauthenticated web
# frontend; running this command is already the operator saying so, the same
# reasoning that leaves the CLI escalation actions ungated. shodan_cache_ttl is
# needed, though -- with caching off there is nowhere to put an answer, and a
# run would be pure cost.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: whatever the chosen renderer returned. Prints a row per address
# looked up, and a summary line accounting for every address the window named
# -- including the ones dropped, so a run that did nothing says why rather than
# printing nothing. Exits 0 unless the database or the config is unusable; an
# address Shodan cannot answer for is a row, not a failure.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith = $self->lilith;
	my $toml   = $self->config;

	my $ttl
		= defined $toml->{shodan_cache_ttl} && $toml->{shodan_cache_ttl} =~ /^[0-9]+$/
		? $toml->{shodan_cache_ttl} + 0
		: 2592000;
	die("shodan_cache_ttl is 0, so there is nowhere to cache to; set it before running this\n") unless $ttl > 0;

	my $api_key = defined $toml->{shodan_api_key} ? $toml->{shodan_api_key} : '';
	my $source  = Lilith::Shodan::source($api_key);

	# See Lilith::Shodan::fetch for what history costs and buys.
	my $history = $toml->{shodan_history} ? 1 : 0;

	my @tables = grep { $_ ne '' } split( /\s*,\s*/, defined( $opt->{tables} ) ? $opt->{tables} : '' );

	my $ips
		= defined $opt->{ip} && $opt->{ip} ne ''
		? [ $opt->{ip} ]
		: $lilith->alert_ips( go_back_seconds => $opt->{s}, tables => \@tables );
	my $scanned = scalar @{$ips};

	# Public addresses only.
	my @public  = grep { !Lilith::Shodan::is_private_ip($_) } @{$ips};
	my $private = $scanned - scalar @public;

	# Whatever the cache already holds fresh, in one statement rather than one
	# per address. --force wants those refetched, so it skips the question
	# entirely; --ip is a request to update that address, which is the same ask.
	my @wanted = @public;
	my $fresh  = 0;
	unless ( $opt->{force} || defined $opt->{ip} ) {
		my $held = $lilith->shodan_cache_badges( ips => \@public, source => $source, ttl => $ttl );
		@wanted = grep { !$held->{$_} } @public;
		$fresh  = scalar(@public) - scalar(@wanted);
	}

	# --limit truncates, and says how much it left -- a run that quietly covered
	# part of its window would read as one that covered all of it.
	my $limit  = ( defined $opt->{limit} && $opt->{limit} =~ /^[0-9]+$/ ) ? $opt->{limit} + 0 : 0;
	my $capped = 0;
	if ( $limit > 0 && scalar(@wanted) > $limit ) {
		$capped = scalar(@wanted) - $limit;
		@wanted = @wanted[ 0 .. $limit - 1 ];
	}

	my @results;
	my $failed = 0;
	my $first  = 1;
	foreach my $ip (@wanted) {
		if ( $opt->{dry_run} ) {
			push( @results, { ip => $ip, status => 'would look up', ports => '', vulns => '', tags => '' } );
			next;
		}

		# Shodan's limit is about a request a second. Sleeping before each
		# lookup but the first keeps a run of one address instant.
		sleep(1) unless $first;
		$first = 0;

		my ( $info, $error, $raw ) = Lilith::Shodan::gather( $ip, $api_key, $source, $history );
		if ( $error ne '' ) {
			$failed++;
			push( @results, { ip => $ip, status => $error, ports => '', vulns => '', tags => '' } );
			next;
		}

		$lilith->shodan_cache_put( ip => $ip, source => $source, raw => $raw, info => $info, ttl => $ttl );

		push(
			@results,
			{
				ip     => $ip,
				status => ( keys %{$raw} ? 'cached' : 'cached, nothing known' ),
				ports  => scalar @{ $info->{ports} },
				vulns  => scalar @{ $info->{vulns} },
				tags   => join( ',', @{ $info->{tags} } ),
			}
		);
	} ## end foreach my $ip (@wanted)

	# A dry run has looked nothing up, so it must not be counted as having done
	# so; what it produced is a list of what a real run would ask about.
	my %summary = (
		scanned       => $scanned,
		private       => $private,
		fresh         => $fresh,
		looked_up     => ( $opt->{dry_run} ? 0                : scalar(@results) - $failed ),
		would_look_up => ( $opt->{dry_run} ? scalar(@results) : 0 ),
		failed        => $failed,
		not_reached   => $capped,
		source        => $source,
	);

	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( { summary => \%summary, results => \@results }, $opt->{pretty} ) },
		table => sub {
			if (@results) {
				my $tb = $self->table( 'IP', 'Status', 'Ports', 'CVEs', 'Tags' );
				$tb->add_rows(
					[ map { [ $_->{ip}, $_->{status}, $_->{ports}, $_->{vulns}, $_->{tags} ] } @results ] );
				print $tb->draw;
			}

			print 'scanned: '
				. $summary{scanned}
				. '  private: '
				. $summary{private}
				. '  already cached: '
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
