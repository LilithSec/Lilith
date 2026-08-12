#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use Lilith                 ();
use Lilith::CLI            ();
use Lilith::Schema         ();
use DBIx::Class::Migration ();
use JSON                   ();

# The table renderer reads its border and color styles out of the environment,
# and Lilith::CLI sets those before dispatching. These runs bypass App::Cmd, so
# set them the same way rather than leaving Text::ANSITable with a blank style.
Lilith::CLI->set_env_defaults;

# `lilith cvedb_cache` against a real PostgreSQL server: TestPG initdb's a
# throwaway cluster, the schema is deployed into it, and the command runs its
# real selection against real rows.
#
# Every run here is --dry-run, so nothing is asked of CVEDB -- what is under
# test is which ids the command decides are worth asking about, which is the
# part that has to be right. The lookup itself is covered by t/lilith-cvedb.t
# and the cache methods by t/pg-migrate.t.
use TestPG ();

plan skip_all => 'PostgreSQL server binaries (initdb/pg_ctl/postgres) not found'
	unless TestPG->bindir;

use_ok('Lilith::CLI::Command::CvedbCache') or BAIL_OUT('CvedbCache failed to load');

my $pg = eval { TestPG->new };
BAIL_OUT("could not start PostgreSQL: $@") unless $pg;

DBIx::Class::Migration->new(
	schema_class => 'Lilith::Schema',
	schema_args  => [ $pg->dsn, $pg->user, $pg->pass ],
)->dbic_dh->install;

my $lilith = Lilith->new( dsn => $pg->dsn, user => $pg->user, pass => $pg->pass );

# The command reads its settings through config() and its database handle
# through lilith(); stub both rather than standing up an App::Cmd.
my %cfg = ( cvedb_cache_ttl => 3600 );
{
	no warnings qw(redefine once);
	*Lilith::CLI::Command::config = sub { return \%cfg };
	*Lilith::CLI::Command::lilith = sub { return $lilith };
}

# Run the command with the given options, capturing what it printed.
sub run_cmd {
	my (%opt) = @_;

	$opt{s}      = 600     unless exists $opt{s};
	$opt{limit}  = 0       unless exists $opt{limit};
	$opt{output} = 'table' unless exists $opt{output};

	my $cmd = bless {}, 'Lilith::CLI::Command::CvedbCache';
	my $out = '';
	open( my $fh, '>', \$out ) or die $!;
	my $old = select($fh);
	eval { $cmd->execute( \%opt, [] ) };
	my $err = $@;
	select($old);
	close($fh);

	return ( $out, $err );
} ## end sub run_cmd

my $dbh = $pg->dbh;

# ---------------------------------------------------------------------------
# 1.  A zero refresh window would refetch everything every run
# ---------------------------------------------------------------------------

{
	local $cfg{cvedb_cache_ttl} = 0;
	my ( undef, $err ) = run_cmd();
	like( $err, qr/refetch everything/, 'a zero ttl stops the command rather than burning lookups' );
}

# ---------------------------------------------------------------------------
# 2.  The ids come from shodan_cache, deduped, and only real CVE ids are
#     candidates
# ---------------------------------------------------------------------------

{
	# Two addresses sharing a CVE, and one id that is not a CVE at all.
	$lilith->shodan_cache_put(
		ip     => '45.0.0.1',
		source => 'internetdb',
		raw    => { vulns => [ 'CVE-2021-40438',            'CVE-2019-0217',            'NOT-A-CVE' ] },
		info   => { vulns => [ { cve => 'CVE-2021-40438' }, { cve => 'CVE-2019-0217' }, { cve => 'NOT-A-CVE' } ] },
		ttl    => 3600,
	);
	$lilith->shodan_cache_put(
		ip     => '45.0.0.2',
		source => 'internetdb',
		raw    => { vulns => ['CVE-2019-0217'] },
		info   => { vulns => [ { cve => 'CVE-2019-0217' } ] },
		ttl    => 3600,
	);

	my ( $out, $err ) = run_cmd( dry_run => 1 );
	is( $err, '', 'a dry run lives' );

	like( $out, qr/scanned: 3/,       'every distinct id shodan_cache names is counted as scanned' );
	like( $out, qr/not CVE ids: 1/,   'what is not a CVE id is dropped' );
	like( $out, qr/would look up: 2/, 'only the real ids are candidates' );
	like( $out, qr/looked up: 0/,     'a dry run reports nothing as looked up' );
	unlike( $out, qr/NOT-A-CVE/, 'a non-CVE id is never listed' );

	# and the shared CVE is one candidate, not two
	my $rows = () = $out =~ /CVE-2019-0217/g;
	is( $rows, 1, 'a CVE named by several addresses is one candidate' );
}

# ---------------------------------------------------------------------------
# 3.  An id already cached fresh is left alone; a stale one queues behind the
#     never-seen
# ---------------------------------------------------------------------------

{
	$lilith->cvedb_cache_put(
		cve  => 'CVE-2019-0217',
		raw  => { cvss => 7.5 },
		info => { cvss => 7.5, epss => '', kev => 0, ransomware => 0 },
	);

	my ($out) = run_cmd( dry_run => 1 );
	like( $out, qr/already fresh: 1/, 'the cached id is counted as fresh' );
	like( $out, qr/would look up: 1/, 'and is no longer a candidate' );
	unlike( $out, qr/CVE-2019-0217/, 'and is not listed' );

	# Aged past the ttl it is a candidate again -- after the never-seen id, so
	# a capped run spends its lookups on what the cache knows least about.
	$dbh->do(q{update cvedb_cache set fetched = now() - interval '2 hours' where cve = 'CVE-2019-0217'});
	my ($stale) = run_cmd( dry_run => 1 );
	like( $stale, qr/would look up: 2/, 'a stale row is due again' );

	my ($capped) = run_cmd( dry_run => 1, limit => 1 );
	like( $capped, qr/would look up: 1/, '--limit bounds the run' );
	like( $capped, qr/not reached: 1/,   'and what it left behind is reported rather than silently dropped' );
	like( $capped, qr/CVE-2021-40438/,   'the never-seen id goes first' );
	unlike( $capped, qr/CVE-2019-0217/, 'the merely stale one waits' );
}

# ---------------------------------------------------------------------------
# 4.  JSON output carries the same accounting
# ---------------------------------------------------------------------------

{
	my ($json) = run_cmd( dry_run => 1, output => 'json' );
	my $decoded = eval { JSON::decode_json($json) };
	is( $@,                             '', 'json output parses' );
	is( $decoded->{summary}{looked_up}, 0,  'a dry run looked nothing up' );
	is( $decoded->{summary}{not_cves},  1,  'the summary carries the dropped ids' );
	ok( scalar @{ $decoded->{results} }, 'the candidates come back as rows' );
	is( $decoded->{results}[0]{status}, 'would look up', 'each row says what would happen to it' );
}

# ---------------------------------------------------------------------------
# 5.  The window bounds what is read
# ---------------------------------------------------------------------------

{
	$lilith->shodan_cache_put(
		ip     => '45.0.0.3',
		source => 'internetdb',
		raw    => { vulns => ['CVE-2020-11984'] },
		info   => { vulns => [ { cve => 'CVE-2020-11984' } ] },
		ttl    => 3600,
	);
	$dbh->do(q{update shodan_cache set fetched = now() - interval '2 days' where ip = '45.0.0.3'});

	my ($windowed) = run_cmd( dry_run => 1 );
	unlike( $windowed, qr/CVE-2020-11984/, 'an address cached outside the window is not read' );

	my ($everything) = run_cmd( dry_run => 1, s => 0 );
	like( $everything, qr/CVE-2020-11984/, 'a window of 0 reads the whole table' );
}

$dbh->disconnect;
$pg->stop;

done_testing;
