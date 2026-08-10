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

# The table renderer reads its border and color styles out of the environment,
# and Lilith::CLI sets those before dispatching. These runs bypass App::Cmd, so
# set them the same way rather than leaving Text::ANSITable with a blank style.
Lilith::CLI->set_env_defaults;

# `lilith shodan_cache` against a real PostgreSQL server: TestPG initdb's a
# throwaway cluster, the schema is deployed into it, and the command runs its
# real selection against real rows.
#
# Every run here is --dry-run, so nothing is asked of Shodan -- what is under
# test is which addresses the command decides are worth asking about, which is
# the part that has to be right. The lookup itself is covered by
# t/lilith-shodan.t and t/pg-migrate.t.
#
# The public addresses below are 45.0.0.x rather than the usual documentation
# ranges, because the command deliberately treats 192.0.2/24, 198.51.100/24,
# and 203.0.113/24 as addresses never to send anywhere -- so a fixture drawn
# from them would be dropped before the selection under test ever ran. Nothing
# is contacted either way; these runs make no requests at all.
use TestPG ();

plan skip_all => 'PostgreSQL server binaries (initdb/pg_ctl/postgres) not found'
	unless TestPG->bindir;

use_ok('Lilith::CLI::Command::ShodanCache') or BAIL_OUT('ShodanCache failed to load');

my $pg = eval { TestPG->new };
BAIL_OUT("could not start PostgreSQL: $@") unless $pg;

DBIx::Class::Migration->new(
	schema_class => 'Lilith::Schema',
	schema_args  => [ $pg->dsn, $pg->user, $pg->pass ],
)->dbic_dh->install;

my $lilith = Lilith->new( dsn => $pg->dsn, user => $pg->user, pass => $pg->pass );

# The command reads its Shodan settings through config() and its database
# handle through lilith(); stub both rather than standing up an App::Cmd.
my %cfg = ( shodan_cache_ttl => 3600 );
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

	my $cmd = bless {}, 'Lilith::CLI::Command::ShodanCache';
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

sub add_alert {
	my ( $src, $dest ) = @_;
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now(),?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', '1', $src, $dest, 'Misc Attack', 'sig', '{}'
	);
	return;
}

# ---------------------------------------------------------------------------
# 1.  With caching off there is nowhere to put an answer
# ---------------------------------------------------------------------------

{
	local $cfg{shodan_cache_ttl} = 0;
	my ( undef, $err ) = run_cmd();
	like( $err, qr/nowhere to cache to/, 'a zero cache ttl stops the command rather than burning lookups' );
}

# ---------------------------------------------------------------------------
# 2.  Only public addresses are ever candidates
# ---------------------------------------------------------------------------

{
	add_alert( '45.0.0.1', '10.0.0.5' );       # one public, one RFC 1918
	add_alert( '45.0.0.1', '192.168.1.1' );    # the same public one again
	add_alert( '45.0.0.2', '172.16.0.1' );     # another public, another private

	my ( $out, $err ) = run_cmd( dry_run => 1 );
	is( $err, '', 'a dry run lives' );

	like( $out, qr/scanned: 5/,       'every distinct address in the window is counted as scanned' );
	like( $out, qr/private: 3/,       'the private addresses are dropped' );
	like( $out, qr/would look up: 2/, 'only the public ones are candidates' );
	like( $out, qr/looked up: 0/,     'a dry run reports nothing as looked up' );
	like( $out, qr/45\.0\.0\.1/,      'the public address is listed' );
	unlike( $out, qr/10\.0\.0\.5/, 'a private address is never listed' );

	# and the repeat is one candidate, not two
	my $rows = () = $out =~ /45\.0\.0\.1/g;
	is( $rows, 1, 'an address on several alerts is one candidate' );
}

# ---------------------------------------------------------------------------
# 3.  An address already cached fresh is left alone
# ---------------------------------------------------------------------------

{
	$lilith->shodan_cache_put(
		ip     => '45.0.0.1',
		source => 'internetdb',
		raw    => { ports => [443] },
		info   => { ports => [443] },
		ttl    => 3600
	);

	my ($out) = run_cmd( dry_run => 1 );
	like( $out, qr/already cached: 1/, 'the cached address is counted as fresh' );
	like( $out, qr/would look up: 1/,  'and is no longer a candidate' );
	unlike( $out, qr/45\.0\.0\.1/, 'and is not listed' );

	# a row written by the other tier does not count -- it is a shallower answer
	local $cfg{shodan_api_key} = 'abc123';
	my ($keyed) = run_cmd( dry_run => 1 );
	like( $keyed, qr/already cached: 0/, 'a keyless row is not fresh once a key is configured' );
	like( $keyed, qr/would look up: 2/,  'so it becomes a candidate again' );
}

# ---------------------------------------------------------------------------
# 4.  --limit truncates, and says so
# ---------------------------------------------------------------------------

{
	my ($out) = run_cmd( dry_run => 1, limit => 1 );
	like( $out, qr/would look up: 1/, '--limit bounds how many are taken' );
	like( $out, qr/not reached: 0/,   'with one candidate left there is nothing to leave behind' );

	local $cfg{shodan_api_key} = 'abc123';    # two candidates again
	my ($capped) = run_cmd( dry_run => 1, limit => 1 );
	like( $capped, qr/would look up: 1/, '--limit still bounds the run' );
	like( $capped, qr/not reached: 1/,   'and what it left behind is reported rather than silently dropped' );
}

# ---------------------------------------------------------------------------
# 5.  The window bounds what is read
# ---------------------------------------------------------------------------

{
	$dbh->do(
		q{insert into suricata_alerts (instance,host,timestamp,event_id,src_ip,dest_ip,classification,signature,raw)
		  values (?,?,now() - interval '2 days',?,?,?,?,?,?)},
		undef, 's1', 's1.example.org', '9', '45.0.0.3', '10.0.0.9', 'Misc Attack', 'sig', '{}'
	);

	my ($windowed) = run_cmd( dry_run => 1 );
	unlike( $windowed, qr/45\.0\.0\.3/, 'an alert outside the window is not read' );

	my ($everything) = run_cmd( dry_run => 1, s => 0 );
	like( $everything, qr/45\.0\.0\.3/, 'a window of 0 reads the whole table' );
}

# ---------------------------------------------------------------------------
# 6.  JSON output carries the same accounting
# ---------------------------------------------------------------------------

{
	my ($json) = run_cmd( dry_run => 1, output => 'json' );
	my $decoded = eval { JSON::decode_json($json) };
	is( $@,                             '',           'json output parses' );
	is( $decoded->{summary}{source},    'internetdb', 'the summary names the tier that would answer' );
	is( $decoded->{summary}{looked_up}, 0,            'a dry run looked nothing up' );
	ok( scalar @{ $decoded->{results} }, 'the candidates come back as rows' );
	is( $decoded->{results}[0]{status}, 'would look up', 'each row says what would happen to it' );
}

$dbh->disconnect;
$pg->stop;

done_testing;
