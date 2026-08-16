#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use_ok('Lilith') or BAIL_OUT('Lilith failed to load');

# ---------------------------------------------------------------------------
# Bucketed baphomet search against a real PostgreSQL: rows sharing an
# instance, signature, and subject_vars compress to the newest of them, which
# carries a bucket_count. Skipped where the server binaries are absent.
# ---------------------------------------------------------------------------

SKIP: {
	require TestPG;
	skip 'PostgreSQL server binaries not found', 1 unless TestPG->bindir;

	require DBIx::Class::Migration;
	require Lilith::Schema;

	my $pg = TestPG->new;
	DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $pg->dsn, $pg->user, $pg->pass ],
	)->install;

	my $dbh = $pg->dbh;

	# The buckets, newest row last per bucket:
	#   R1 / SRC 1.2.3.4 :: three rows (scores 1..3, the newest scoring 3)
	#   R1 / SRC 5.6.7.8 :: one row
	#   R2 / SRC 1.2.3.4 :: two rows
	#   R3 / no subjects :: two rows (a NULL subject key still buckets)
	#   R4 / two vars, one numeric :: two rows (for the structural match)
	# plus an old R1 / SRC 1.2.3.4 row outside the window, which must not
	# inflate that bucket's count.
	my @rows = (
		[ 'R1', '{"subject_vars":{"SRC":"1.2.3.4"}}',            '9 minutes',  1 ],
		[ 'R1', '{"subject_vars":{"SRC":"1.2.3.4"}}',            '8 minutes',  2 ],
		[ 'R1', '{"subject_vars":{"SRC":"1.2.3.4"}}',            '1 minute',   3 ],
		[ 'R1', '{"subject_vars":{"SRC":"5.6.7.8"}}',            '5 minutes',  1 ],
		[ 'R2', '{"subject_vars":{"SRC":"1.2.3.4"}}',            '10 minutes', 1 ],
		[ 'R2', '{"subject_vars":{"SRC":"1.2.3.4"}}',            '4 minutes',  2 ],
		[ 'R3', '{}',                                            '7 minutes',  1 ],
		[ 'R3', '{}',                                            '6 minutes',  2 ],
		[ 'R4', '{"subject_vars":{"USER":"srv","TRIES":3}}',     '3 minutes',  1 ],
		[ 'R4', '{"subject_vars":{"USER":"srv","TRIES":3}}',     '2 minutes',  2 ],
	);
	for my $r (@rows) {
		$dbh->do(
			"insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,signature,score,raw)"
				. " values ('i1','gate1', now() - interval '$r->[2]', 'e', 'sighting', ?, ?, ?::jsonb)",
			undef, $r->[0], $r->[3], $r->[1]
		);
	}
	$dbh->do( "insert into baphomet_alerts (instance,host,timestamp,event_id,event_type,signature,score,raw)"
			. " values ('i1','gate1', now() - interval '3 days', 'e', 'sighting', 'R1', 9,"
			. " '{\"subject_vars\":{\"SRC\":\"1.2.3.4\"}}'::jsonb)" );

	my $lilith = Lilith->new( dsn => $pg->dsn, user => $pg->user, pass => $pg->pass );

	# unbucketed: every windowed row, none carrying a bucket_count
	my $plain = $lilith->search( table => 'baphomet' );
	is( scalar @$plain, 10, 'unbucketed search returns every windowed row' );
	ok( !( grep { exists $_->{bucket_count} } @$plain ), 'unbucketed rows carry no bucket_count' );

	# bucketed: one row per (instance, signature, subject_vars), the newest,
	# counting the whole windowed bucket
	my $bucketed = $lilith->search( table => 'baphomet', bucket => 1, order_by => 'timestamp', order_dir => 'DESC' );
	is( scalar @$bucketed, 5, 'bucketed search compresses to one row per bucket' );

	my %by_key = map { ( $_->{signature} . '/' . ( $_->{raw} =~ /1\.2\.3\.4/ ? 'a' : $_->{raw} =~ /5\.6\.7\.8/ ? 'b' : '-' ) ) => $_ }
		@$bucketed;
	is( $by_key{'R1/a'}{bucket_count}, 3, 'a three row bucket counts 3 (the out-of-window row not among them)' );
	is( $by_key{'R1/a'}{score},        3, 'the surviving row is the newest of its bucket' );
	is( $by_key{'R1/b'}{bucket_count}, 1, 'a lone row counts 1' );
	is( $by_key{'R2/a'}{bucket_count}, 2, 'buckets split on signature' );
	is( $by_key{'R3/-'}{bucket_count}, 2, 'rows with no subject_vars still bucket together' );
	is( $by_key{'R3/-'}{score},        2, 'and also surface their newest row' );

	# ordering, paging, and filters apply to the buckets
	is( $bucketed->[0]{signature}, 'R1', 'ordering applies to the surviving rows' );
	my $page = $lilith->search(
		table    => 'baphomet',
		bucket   => 1,
		order_by => 'timestamp',
		order_dir => 'DESC',
		limit    => 2,
		offset   => 2,
	);
	is( scalar @$page, 2, 'limit/offset page the buckets, not the underlying rows' );
	my $filtered = $lilith->search( table => 'baphomet', bucket => 1, signature => 'R1' );
	is( scalar @$filtered, 2, 'filters compose with bucketing' );

	# on any other table the option is ignored, like a filter the table lacks
	my $suricata = $lilith->search( table => 'suricata', bucket => 1 );
	is_deeply( $suricata, [], 'bucket is ignored for a non-baphomet table rather than dying' );

	# -----------------------------------------------------------------------
	# The subjects filter: jsonb equality on raw->'subject_vars', the same key
	# bucketing partitions by -- what makes a bucket's count clickable.
	# -----------------------------------------------------------------------

	my $drilled = $lilith->search( table => 'baphomet', signature => 'R1', subjects => '{"SRC":"1.2.3.4"}' );
	is( scalar @$drilled, 3, 'a bucket key drills down to exactly the rows its count claimed' );

	# structural match: key order, whitespace, and number formatting are all
	# jsonb's problem, not the caller's
	my $reordered = $lilith->search( table => 'baphomet', subjects => '{ "TRIES" : 3.0, "USER" : "srv" }' );
	is( scalar @$reordered, 2, 'the match is structural, not textual' );

	# 'none' is the no-subjects bucket, whose key is SQL NULL
	my $subjectless = $lilith->search( table => 'baphomet', subjects => 'none' );
	is( scalar @$subjectless, 2, "'none' matches the records with no subject_vars" );

	# several values OR
	my $either = $lilith->search( table => 'baphomet', subjects => [ 'none', '{"SRC":"5.6.7.8"}' ] );
	is( scalar @$either, 3, 'several subjects values match any of them' );

	# garbage dies with the reason rather than a DB error
	eval { $lilith->search( table => 'baphomet', subjects => 'derp' ) };
	like( $@, qr/neither JSON/, 'a non-JSON subjects value dies clearly' );

	# and elsewhere the filter is ignored, garbage included
	my $sur_subj = $lilith->search( table => 'suricata', subjects => 'derp' );
	is_deeply( $sur_subj, [], 'subjects is ignored for a non-baphomet table rather than dying' );

	# -----------------------------------------------------------------------
	# The CLI: --bucket reaches search() the same way, and the automatic
	# column set gains a count column for a bucketed baphomet table.
	# -----------------------------------------------------------------------
	{
		require Lilith::CLI;
		require Lilith::CLI::Command::Search;
		Lilith::CLI->set_env_defaults;

		# the command reads its settings through config() and its database
		# handle through lilith(); stub both rather than standing up an App::Cmd
		no warnings qw(redefine once);
		local *Lilith::CLI::Command::config = sub { return {} };
		local *Lilith::CLI::Command::lilith = sub { return $lilith };
		use warnings qw(redefine once);

		# Run the search command with the given options, capturing what it printed.
		my $run_cmd = sub {
			my (%opt) = @_;
			$opt{t}         = 'baphomet' unless exists $opt{t};
			$opt{output}    = 'table'    unless exists $opt{output};
			$opt{columnset} = 'default'  unless exists $opt{columnset};

			my $cmd = bless {}, 'Lilith::CLI::Command::Search';
			my $out = '';
			open( my $fh, '>', \$out ) or die $!;
			my $old = select($fh);
			eval { $cmd->execute( \%opt, [] ) };
			my $err = $@;
			select($old);
			close($fh);

			return ( $out, $err );
		};

		my ( $out, $err ) = $run_cmd->( bucket => 1 );
		is( $err, '', 'bucketed CLI search runs cleanly' );
		like( $out, qr/count/, 'the bucketed table gains the count column' );

		( $out, $err ) = $run_cmd->();
		is( $err, '', 'unbucketed CLI search runs cleanly' );
		unlike( $out, qr/count/, 'the count column only appears when bucketed' );

		( $out, $err ) = $run_cmd->( bucket => 1, output => 'json' );
		is( $err, '', 'bucketed CLI search renders as JSON' );
		like( $out, qr/"bucket_count"\s*:\s*3/, 'the JSON rows carry bucket_count' );

		( $out, $err ) = $run_cmd->( output => 'json', subjects => ['{"SRC":"1.2.3.4"}'] );
		is( $err, '', 'CLI --subjects runs cleanly' );
		like( $out, qr/R1/, '--subjects keeps the rows about that subject' );
		like( $out, qr/R2/, 'across every rule that judged it' );
		unlike( $out, qr/R3|R4/, 'and drops the rows about other subjects' );
	}
}

done_testing();
