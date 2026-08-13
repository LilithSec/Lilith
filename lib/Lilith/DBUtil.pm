package Lilith::DBUtil;

use strict;
use warnings;
use DBI      ();
use Exporter qw( import );

our @EXPORT_OK = qw(
	clamped_int
	column_exists
	connect_cached_dbh
	host_or_text_expr
	measure_expr
	skip_scan_viable
	time_window_clause
	validate_bucket
);

=head1 NAME

Lilith::DBUtil - shared query-building helpers for the read-only DB readers.

=head1 DESCRIPTION

L<Lilith::Stats> (the alert tables) and L<Lilith::Allani> (the Allani log
store) each author small read-only aggregation queries and used to carry
private copies of the same scaffolding: the cached DBI connect, the
time-window WHERE clause, the bucket/measure validation, and the INET
C<host()> value handling. Those copies had already started to drift, so they
live here once and both readers import what they need.

The two readers render SQL slightly differently (Stats splices quoted
literals so its fragments can be reused verbatim inside subqueries; Allani
binds placeholders) and those exact strings are part of their tested
behavior, so C<time_window_clause> takes the rendering style as arguments
rather than forcing one on both.

=head1 FUNCTIONS

=head2 connect_cached_dbh( $error_prefix, $dsn, $user, $pass )

Returns a C<< DBI->connect_cached >> handle with C<RaiseError> set, dying
with C<$error_prefix> (normally the calling package) prepended on failure.

=head2 time_window_clause( %args )

The time-window WHERE fragment for a timestamp column, with the window in
precedence order:

    1. explicit absolute bounds -- start and/or end (either alone is fine);
    2. event-anchored -- BETWEEN around +/- window_minutes;
    3. now-relative over the already-validated minutes.

The bounds are checked with defined-and-non-empty flags, so a value of C<0>
still counts as a given bound. Timestamp values never reach the SQL raw: they
are cast to C<timestamptz> (read in the DB session's timezone) and rendered
per the caller's style, so a malformed value is a query error rather than an
injection. Args:

    - time_column :: the column the window applies to. Required.
    - opts :: the caller's option hash ref, read for start/end/around.
        Required.
    - minutes :: the validated now-relative window in minutes. Required.
    - binds :: array ref to push bind values onto, rendering each timestamp
        as a placeholder. When absent, quote_dbh is used instead.
    - quote_dbh :: DBI handle whose quote() renders each timestamp as a
        literal, so the fragment carries no binds.
    - window_minutes :: the validated half-width of an anchored window.
        Default: 60.
    - and_joiner :: how a start+end pair is joined. Default: ' AND '.
    - now_sql :: the SQL current-time expression for the relative window.
        Default: 'now()'.

=head2 validate_bucket( $bucket )

Returns C<$bucket> if it is a valid C<date_trunc> unit for a timeseries
(minute, hour, day, week, or month), dying otherwise.

=head2 host_or_text_expr( $column )

The SQL expression yielding a column's text value: C<host($column)> for the
known INET columns -- C<src_ip>/C<dest_ip> on the alert tables and
C<sourceip>/C<client_ip> in the Allani store -- whose value is wanted as the
bare host address (C<1.2.3.4>) rather than the C<1.2.3.4/32> that C<::text>
yields (and which would break GeoIP lookups); everything else is cast to
text.

=head2 measure_expr( %args )

The SQL aggregate a named measure resolves to, from a server-defined catalog
(so only a name from the catalog ever reaches SQL). Args:

    - list :: array ref of measure entries, each with a name and optionally
        agg (count/distinct/avg/sum/max/min, default count) plus the expr or
        col it aggregates. Required.
    - name :: the requested measure name; defaults to count. Dies when not
        in the list.
    - context :: appended to the die message as ' for <context>' when set.
    - column_expr_for :: coderef mapping a distinct measure's column name to
        its SQL reference (e.g. a virtual column's expression); the bare
        column name is used when absent.

Resolves to C<count(*)>, C<count(distinct ...)>, a zero-defaulted rounded
average, or C<< agg(expr) >>.

=head2 skip_scan_viable( %args )

Whether counting a column's distinct values is better done by walking an index
than by reading the rows, for a windowed count. True only when both conditions
hold, because either alone makes it slower than what it replaces. Args:

    - dbh :: the handle to ask the catalog through. Required.
    - table :: the table the column belongs to. Required.
    - column :: the column being counted. Required.
    - time_column :: the column the window is on. Required.
    - max_distinct :: the most values worth walking. Required.
    - cache :: hash ref the answer is remembered in, per table and column.
        Required, and owned by the caller -- the two readers talk to
        different databases, so one shared cache would confuse them.

The first condition is a btree index whose first key is the column and whose
second is the timestamp. Walking distinct values costs one index descent each,
but each value then has to be checked for a row inside the window, and only the
timestamp as second key makes that a descent too. With a C<< (column, id) >>
index -- which orders a value's rows by insertion -- that check walks every
older entry first, and the whole thing measured ten times slower than the plain
count over a day's window.

The second is the estimated number of distinct values. The walk is capped in any
case, but reaching the cap means paying for thousands of descents before falling
back, so a column already known to be wide is not started. The estimate comes
from C<pg_stats> and is only a sample, hence the cap staying as the backstop.

=head2 column_exists( $dbh, $table, $column )

Whether a table currently has a column, asked of the catalog: 1 when it does, 0
when it does not. How the readers cope with a database still on an older schema
than the code -- a promoted or generated column is probed for rather than
assumed, so the feature built on it can be withheld instead of erroring.

Answers per call and dies if the catalog cannot be read; whether and how long
to remember the answer is the caller's business, since each caller has its own
rules about caching a failure.

=head2 clamped_int( $value, $default, $min, $max )

C<$value> as an integer clamped to the optional C<$min>/C<$max>, or
C<$default> when it is not a non-negative integer. This is the
silently-defaulting flavor used for request-shaped integers; validation that
must die with a specific message stays with the caller.

=cut

sub connect_cached_dbh {
	my ( $error_prefix, $dsn, $user, $pass ) = @_;

	my $dbh;
	eval { $dbh = DBI->connect_cached( $dsn, $user, $pass, { RaiseError => 1 } ); };
	if ( $@ || !$dbh ) {
		die( $error_prefix . ': DBI->connect_cached failure... ' . $@ );
	}

	return $dbh;
} ## end sub connect_cached_dbh

sub time_window_clause {
	my (%args) = @_;

	my $time_column = $args{time_column};
	my $opts        = $args{opts};
	my $and_joiner  = defined $args{and_joiner} ? $args{and_joiner} : ' AND ';
	my $now_sql     = defined $args{now_sql}    ? $args{now_sql}    : 'now()';

	# Render a timestamp value into the clause: a pushed bind placeholder when a
	# binds array is given, a quoted literal otherwise.
	my $binds = $args{binds};
	my $render
		= $binds
		? sub { push( @$binds, $_[0] ); return '?' }
		: sub { return $args{quote_dbh}->quote( $_[0] ) };

	my $has_start = defined $opts->{start} && $opts->{start} ne '';
	my $has_end   = defined $opts->{end}   && $opts->{end} ne '';
	if ( $has_start || $has_end ) {
		my @conds;
		push( @conds, "$time_column >= " . $render->( $opts->{start} ) . '::timestamptz' ) if $has_start;
		push( @conds, "$time_column <= " . $render->( $opts->{end} ) . '::timestamptz' )   if $has_end;
		return join( $and_joiner, @conds );
	}

	if ( defined $opts->{around} && $opts->{around} ne '' ) {
		my $window_minutes = defined $args{window_minutes} ? $args{window_minutes} : 60;
		return
			  "$time_column BETWEEN "
			. $render->( $opts->{around} )
			. "::timestamptz - interval '$window_minutes minutes' AND "
			. $render->( $opts->{around} )
			. "::timestamptz + interval '$window_minutes minutes'";
	}

	return "$time_column >= $now_sql - interval '$args{minutes} minutes'";
} ## end sub time_window_clause

# date_trunc units accepted for timeseries buckets.
my %BUCKET = map { $_ => 1 } qw( minute hour day week month );

sub validate_bucket {
	my ($bucket) = @_;
	die( '"' . ( defined $bucket ? $bucket : '' ) . '" is not a valid bucket (minute, hour, day, week, month)' . "\n" )
		unless defined $bucket && $BUCKET{$bucket};
	return $bucket;
}

# The INET columns across both stores; the names do not collide (the alert
# tables have no sourceip/client_ip and the Allani store no src_ip/dest_ip).
my %INET = map { $_ => 1 } qw( src_ip dest_ip sourceip client_ip );

sub host_or_text_expr {
	my ($column) = @_;
	return $INET{$column} ? "host($column)" : "($column)::text";
}

sub measure_expr {
	my (%args) = @_;

	my $name = $args{name};
	$name = 'count' unless defined $name && $name ne '';

	my ($measure) = grep { $_->{name} eq $name } @{ $args{list} };
	die( '"' . $name . '" is not a known measure' . ( defined $args{context} ? ' for ' . $args{context} : '' ) . "\n" )
		unless $measure;

	my $aggregate = $measure->{agg} || 'count';
	return 'count(*)' if $aggregate eq 'count';
	if ( $aggregate eq 'distinct' ) {
		my $column = $measure->{col};
		return 'count(distinct ' . ( $args{column_expr_for} ? $args{column_expr_for}->($column) : $column ) . ')';
	}
	my $operand = defined $measure->{expr} ? $measure->{expr} : $measure->{col};
	return 'coalesce(round(avg(' . $operand . ')::numeric, 1), 0)' if $aggregate eq 'avg';
	# sum / max / min all yield NULL when every row in the group is NULL (e.g. a
	# baphomet offender whose judgments all have a NULL score); coalesce to 0 so
	# the measure is always numeric, matching avg above.
	return 'coalesce(' . $aggregate . '(' . $operand . '), 0)';    # sum / max / min
} ## end sub measure_expr

sub skip_scan_viable {
	my (%args) = @_;

	my ( $table, $column ) = ( $args{table}, $args{column} );
	my $cached = $args{cache}{$table}{$column};
	return $cached if defined $cached;

	my $viable = eval {
		my $sth = $args{dbh}->prepare(<<'SQL');
SELECT 1
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
JOIN pg_class t ON t.oid = x.indrelid
JOIN pg_am    m ON m.oid = i.relam
JOIN pg_attribute first  ON first.attrelid  = t.oid AND first.attnum  = x.indkey[0]
JOIN pg_attribute second ON second.attrelid = t.oid AND second.attnum = x.indkey[1]
WHERE t.relname = ? AND first.attname = ? AND second.attname = ? AND m.amname = 'btree'
LIMIT 1
SQL
		$sth->execute( $table, $column, $args{time_column} );
		my $indexed = $sth->fetchrow_arrayref ? 1 : 0;
		$sth->finish;
		return 0 unless $indexed;

		# n_distinct is negative when Postgres expresses it as a fraction of the
		# table, which only happens for columns distinct enough that it gave up
		# on a fixed count -- exactly the ones not worth walking.
		my ($n_distinct)
			= $args{dbh}->selectrow_array( 'SELECT n_distinct FROM pg_stats WHERE tablename = ? AND attname = ?',
				undef, $table, $column );
		return 0 unless defined $n_distinct;
		return 0 if $n_distinct < 0;
		return $n_distinct <= $args{max_distinct} ? 1 : 0;
	};
	$viable = 0 unless defined $viable;

	$args{cache}{$table}{$column} = $viable;
	return $viable;
} ## end sub skip_scan_viable

sub column_exists {
	my ( $dbh, $table, $column ) = @_;
	my ($found) = $dbh->selectrow_array(
		'SELECT 1 FROM pg_attribute WHERE attrelid = ?::regclass'
			. ' AND attname = ? AND attnum > 0 AND NOT attisdropped',
		undef, $table, $column
	);
	return $found ? 1 : 0;
}

sub clamped_int {
	my ( $value, $default, $min, $max ) = @_;
	return $default unless defined $value && $value =~ /^[0-9]+$/;
	$value += 0;
	$value = $min if defined $min && $value < $min;
	$value = $max if defined $max && $value > $max;
	return $value;
}

1;
