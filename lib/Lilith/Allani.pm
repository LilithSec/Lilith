package Lilith::Allani;

use strict;
use warnings;
use Lilith::DBUtil qw( clamped_int connect_cached_dbh distinct_by_skip_scan host_or_text_expr measure_expr
	skip_scan_viable time_window_clause validate_bucket );

=head1 NAME

Lilith::Allani - Read-only reader for an Allani log store, for the web UI.

=head1 SYNOPSIS

    my $reader = Lilith::Allani->new(
        dsn  => 'dbi:Pg:dbname=allani',
        user => 'allani',
        pass => 'xxx',
    );

    my $out = $reader->search(
        source          => 'syslog',
        go_back_minutes => 1440,
        filters         => { host => [ 'db1', 'db2' ], message => 'error' },
        limit           => 100,
    );
    # $out = { source => 'syslog', headers => [...], rows => [ {...}, ... ] }

=head1 DESCRIPTION

Lilith stores only the noteworthy dead; L<Allani|https://github.com/LilithSec/Allani>
keeps every log line (syslog-ng JSON in PostgreSQL). This is a thin, read-only
reader Lilith::Web uses to browse an Allani store over its own connection,
without going through Lilith's own alert schema.

The per-source definitions (tables, timestamp columns, exact-match filter
columns, and the display columns) are B<not> duplicated here: they are reused
from C<Allani::Sources>, so Allani must be installed for the C</logs> page to work.

=cut

# The selector as presented on /logs: our key => the underlying Allani::Sources
# name (undef for the synthetic http_all), plus a label. Order is display order.
my @SOURCES = (
	{ key => 'syslog',     src => 'syslog',      label => 'syslog' },
	{ key => 'http',       src => 'http_access', label => 'http (access)' },
	{ key => 'http_error', src => 'http_error',  label => 'http error' },
	{ key => 'http_all',   src => undef,         label => 'http (interleaved)' },
);
my %SOURCE = map { $_->{key} => $_ } @SOURCES;

# The synthetic http_all view: a normalized projection each half maps onto, and
# the filters it accepts. This is the one query Lilith authors rather than
# reusing from Allani::Sources.
my @HTTP_ALL_HEADERS = qw( source id time host client vhost status detail message );
my %HTTP_ALL_FILTER  = map { $_ => 1 } qw( host vhost client_ip message );

# The columns Allani::Sources treats as LIKEABLE: a value carrying a % wildcard
# is matched with LIKE for these, and =, wildcard taken literally, for the rest.
my %LIKEABLE = map { $_ => 1 } qw( host program );

# What a top/timeseries panel may aggregate beyond counting rows, per underlying
# source table. 'count' is always available; a measure names a numeric column to
# sum. The column is server-defined here (never from the request), so only a
# measure name from this catalog reaches SQL. Sources absent here get count only.
my @DEFAULT_MEASURE = ( { name => 'count', label => 'Count' } );
my %MEASURE         = (
	http_access => [
		{ name => 'count', label => 'Count' },
		{ name => 'bytes', label => 'Total bytes', agg => 'sum', col => 'bytes' },
	],
);

# The source IP column geolocated for the countries panel, per selector key.
my %IP_COL = (
	syslog     => 'sourceip',
	http       => 'client_ip',
	http_error => 'client_ip',
);

=head2 new

    my $reader = Lilith::Allani->new( dsn => ..., user => ..., pass => ... );

Requires C<Allani::Sources> (dies with a clear message if Allani is not
installed) and stashes the connection details. No connection is made until a
query runs.

=cut

sub new {
	my ( $class, %opts ) = @_;

	eval { require Allani::Sources; 1 }
		or die "Lilith::Allani: Allani is not installed (the /logs page needs it): $@";

	my $self = {
		dsn  => $opts{dsn},
		user => $opts{user},
		pass => $opts{pass},
	};

	return bless $self, $class;
} ## end sub new

=head2 sources

Returns an array ref of C<< { key, label } >> for the source selector, in
display order.

=cut

sub sources {
	return [ map { { key => $_->{key}, label => $_->{label} } } @SOURCES ];
}

=head2 valid_source

True if C<$key> names a source this reader serves.

=cut

sub valid_source { return exists $SOURCE{ $_[1] // '' } ? 1 : 0; }

=head2 filters

    my $names = $reader->filters('syslog');

The filter field names valid for a source: its C<Allani::Sources> exact-match
columns, plus the free-text C<message> where it is meaningful. C<message> maps
to C<< raw->>'MESSAGE' >>, which only C<syslog> populates, so it is offered for
C<syslog> (and for C<http_all>, whose own reduced set matches it against the
request/message columns instead) but not for the individual http sources, whose
text lives in real columns rather than a C<raw.MESSAGE> field.

=cut

sub filters {
	my ( $self, $key ) = @_;

	return [ sort keys %HTTP_ALL_FILTER ] if defined $key && $key eq 'http_all';

	my $entry = $SOURCE{ $key // '' }                    or return [];
	my $meta  = Allani::Sources::source( $entry->{src} ) or return [];

	my %names = %{ $meta->{eq} };
	$names{message} = 1 if $key eq 'syslog';
	return [ sort keys %names ];
} ## end sub filters

=head2 search

    my $out = $reader->search(
        source          => 'syslog',
        go_back_minutes => 1440,
        order_dir       => 'DESC',
        limit           => 100,
        offset          => 0,
        filters         => { host => [ 'db1', 'db2' ], message => 'timeout' },
    );

Runs one windowed query and returns
C<< { source => ..., headers => [...], rows => [ {header=>value,...}, ... ] } >>.
Column names and the accepted filter set come from C<Allani::Sources>; every
value is bound.

Each filter takes a single value or an array ref of several, matched as any of
them. For C<host> and C<program> a value carrying a C<%> wildcard is matched
with LIKE (a plain value with C<=>); the other columns match with C<=>, C<%>
taken literally. C<message> is a substring (ILIKE) match, only accepted where
the source has message text to match it against (C<syslog> and C<http_all>);
C<message_match> picks how its several values combine -- C<AND> (the default)
so each added term narrows the match like a chained grep, or C<OR> to match
any of them as the other filters do.

The time window is, in precedence: an explicit absolute range (C<start> and/or
C<end> timestamps); an event-anchored window (C<around> a timestamp, within
C<window_minutes> either side, default 60); or now-relative (C<go_back_minutes>,
default a day). The event view uses the anchored form; the search page's time
control uses start/end or go_back_minutes. Dies on a bad source, a filter
invalid for the source, or a DB error.

=cut

sub search {
	my ( $self, %opts ) = @_;

	my $key = $opts{source} // 'syslog';
	die( '"' . $key . "\" is not a known log source\n" ) unless $self->valid_source($key);

	my $dir   = ( defined $opts{order_dir} && uc $opts{order_dir} eq 'ASC' ) ? 'ASC' : 'DESC';
	my $limit = clamped_int( $opts{limit},  100, 1, 10000 );
	my $off   = clamped_int( $opts{offset}, 0,   0 );
	my $filt  = ( ref $opts{filters} eq 'HASH' ) ? $opts{filters} : {};

	# message_match reduced to one of two authored strings -- anything but 'OR'
	# (unset included) is the 'AND' default -- so what reaches _ilike_clause is
	# never the raw parameter.
	my $message_join = ( defined $opts{message_match} && uc( $opts{message_match} ) eq 'OR' ) ? 'OR' : 'AND';

	return $self->_search_http_all( \%opts, $dir, $limit, $off, $filt, $message_join )
		if $key eq 'http_all';

	my $entry = $SOURCE{$key};
	my $meta  = Allani::Sources::source( $entry->{src} )
		or die( '"' . $entry->{src} . "\" is unknown to Allani::Sources\n" );
	my $tscol = $self->_ts_col($meta);

	# One clause per filter, each an any-of group over its values. 'message' is
	# the substring match on the raw MESSAGE field (which only syslog populates),
	# and by default the one all-of group -- every term must appear in the line
	# unless message_match is 'OR'; everything else must be one of the source's
	# exact-match columns. The time window (now-relative, or anchored around an
	# event) appends its binds last, so clause order and bind order stay aligned.
	my ( @where, @binds );
	for my $col ( sort keys %$filt ) {
		my ( $frag, @vbinds );
		if ( $col eq 'message' ) {
			die( "\"message\" is not a valid filter for " . $key . "\n" ) unless $key eq 'syslog';
			( $frag, @vbinds ) = $self->_ilike_clause( "raw->>'MESSAGE'", $filt->{$col}, $message_join );
		} else {
			die( '"' . $col . '" is not a valid filter for ' . $key . "\n" ) unless $meta->{eq}{$col};
			( $frag, @vbinds ) = $self->_multi_clause( $col, $filt->{$col} );
		}
		next unless defined $frag;
		push( @where, $frag );
		push( @binds, @vbinds );
	} ## end for my $col ( sort keys %$filt )

	my $tclause = $self->_time_clause( $tscol, \%opts, \@binds );
	my ( $select, $headers ) = Allani::Sources::select_and_headers( $meta, $tscol, 0, 1 );

	my $sql
		= "SELECT $select FROM "
		. $meta->{table}
		. ' WHERE '
		. join( ' AND ', @where, $tclause )
		. " ORDER BY id $dir LIMIT ? OFFSET ?";

	my $rows = $self->_run( $sql, [ @binds, $limit, $off ], $headers );
	return { source => $key, headers => $headers, rows => $rows };
} ## end sub search

# The interleaved http view: a UNION ALL of http_access and http_error onto the
# normalized HTTP_ALL_HEADERS, ordered by the shared receive time. The same
# filter set is applied to each half; all values are bound.
#
# This is the one query Lilith authors itself rather than reusing from
# Allani::Sources, since Allani has no combined http source. Each half selects
# its own columns under the shared header names, with a literal discriminator
# so a row knows which selector key it came from and can link back to the right
# record view.
#
# Args:
#
#   - $opts :: the caller's option hash ref, passed on to _time_clause for the
#     window.
#   - $dir :: the sort direction for the shared time column, 'ASC' or 'DESC'.
#     Already checked by the caller.
#   - $limit :: how many rows to return, already clamped.
#   - $off :: how many rows to skip, for paging.
#   - $filt :: hash ref of filter column to value, restricted to
#     %HTTP_ALL_FILTER (host, vhost, client_ip, message). Each value may be a
#     single value or an array ref of several, matched as any of them.
#   - $message_join :: 'AND' or 'OR', how several message terms combine.
#     Already normalized from message_match by the caller.
#
# Returns: a hash ref of the same shape search() gives for a real source:
# { source => 'http_all', headers => \@HTTP_ALL_HEADERS, rows => [ ... ] }.
# Each row is keyed by those headers, and its 'source' says which half it came
# from ('http' or 'http_error').
#
#     my $out = $self->_search_http_all( $opts, 'DESC', 100, 0, { host => 'www1' } );
sub _search_http_all {
	my ( $self, $opts, $dir, $limit, $off, $filt, $message_join ) = @_;

	my @binds;
	# $key is the selector key emitted as the 'source' discriminator, so a row's
	# id links to a record view the reader understands (/logs/<key>/<id>) rather
	# than to the raw table name; $table is where the half actually reads from.
	# Each half builds its own binds (time window first, then filters, in WHERE
	# order) and appends them, so the two halves and the limit/offset line up.
	my $half = sub {
		my ( $key, $table, $status_col, $detail_col, $msg_col ) = @_;
		my @hbinds;
		my @where = ( $self->_time_clause( 'r_isodate', $opts, \@hbinds ) );
		for my $col (qw( host vhost client_ip )) {
			my ( $frag, @vbinds ) = $self->_multi_clause( $col, $filt->{$col} );
			next unless defined $frag;
			push( @where,  $frag );
			push( @hbinds, @vbinds );
		}
		my ( $msg_frag, @msg_binds ) = $self->_ilike_clause( $msg_col, $filt->{message}, $message_join );
		if ( defined $msg_frag ) {
			push( @where,  $msg_frag );
			push( @hbinds, @msg_binds );
		}
		push( @binds, @hbinds );
		return
			  "SELECT '$key' AS source, id, r_isodate AS time, host, client_ip AS client,"
			. " vhost, ${status_col}::text AS status, $detail_col AS detail, $msg_col AS message"
			. " FROM $table WHERE "
			. join( ' AND ', @where );
	}; ## end $half = sub

	my $sql
		= $half->( 'http', 'http_access', 'status', 'method', 'request' )
		. ' UNION ALL '
		. $half->( 'http_error', 'http_error', 'code', 'loglevel', 'message' )
		. " ORDER BY time $dir LIMIT ? OFFSET ?";

	my $rows = $self->_run( $sql, [ @binds, $limit, $off ], \@HTTP_ALL_HEADERS );
	return { source => 'http_all', headers => \@HTTP_ALL_HEADERS, rows => $rows };
} ## end sub _search_http_all

=head2 row

    my $row = $reader->row( 'syslog', 42 );

One record by id, as a hash ref of every column (C<raw> included), or undef if
not found. For C<http_all> the source must be one of the real http tables.

=cut

sub row {
	my ( $self, $key, $id ) = @_;

	die("invalid id\n") unless defined $id && $id =~ /^[0-9]+$/;
	# http_all is a view, not a table, so it has no single-record page; its result
	# rows link to their real source (http / http_error), never to http_all.
	die("http_all has no single record view\n") if defined $key && $key eq 'http_all';
	die( '"' . ( $key // '' ) . "\" is not a known log source\n" ) unless $self->valid_source($key);

	my $meta = Allani::Sources::source( $SOURCE{$key}{src} )
		or die("unknown source\n");

	my $dbh = $self->_dbh;
	my $sth = $dbh->prepare( 'SELECT * FROM ' . $meta->{table} . ' WHERE id = ?' );
	$sth->execute($id);
	my $r = $sth->fetchrow_hashref;
	$sth->finish;
	return $r;
} ## end sub row

=head2 dims

    my $names = $reader->dims('syslog');

The dimensions a source may be grouped/counted by (its C<Allani::Sources>
C<dims>), C<default_dim> first. Empty for C<http_all> (no single-table
aggregate) or an unknown source. Drives the dashboard's panels.

=cut

sub dims {
	my ( $self, $key ) = @_;
	my $entry = $SOURCE{ $key // '' } or return [];
	return [] unless defined $entry->{src};
	my $meta = Allani::Sources::source( $entry->{src} ) or return [];
	my $dd   = $meta->{default_dim};
	my @rest = sort grep { $_ ne $dd } keys %{ $meta->{dims} };
	return [ ( $meta->{dims}{$dd} ? ($dd) : () ), @rest ];
}

=head2 measures

    my $ms = $reader->measures('http_access');

The measures a top/timeseries panel on this source may aggregate by, as an array
ref of C<< { name, label } >> (C<count> first). Every source has C<count>;
C<http_access> also has C<bytes>. Empty for C<http_all>/unknown.

=cut

sub measures {
	my ( $self, $key ) = @_;
	my $entry = $SOURCE{ $key // '' } or return [];
	return [] unless defined $entry->{src};
	my $list = $MEASURE{ $entry->{src} } || \@DEFAULT_MEASURE;
	return [ map { { name => $_->{name}, label => $_->{label} } } @$list ];
}

=head2 top_ips

    my $rows = $reader->top_ips( source => 'syslog', limit => 500 );

The busiest source IPs in the window, as C<< { value, count } >>, from the
source's IP column (C<sourceip> for syslog, C<client_ip> for the http sources).
Used by the dashboard's countries panel, which geolocates them. Aggregate
sources only.

=cut

sub top_ips {
	my ( $self, %opts )  = @_;
	my ( $meta, $tscol ) = $self->_agg_meta( $opts{source} );
	my $col = $IP_COL{ $opts{source} // '' }
		or die( '"' . ( $opts{source} // '' ) . "\" has no source IP column\n" );
	my $limit = clamped_int( $opts{limit}, 500, 1, 5000 );
	return $self->_top_values( $meta, $tscol, \%opts, $col, 'count(*)', $limit );
}

=head2 total

    my $n = $reader->total( source => 'syslog', go_back_minutes => 1440 );

Row count in the window (accepts the same window options as L</search>,
now-relative or C<around>-anchored). Aggregate sources only (not C<http_all>).

=cut

sub total {
	my ( $self, %opts )  = @_;
	my ( $meta, $tscol ) = $self->_agg_meta( $opts{source} );
	my @binds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@binds );
	my ($n) = $self->_dbh->selectrow_array( "SELECT count(*) FROM $meta->{table} WHERE $tc", undef, @binds );
	return ( $n // 0 ) + 0;
}

# How many distinct values a skip scan walks before giving up and letting
# distinct() count rows instead. Each value costs one index descent, so a few
# thousand is still quick, while a column with far more than this is one where
# reading the rows outright wins.
my $SKIP_SCAN_CAP = 5000;

=head2 distinct

    my $n = $reader->distinct( source => 'syslog', column => 'host' );

The number of distinct non-null values of a dimension in the window. C<column>
must be one of the source's C<dims>. Aggregate sources only.

Counting the rows means reading every one in the window to arrive at a single
small number, which over a wide window is most of the table however few distinct
values there turn out to be. Where a C<< (column, timestamp) >> index exists
this instead walks the column's distinct values through it and asks whether each
has a row in the window, so the cost follows the number of values rather than
the number of rows. Allani ships those indexes from schema version 9; without
one the rows are counted as before.

The pairing matters, and a C<< (column, id) >> index will not do. It orders a
value's rows by insertion, so asking whether a host appears in the last day
walks every older entry for that host first -- measured at ten times slower than
simply counting the rows. Ordering each value's entries by time makes the same
question one index descent, and about seventy times faster than counting.

=cut

sub distinct {
	my ( $self, %opts )  = @_;
	my ( $meta, $tscol ) = $self->_agg_meta( $opts{source} );
	my $col = $self->_dim( $meta, $opts{column} );

	my @binds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@binds );

	# The viability check -- an index leading with the column and the timestamp
	# as its second key, and few enough distinct values to be worth walking --
	# lives in Lilith::DBUtil, since Lilith::Stats asks the same question of the
	# alert tables. The cache belongs to this object because the two readers are
	# pointed at different databases.
	if (
		skip_scan_viable(
			dbh          => $self->_dbh,
			table        => $meta->{table},
			column       => $col,
			time_column  => $tscol,
			max_distinct => $SKIP_SCAN_CAP,
			cache        => ( $self->{_skip_scan_cache} ||= {} ),
		)
		)
	{
		# The cap earns its keep even behind the index check, because pg_stats
		# estimates cardinality from a sample and can be badly wrong -- on the
		# store this was written against it put pid at 6731 distinct values
		# where the real figure was 227442. undef means over the cap or the
		# query failed -- an optimization must not turn a working page into an
		# error -- so fall through to counting rows.
		my $count = distinct_by_skip_scan(
			dbh    => $self->_dbh,
			table  => $meta->{table},
			column => $col,
			where  => $tc,
			binds  => \@binds,
			cap    => $SKIP_SCAN_CAP,
		);
		return $count if defined $count;
	} ## end if ( skip_scan_viable(...))

	my ($n)
		= $self->_dbh->selectrow_array( "SELECT count(distinct $col) FROM $meta->{table} WHERE $tc", undef, @binds );
	return ( $n // 0 ) + 0;
} ## end sub distinct

=head2 top

    my $rows = $reader->top( source => 'syslog', column => 'program', limit => 10 );

The top values of a dimension in the window, as an array ref of
C<< { value, count } >> ordered by the measure descending (ties by value).
C<column> must be one of the source's C<dims>; C<limit> defaults to 10.
C<measure> (default C<count>) picks what C<count> holds -- row count, or a summed
numeric column from the source's catalog (see L</measures>), so "top vhosts by
Total bytes" is a traffic panel.

=cut

sub top {
	my ( $self, %opts ) = @_;
	my ( $meta, $tscol, $src ) = $self->_agg_meta( $opts{source} );
	my $col   = $self->_dim( $meta, $opts{column} );
	my $limit = clamped_int( $opts{limit}, 10, 1, 1000 );
	my $magg  = $self->_measure_expr( $src, $opts{measure} );
	return $self->_top_values( $meta, $tscol, \%opts, $col, $magg, $limit );
}

=head2 timeseries

    my $rows = $reader->timeseries( source => 'syslog', bucket => 'hour' );

Counts bucketed over time, as an array ref of C<< { bucket, count } >> oldest
first. C<bucket> is one of minute/hour/day/week/month, or C<auto> (the default),
which sizes the bucket to the window (see L</bucket>). C<measure> aggregates as
in L</top>.

With C<group_by> (a dimension) the counts are split per value and each row also
carries C<group>; C<top_groups> (default 5) restricts the split to that many
busiest values, so a stacked chart stays to a handful of series. The busiest are
picked from the bucketed counts rather than by a second look at the table, so a
grouped series costs one pass over the window rather than two.

=cut

sub timeseries {
	my ( $self, %opts ) = @_;
	my ( $meta, $tscol, $src ) = $self->_agg_meta( $opts{source} );
	my $bucket = $self->bucket( $opts{bucket}, $opts{go_back_minutes} );
	my $magg   = $self->_measure_expr( $src, $opts{measure} );
	my $tbl    = $meta->{table};

	# Bucket by the truncated timestamp and label it only on the way out. The
	# label is what the caller wants, but formatting it before the grouping means
	# running to_char once per row and then grouping on the resulting string --
	# eight million formats and string comparisons to produce a hundred or so
	# rows. Grouping on the timestamp and formatting the result instead measured
	# 3.9x quicker over a day and 2.2x over a month.
	my $trunc  = "date_trunc('$bucket', $tscol)";
	my $format = q{'YYYY-MM-DD"T"HH24:MI:SS'};

	my @wbinds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@wbinds );

	if ( defined $opts{group_by} && $opts{group_by} ne '' ) {
		my $g     = $self->_dim( $meta, $opts{group_by} );
		my $gexpr = host_or_text_expr($g);
		my $k     = clamped_int( $opts{top_groups}, 5, 1, 20 );

		# Bucket every group once, then pick the busiest k from that result
		# rather than going back to the table for them. The obvious way round --
		# a subquery naming the top groups, joined against a second pass -- reads
		# the window twice, and the window is the expensive part: over 30 days of
		# an 8 million row store the two-pass form took 7.9 seconds against 5.5
		# for this one. What is ranked here is already aggregated, so it is a few
		# hundred rows however wide the window is.
		my $sql = <<"SQL";
WITH per_bucket AS (
    SELECT $trunc AS bucket_ts, $gexpr AS grp, $magg AS count
    FROM $tbl WHERE $tc AND $g IS NOT NULL
    GROUP BY 1, 2
),
busiest AS (
    SELECT grp FROM per_bucket GROUP BY grp ORDER BY sum(count) DESC, grp ASC LIMIT ?
)
SELECT to_char(per_bucket.bucket_ts, $format) AS bucket, per_bucket.grp AS "group", per_bucket.count
FROM per_bucket JOIN busiest USING (grp)
ORDER BY per_bucket.bucket_ts ASC, 2 ASC
SQL
		return $self->_dbh->selectall_arrayref( $sql, { Slice => {} }, @wbinds, $k );
	} ## end if ( defined $opts{group_by} && $opts{group_by...})

	# same reasoning as the grouped branch: bucket on the timestamp, label after
	my $sql = <<"SQL";
SELECT to_char(bucket_ts, $format) AS bucket, count
FROM (SELECT $trunc AS bucket_ts, $magg AS count FROM $tbl WHERE $tc GROUP BY 1) bucketed
ORDER BY bucket_ts ASC
SQL
	return $self->_dbh->selectall_arrayref( $sql, { Slice => {} }, @wbinds );
} ## end sub timeseries

=head2 bucket

    my $unit = $reader->bucket( 'auto', 1440 );

The date_trunc unit to bucket a timeseries by: an explicit
minute/hour/day/week/month is validated and returned as-is; C<auto> (or unset)
is sized to the window in minutes so a long span does not yield thousands of
buckets (minute up to 3h, hour up to 2d, day up to 90d, week up to ~2y, else
month). L</timeseries> resolves its bucket through this, and the dashboard also
calls it to label which unit an C<auto> request resolved to. Dies on an unknown
unit.

=cut

sub bucket {
	my ( $self, $b, $mins ) = @_;
	if ( !defined $b || $b eq '' || $b eq 'auto' ) {
		$mins = clamped_int( $mins, 1440 );
		return 'minute' if $mins <= 180;          # <= 3h
		return 'hour'   if $mins <= 2880;         # <= 2d
		return 'day'    if $mins <= 129_600;      # <= 90d
		return 'week'   if $mins <= 1_051_200;    # <= ~2y
		return 'month';
	}
	return validate_bucket($b);
} ## end sub bucket

#
# internals
#

# Run a prepared query and zip each result row against $headers into a hashref.
# Rows are fetched as array refs and named here rather than with
# fetchrow_hashref, so a UNION that projects two tables onto one header list
# (_search_http_all) names its columns the same way an ordinary select does.
#
# Args:
#
#   - $sql :: the statement to run. Every value in it must be a placeholder --
#     table and column names are the only things interpolated by callers, and
#     those come from Allani::Sources rather than the request.
#   - $binds :: array ref of bind values, in placeholder order.
#   - $headers :: array ref of names to give the selected columns, in select
#     order. Becomes the keys of each returned row.
#
# Returns: an array ref of hash refs, one per row, keyed by $headers. Empty
# array ref when nothing matched.
#
#     my $rows = $self->_run(
#         'SELECT id, host FROM syslog WHERE host = ? LIMIT ?',
#         [ 'db1', 10 ],
#         [ 'id', 'host' ],
#     );
#     # [ { id => 12, host => 'db1' }, ... ]
sub _run {
	my ( $self, $sql, $binds, $headers ) = @_;

	my $dbh = $self->_dbh;
	my $sth = $dbh->prepare($sql);
	$sth->execute(@$binds);

	my @rows;
	while ( my $r = $sth->fetchrow_arrayref ) {
		my %row;
		@row{@$headers} = @$r;
		push( @rows, \%row );
	}
	return \@rows;
} ## end sub _run

# The DBI handle for the Allani store. This is Allani's own connection, quite
# separate from Lilith's -- the two need not share a database -- and it is only
# ever read from. Shared through connect_cached, with the class name as the
# error prefix so a failure names Lilith::Allani and not the shared helper.
#
# Args: none.
#
# Returns: a DBI database handle with RaiseError set. Dies with
# 'Lilith::Allani: DBI->connect_cached failure... ' and the DBI error when the
# store cannot be reached.
#
#     my $sth = $self->_dbh->prepare($sql);
sub _dbh {
	my ($self) = @_;
	return connect_cached_dbh( ref($self), $self->{dsn}, $self->{user}, $self->{pass} );
}

# The time-window WHERE fragment for column $tscol, appending any binds to
# @$binds in WHERE order. Timestamps are bound as text and cast to timestamptz
# (read in the DB session's timezone), so a malformed value is a query error the
# caller reports rather than an injection. In precedence:
#   1. explicit absolute bounds -- start and/or end;
#   2. event-anchored window -- BETWEEN around +/- window_minutes (default 60);
#   3. now-relative over go_back_minutes.
#
# Args:
#
#   - $tscol :: the timestamp column to window on, from _ts_col.
#   - $opts :: the caller's option hash ref. Read for 'start'/'end' (absolute
#     bounds), 'around' (a timestamp to centre on) with 'window_minutes' (how
#     far either side, default 60), and 'go_back_minutes' (the relative
#     fallback). All optional; the precedence above decides which is used.
#   - $binds :: array ref the timestamp binds are pushed onto, in WHERE order.
#     Modified in place, so the caller passes the same array it will execute
#     with.
#
# Returns: a SQL boolean expression as a string, with '?' placeholders for
# every timestamp. Unlike the fragment Lilith::Stats builds, this one carries
# binds, so it cannot be reused in a second query without the matching values.
#
#     my @binds;
#     my $tc = $self->_time_clause( 'r_isodate', $opts, \@binds );
#     $sth->execute( @binds, $limit );
sub _time_clause {
	my ( $self, $tscol, $opts, $binds ) = @_;

	return time_window_clause(
		time_column    => $tscol,
		opts           => $opts,
		binds          => $binds,
		minutes        => clamped_int( $opts->{go_back_minutes}, 1440 ),
		window_minutes => clamped_int( $opts->{window_minutes},  60, 1, 44_640 ),
	);
} ## end sub _time_clause

# One "top values of $col" query over the window: the column's text value and
# the aggregate, non-null values only, grouped by the column and ordered by the
# aggregate descending (ties broken by value), with the limit bound last. Backs
# both top() (a validated dimension, any measure) and top_ips() (the source's
# IP column, count(*)).
#
# Args:
#
#   - $meta :: the Allani::Sources metadata for the source, whose 'table' says
#     where to read.
#   - $tscol :: the timestamp column to window on, from _ts_col.
#   - $opts :: the caller's option hash ref, passed on to _time_clause for the
#     window.
#   - $col :: the column to group by. Already checked -- by _dim for top(), or
#     taken from the source metadata for top_ips().
#   - $measure_aggregate :: the aggregate as SQL, from _measure_expr. 'count(*)'
#     for a plain tally.
#   - $limit :: how many rows to return, already clamped by the caller.
#
# Returns: an array ref of { value, count } hash refs, ordered by count
# descending with ties broken by value ascending. 'value' is the column as
# text (an inet comes back without its mask); 'count' is whatever the measure
# worked out, so it is not always a row tally. Rows whose column is NULL are
# left out. Empty array ref when nothing matched.
#
#     my $rows = $self->_top_values( $meta, 'r_isodate', $opts, 'host', 'count(*)', 10 );
#     # [ { value => 'db1', count => 402 }, ... ]
sub _top_values {
	my ( $self, $meta, $tscol, $opts, $col, $measure_aggregate, $limit ) = @_;

	my $vexpr = host_or_text_expr($col);
	my @binds;
	my $tc = $self->_time_clause( $tscol, $opts, \@binds );
	push( @binds, $limit );
	return $self->_dbh->selectall_arrayref(
		"SELECT $vexpr AS value, $measure_aggregate AS count FROM $meta->{table}"
			. " WHERE $tc AND $col IS NOT NULL GROUP BY $col ORDER BY count DESC, value ASC LIMIT ?",
		{ Slice => {} },
		@binds
	);
} ## end sub _top_values

# Resolve an aggregate source to ( $meta, $timestamp_column, $source_name ).
# Aggregation is over a single real table, so http_all (a view) and unknown
# sources die.
#
# Args:
#
#   - $key :: the selector key as it appears on /logs -- 'syslog', 'http', or
#     'http_error'. 'http_all' is a known key but has no table to aggregate
#     over, so it dies here rather than further down.
#
# Returns: the three-element list ( $meta, $timestamp_column, $source_name ):
# the Allani::Sources metadata hash ref, the column to window and bucket on,
# and the underlying Allani source name ('http_access' for the 'http' key).
# Dies with '"$key" is not a known log source', 'http_all has no aggregate
# view', or 'unknown source' when Allani itself does not recognise it.
#
#     my ( $meta, $tscol, $src ) = $self->_agg_meta('http');
#     # $src is 'http_access'
sub _agg_meta {
	my ( $self, $key ) = @_;
	$key = '' unless defined $key;
	my $entry = $SOURCE{$key} or die( '"' . $key . "\" is not a known log source\n" );
	die("http_all has no aggregate view\n") unless defined $entry->{src};
	my $meta = Allani::Sources::source( $entry->{src} ) or die("unknown source\n");
	return ( $meta, $self->_ts_col($meta), $entry->{src} );
}

# The timestamp column to anchor time windows, timeseries buckets and the
# displayed time on. The aggregator's receive time (r_isodate) is authoritative
# -- a sending host's clock may be wrong -- so prefer it whenever the source
# records it, falling back to the source's own default_ts otherwise. This is a
# no-op for the http sources (already default_ts => r_isodate) and flips syslog
# off its host-stamped s_isodate. The original stamp survives in raw and the
# single-record view, so nothing is hidden.
#
# Args:
#
#   - $meta :: the Allani::Sources metadata for a source. Read for its 'ts' map
#     of available timestamp columns and its 'default_ts'.
#
# Returns: the column name to use, as a string -- 'r_isodate' where the source
# records the aggregator's receive time, otherwise whatever that source calls
# its default.
#
#     my $tscol = $self->_ts_col($meta);    # 'r_isodate'
sub _ts_col {
	my ( $self, $meta ) = @_;
	return $meta->{ts}{r_isodate} ? 'r_isodate' : $meta->{default_ts};
}

# The SQL aggregate a measure resolves to (count(*) by default), from the
# server-defined per-source catalog. Never takes a column from the request.
#
# Args:
#
#   - $src :: the underlying Allani source name, as _agg_meta returns it --
#     'syslog', 'http_access', or 'http_error'. A source with no catalog entry
#     of its own falls back to the shared @DEFAULT_MEASURE.
#   - $name :: the measure name, e.g. 'count' or http's 'sum_bytes'. undef or
#     '' is taken as 'count'.
#
# Returns: the aggregate as a SQL expression string for a select list, e.g.
# 'count(*)'. Dies with '"$name" is not a known measure for $src' when the
# source has no such measure.
#
#     my $agg = $self->_measure_expr( 'http_access', 'sum_bytes' );
sub _measure_expr {
	my ( $self, $src, $name ) = @_;
	return measure_expr(
		list    => $MEASURE{$src} || \@DEFAULT_MEASURE,
		name    => $name,
		context => $src,
	);
}

# A WHERE fragment matching $col against one or more values, returned with its
# binds. For a LIKEABLE column a value carrying a % wildcard is matched with
# LIKE; otherwise =, the wildcard taken literally. Several values are ORed in
# one parenthesized group. Every value is bound.
#
# Args:
#
#   - $col :: the column to match, already known to be a filter column for this
#     source. Whether it takes LIKE is decided by %LIKEABLE, not by the caller.
#   - $values :: the filter as the web layer hands it over -- a single value or
#     an array ref of several. undef and empty values are dropped, so a blank
#     filter matches nothing extra rather than nothing at all.
#
# Returns: the two-or-more element list ( $fragment, @binds ) -- a SQL boolean
# expression with one placeholder per value, parenthesized when there is more
# than one, plus the values in placeholder order. Returns the empty list when
# there is nothing to match, so a caller can push straight onto its clause and
# bind lists and have a blank filter add nothing.
#
#     my ( $frag, @binds ) = $self->_multi_clause( 'host', [ 'db1', 'db2' ] );
#     # $frag is '(host = ? OR host = ?)', @binds is ( 'db1', 'db2' )
sub _multi_clause {
	my ( $self, $col, $values ) = @_;

	my @vals = grep { defined($_) && $_ ne '' } ( ref $values eq 'ARRAY' ? @$values : ($values) );
	return unless @vals;

	my ( @preds, @binds );
	for my $val (@vals) {
		push( @preds, ( $LIKEABLE{$col} && index( $val, '%' ) >= 0 ? "$col LIKE ?" : "$col = ?" ) );
		push( @binds, $val );
	}
	my $frag = ( @preds > 1 ) ? '(' . join( ' OR ', @preds ) . ')' : $preds[0];
	return ( $frag, @binds );
} ## end sub _multi_clause

# A WHERE fragment substring-matching $expr against one or more values, each
# bound as %value% for ILIKE and joined in one parenthesized group -- ANDed by
# default so every term must appear and each added term narrows the match the
# way a chained grep would, or ORed when the caller passes 'OR'. Backs the
# message filter, whose text lives in an expression rather than a plain column.
#
# Args:
#
#   - $expr :: the SQL expression holding the text, e.g. "raw->>'MESSAGE'" or a
#     message column name. Always authored here, never request data.
#   - $values :: a single value or an array ref of several, as _multi_clause
#     takes. undef and empty values are dropped.
#   - $join :: 'AND' or 'OR', how several values combine. Already normalized
#     by search(), never request data. Defaults to 'AND'.
#
# Returns: ( $fragment, @binds ) as _multi_clause does, or the empty list when
# there is nothing to match.
#
#     my ( $frag, @binds ) = $self->_ilike_clause( 'message', [ 'boom', 'oops' ] );
#     # $frag is '(message ILIKE ? AND message ILIKE ?)', @binds ( '%boom%', '%oops%' )
sub _ilike_clause {
	my ( $self, $expr, $values, $join ) = @_;

	my @vals = grep { defined($_) && $_ ne '' } ( ref $values eq 'ARRAY' ? @$values : ($values) );
	return unless @vals;

	$join = 'AND' unless defined $join && $join eq 'OR';
	my @binds = map { '%' . $_ . '%' } @vals;
	my $frag  = join( " $join ", ( $expr . ' ILIKE ?' ) x scalar(@vals) );
	$frag = '(' . $frag . ')' if @vals > 1;
	return ( $frag, @binds );
} ## end sub _ilike_clause

# A group/count dimension, checked against the source's Allani::Sources dims
# (dies otherwise). Lilith keeps no dimension list of its own for log sources --
# Allani's is authoritative -- but the check still has to happen here, since the
# name is spliced into the SQL.
#
# Args:
#
#   - $meta :: the Allani::Sources metadata for the source, whose 'dims' names
#     the columns that may be grouped by.
#   - $col :: the column a widget wants to group or count by, e.g. 'host' or
#     'program' for syslog, 'vhost' for http.
#
# Returns: the checked column name as a string, unchanged. Dies with 'a column
# is required' when undef or empty, or '"$col" is not an aggregatable column'
# when that source does not offer it.
#
#     my $col = $self->_dim( $meta, 'program' );
sub _dim {
	my ( $self, $meta, $col ) = @_;
	die("a column is required\n")                            unless defined $col && $col ne '';
	die( '"' . $col . "\" is not an aggregatable column\n" ) unless $meta->{dims}{$col};
	return $col;
}

1;
