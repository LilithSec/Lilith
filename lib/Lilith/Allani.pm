package Lilith::Allani;

use strict;
use warnings;
use Lilith::DBUtil
	qw( clamped_int connect_cached_dbh host_or_text_expr measure_expr time_window_clause validate_bucket );

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
        filters         => { host => 'db1', message => 'error' },
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
The only query this module authors itself is C<http_all>, the interleaved view
of C<http_access> and C<http_error>.

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

# Filter columns that accept several whitespace-separated values on /logs,
# matched as an OR of per-value predicates -- the same per-value rule build_where
# applies to a single value, just spread over each token.
my %MULTI = map { $_ => 1 } qw( host program vhost );

# Of those, the columns Allani::Sources treats as LIKEABLE: a token carrying a %
# wildcard is matched with LIKE for these, and =, wildcard taken literally, for
# the rest -- mirroring build_where's single-value behavior per column.
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
        filters         => { host => 'db1', message => 'timeout' },
    );

Runs one windowed query and returns
C<< { source => ..., headers => [...], rows => [ {header=>value,...}, ... ] } >>.
Column names and the WHERE come from C<Allani::Sources>; every value is bound.

The C<host>, C<program> and C<vhost> filters each accept several
whitespace-separated values and match any of them. For C<host> and C<program> a
token carrying a C<%> wildcard is matched with LIKE (a plain token with C<=>);
C<vhost> matches every token with C<=> (its C<%> is literal). The other filters
are single exact matches.

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

	return $self->_search_http_all( \%opts, $dir, $limit, $off, $filt )
		if $key eq 'http_all';

	my $entry = $SOURCE{$key};
	my $meta  = Allani::Sources::source( $entry->{src} )
		or die( '"' . $entry->{src} . "\" is unknown to Allani::Sources\n" );
	my $tscol = $self->_ts_col($meta);

	# host and program each accept several whitespace-separated values; pull those
	# out and match them ourselves (an OR of per-value = / LIKE), leaving
	# build_where to handle the remaining single-value filters unchanged.
	my %single = %$filt;
	my ( @multi_where, @multi_binds );
	for my $col ( grep { $MULTI{$_} && $meta->{eq}{$_} } sort keys %single ) {
		my ( $frag, @vbinds ) = $self->_multi_clause( $col, delete $single{$col} );
		next unless defined $frag;
		push( @multi_where, $frag );
		push( @multi_binds, @vbinds );
	}

	# Reuse Allani's column/filter definitions for the WHERE (via an accessor shim)
	# and the selected columns; we fetch positionally and zip against its headers.
	# The multi-value clauses follow build_where's, then the time window
	# (now-relative, or anchored around an event) appends its own binds last, so
	# clause order and bind order stay aligned.
	my ( $where, $binds ) = Allani::Sources::build_where( $meta, Lilith::Allani::_Opt->new(%single) );
	push( @$where, @multi_where );
	push( @$binds, @multi_binds );
	my $tclause = $self->_time_clause( $tscol, \%opts, $binds );
	my ( $select, $headers ) = Allani::Sources::select_and_headers( $meta, $tscol, 0, 1 );

	my $sql
		= "SELECT $select FROM "
		. $meta->{table}
		. ' WHERE '
		. join( ' AND ', @$where, $tclause )
		. " ORDER BY id $dir LIMIT ? OFFSET ?";

	my $rows = $self->_run( $sql, [ @$binds, $limit, $off ], $headers );
	return { source => $key, headers => $headers, rows => $rows };
} ## end sub search

# The interleaved http view: a UNION ALL of http_access and http_error onto the
# normalized HTTP_ALL_HEADERS, ordered by the shared receive time. The same
# filter set is applied to each half; all values are bound.
sub _search_http_all {
	my ( $self, $opts, $dir, $limit, $off, $filt ) = @_;

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
			next unless defined $filt->{$col} && $filt->{$col} ne '';
			# host and vhost accept several whitespace-separated values (matched as an
			# OR of per-value predicates); client_ip stays a single exact match.
			if ( $MULTI{$col} ) {
				my ( $frag, @vbinds ) = $self->_multi_clause( $col, $filt->{$col} );
				next unless defined $frag;
				push( @where,  $frag );
				push( @hbinds, @vbinds );
			} else {
				push( @where,  "$col = ?" );
				push( @hbinds, $filt->{$col} );
			}
		} ## end for my $col (qw( host vhost client_ip ))
		if ( defined $filt->{message} && $filt->{message} ne '' ) {
			push( @where,  "$msg_col ILIKE ?" );
			push( @hbinds, '%' . $filt->{message} . '%' );
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
	my $tc  = $self->_time_clause( $tscol, \%opts, \@binds );
	my $sth = $self->_dbh->prepare("SELECT count(*) FROM $meta->{table} WHERE $tc");
	$sth->execute(@binds);
	my $r = $sth->fetchrow_arrayref;
	$sth->finish;
	return ( ( $r && defined $r->[0] ) ? $r->[0] : 0 ) + 0;
} ## end sub total

=head2 distinct

    my $n = $reader->distinct( source => 'syslog', column => 'host' );

The number of distinct non-null values of a dimension in the window. C<column>
must be one of the source's C<dims>. Aggregate sources only.

=cut

sub distinct {
	my ( $self, %opts )  = @_;
	my ( $meta, $tscol ) = $self->_agg_meta( $opts{source} );
	my $col = $self->_dim( $meta, $opts{column} );
	my @binds;
	my $tc  = $self->_time_clause( $tscol, \%opts, \@binds );
	my $sth = $self->_dbh->prepare("SELECT count(distinct $col) FROM $meta->{table} WHERE $tc");
	$sth->execute(@binds);
	my $r = $sth->fetchrow_arrayref;
	$sth->finish;
	return ( ( $r && defined $r->[0] ) ? $r->[0] : 0 ) + 0;
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
busiest values, so a stacked chart stays to a handful of series.

=cut

sub timeseries {
	my ( $self, %opts ) = @_;
	my ( $meta, $tscol, $src ) = $self->_agg_meta( $opts{source} );
	my $bucket = $self->bucket( $opts{bucket}, $opts{go_back_minutes} );
	my $magg   = $self->_measure_expr( $src, $opts{measure} );
	my $tbl    = $meta->{table};
	my $bexpr  = "to_char(date_trunc('$bucket', $tscol), 'YYYY-MM-DD\"T\"HH24:MI:SS')";

	my @wbinds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@wbinds );

	if ( defined $opts{group_by} && $opts{group_by} ne '' ) {
		my $g     = $self->_dim( $meta, $opts{group_by} );
		my $gexpr = host_or_text_expr($g);
		my $k     = clamped_int( $opts{top_groups}, 5, 1, 20 );

		# Restrict the split to the top-k group values in the window (its own copy
		# of the window clause, so its binds repeat), then bucket per group.
		my $sql
			= "SELECT $bexpr AS bucket, $gexpr AS \"group\", $magg AS count FROM $tbl"
			. " WHERE $tc AND $g IS NOT NULL AND $g IN ("
			. "SELECT $g FROM $tbl WHERE $tc AND $g IS NOT NULL GROUP BY $g ORDER BY $magg DESC, $g ASC LIMIT ?)"
			. " GROUP BY 1, 2 ORDER BY 1 ASC, 2 ASC";
		my $sth = $self->_dbh->prepare($sql);
		$sth->execute( @wbinds, @wbinds, $k );
		my $rows = $sth->fetchall_arrayref( {} );
		$sth->finish;
		return $rows || [];
	} ## end if ( defined $opts{group_by} && $opts{group_by...})

	my $sth
		= $self->_dbh->prepare("SELECT $bexpr AS bucket, $magg AS count FROM $tbl WHERE $tc GROUP BY 1 ORDER BY 1 ASC");
	$sth->execute(@wbinds);
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	return $rows || [];
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
sub _top_values {
	my ( $self, $meta, $tscol, $opts, $col, $measure_aggregate, $limit ) = @_;

	my $vexpr = host_or_text_expr($col);
	my @binds;
	my $tc = $self->_time_clause( $tscol, $opts, \@binds );
	push( @binds, $limit );
	my $sth = $self->_dbh->prepare( "SELECT $vexpr AS value, $measure_aggregate AS count FROM $meta->{table}"
			. " WHERE $tc AND $col IS NOT NULL GROUP BY $col ORDER BY count DESC, value ASC LIMIT ?" );
	$sth->execute(@binds);
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	return $rows || [];
} ## end sub _top_values

# Resolve an aggregate source to ( $meta, $timestamp_column, $source_name ).
# Aggregation is over a single real table, so http_all (a view) and unknown
# sources die.
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
sub _ts_col {
	my ( $self, $meta ) = @_;
	return $meta->{ts}{r_isodate} ? 'r_isodate' : $meta->{default_ts};
}

# The SQL aggregate a measure resolves to (count(*) by default), from the
# server-defined per-source catalog. Never takes a column from the request.
sub _measure_expr {
	my ( $self, $src, $name ) = @_;
	return measure_expr(
		list    => $MEASURE{$src} || \@DEFAULT_MEASURE,
		name    => $name,
		context => $src,
	);
}

# A WHERE fragment matching $col against one or more whitespace-separated values
# from $raw, returned with its binds. For a LIKEABLE column a value carrying a %
# wildcard is matched with LIKE; otherwise = (as build_where does for a single
# value). Several values are ORed in one parenthesized group. Every value is
# bound. Returns an empty list when $raw holds no non-blank tokens.
sub _multi_clause {
	my ( $self, $col, $raw ) = @_;

	my @vals = split( ' ', ( defined $raw ? $raw : '' ) );
	return unless @vals;

	my ( @preds, @binds );
	for my $val (@vals) {
		push( @preds, ( $LIKEABLE{$col} && index( $val, '%' ) >= 0 ? "$col LIKE ?" : "$col = ?" ) );
		push( @binds, $val );
	}
	my $frag = ( @preds > 1 ) ? '(' . join( ' OR ', @preds ) . ')' : $preds[0];
	return ( $frag, @binds );
} ## end sub _multi_clause

# A group/count dimension, checked against the source's Allani::Sources dims (dies otherwise).
sub _dim {
	my ( $self, $meta, $col ) = @_;
	die("a column is required\n")                            unless defined $col && $col ne '';
	die( '"' . $col . "\" is not an aggregatable column\n" ) unless $meta->{dims}{$col};
	return $col;
}

#
# A minimal App::Cmd-opt-shaped object so Allani::Sources::build_where (which
# reads its filters via $opt->accessor) can be fed a plain hash of web params.
# AUTOLOAD returns the stored value, or undef for any filter not set.
#
package Lilith::Allani::_Opt;

our $AUTOLOAD;

sub new {
	my ( $class, %h ) = @_;
	return bless {%h}, $class;
}

sub AUTOLOAD {
	my $self = shift;
	( my $name = $AUTOLOAD ) =~ s/.*:://;
	return if $name eq 'DESTROY';
	return $self->{$name};
}

1;
