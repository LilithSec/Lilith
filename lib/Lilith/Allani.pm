package Lilith::Allani;

use strict;
use warnings;
use DBI;

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

The per-source whitelist (tables, timestamp columns, exact-match filter
columns, and the display columns) is B<not> duplicated here: it is reused from
C<Allani::Sources>, so Allani must be installed for the C</logs> page to work.
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

# date_trunc units a timeseries may be bucketed on.
my %BUCKET = map { $_ => 1 } qw( minute hour day week month );

# What a top/timeseries panel may aggregate beyond counting rows, per underlying
# source table. 'count' is always available; a measure names a numeric column to
# sum. The column is server-defined here (never from the request), so only the
# whitelisted measure name reaches SQL. Sources absent here get count only.
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

# inet columns, whose value we want as the bare host address ('1.2.3.4') via
# host() rather than the '1.2.3.4/32' that ::text yields (which would also break
# GeoIP lookups). Everything else is cast to text.
my %INET = map { $_ => 1 } qw( sourceip client_ip );

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

The time window is either now-relative (C<go_back_minutes>, default a day) or,
when C<around> is given a timestamp, anchored: rows within C<window_minutes>
(default 60) on either side of it. The event view uses the anchored form to
show the logs around an alert. Dies on a bad source, a filter invalid for the
source, or a DB error.

=cut

sub search {
	my ( $self, %opts ) = @_;

	my $key = $opts{source} // 'syslog';
	die( '"' . $key . "\" is not a known log source\n" ) unless $self->valid_source($key);

	my $dir   = ( defined $opts{order_dir} && uc $opts{order_dir} eq 'ASC' ) ? 'ASC' : 'DESC';
	my $limit = _int( $opts{limit},  100, 1, 10000 );
	my $off   = _int( $opts{offset}, 0,   0 );
	my $filt  = ( ref $opts{filters} eq 'HASH' ) ? $opts{filters} : {};

	return $self->_search_http_all( \%opts, $dir, $limit, $off, $filt )
		if $key eq 'http_all';

	my $entry = $SOURCE{$key};
	my $meta  = Allani::Sources::source( $entry->{src} )
		or die( '"' . $entry->{src} . "\" is unknown to Allani::Sources\n" );
	my $tscol = $meta->{default_ts};

	# Reuse Allani's whitelist for both the WHERE (via an accessor shim) and the
	# selected columns; we fetch positionally and zip against its headers. The
	# time window (now-relative, or anchored around an event) appends its own
	# binds after build_where's, in WHERE order.
	my ( $where, $binds ) = Allani::Sources::build_where( $meta, Lilith::Allani::_Opt->new(%$filt) );
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
			push( @where,  "$col = ?" );
			push( @hbinds, $filt->{$col} );
		}
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
	my $limit = _int( $opts{limit}, 500, 1, 5000 );
	my $vexpr = $self->_val_expr($col);
	my @binds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@binds );
	push( @binds, $limit );
	my $sth = $self->_dbh->prepare( "SELECT $vexpr AS value, count(*) AS count FROM $meta->{table}"
			. " WHERE $tc AND $col IS NOT NULL GROUP BY $col ORDER BY count DESC, value ASC LIMIT ?" );
	$sth->execute(@binds);
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	return $rows || [];
} ## end sub top_ips

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
is whitelisted against the source's C<dims>. Aggregate sources only.

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
C<column> is whitelisted against the source's C<dims>; C<limit> defaults to 10.
C<measure> (default C<count>) picks what C<count> holds -- row count, or a summed
numeric column from the source's catalog (see L</measures>), so "top vhosts by
Total bytes" is a traffic panel.

=cut

sub top {
	my ( $self, %opts ) = @_;
	my ( $meta, $tscol, $src ) = $self->_agg_meta( $opts{source} );
	my $col   = $self->_dim( $meta, $opts{column} );
	my $limit = _int( $opts{limit}, 10, 1, 1000 );
	my $magg  = $self->_measure_expr( $src, $opts{measure} );
	my $vexpr = $self->_val_expr($col);
	my @binds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@binds );
	push( @binds, $limit );
	my $sth = $self->_dbh->prepare( "SELECT $vexpr AS value, $magg AS count FROM $meta->{table}"
			. " WHERE $tc AND $col IS NOT NULL GROUP BY $col ORDER BY count DESC, value ASC LIMIT ?" );
	$sth->execute(@binds);
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	return $rows || [];
} ## end sub top

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
		my $gexpr = $self->_val_expr($g);
		my $k     = _int( $opts{top_groups}, 5, 1, 20 );

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
		$mins = _minutes($mins);
		return 'minute' if $mins <= 180;          # <= 3h
		return 'hour'   if $mins <= 2880;         # <= 2d
		return 'day'    if $mins <= 129_600;      # <= 90d
		return 'week'   if $mins <= 1_051_200;    # <= ~2y
		return 'month';
	}
	die( '"' . $b . "\" is not a valid bucket\n" ) unless $BUCKET{$b};
	return $b;
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

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass}, { RaiseError => 1 } ); };
	if ( $@ || !$dbh ) {
		die( 'Lilith::Allani: DBI->connect_cached failure... ' . $@ );
	}
	return $dbh;
} ## end sub _dbh

# The time-window WHERE fragment for column $tscol, appending any binds to
# @$binds in WHERE order. Anchored -- BETWEEN around +/- window_minutes -- when
# opts{around} is a non-empty timestamp (bound as text and cast, so a malformed
# value is a query error the caller reports, not an injection); otherwise
# now-relative over opts{go_back_minutes}. window_minutes defaults to 60.
sub _time_clause {
	my ( $self, $tscol, $opts, $binds ) = @_;

	if ( defined $opts->{around} && $opts->{around} ne '' ) {
		my $w = _int( $opts->{window_minutes}, 60, 1, 44_640 );
		push( @$binds, $opts->{around}, $opts->{around} );
		return "$tscol BETWEEN ?::timestamptz - interval '$w minutes'" . " AND ?::timestamptz + interval '$w minutes'";
	}

	my $mins = _minutes( $opts->{go_back_minutes} );
	return "$tscol >= now() - interval '$mins minutes'";
} ## end sub _time_clause

# Resolve an aggregate source to ( $meta, $timestamp_column, $source_name ).
# Aggregation is over a single real table, so http_all (a view) and unknown
# sources die.
sub _agg_meta {
	my ( $self, $key ) = @_;
	$key = '' unless defined $key;
	my $entry = $SOURCE{$key} or die( '"' . $key . "\" is not a known log source\n" );
	die("http_all has no aggregate view\n") unless defined $entry->{src};
	my $meta = Allani::Sources::source( $entry->{src} ) or die("unknown source\n");
	return ( $meta, $meta->{default_ts}, $entry->{src} );
}

# The SQL aggregate a measure resolves to (count(*) by default), from the
# server-defined per-source catalog. Never takes a column from the request.
sub _measure_expr {
	my ( $self, $src, $name ) = @_;
	$name = 'count' unless defined $name && $name ne '';
	my $list = $MEASURE{$src} || \@DEFAULT_MEASURE;
	my ($m) = grep { $_->{name} eq $name } @$list;
	die( '"' . $name . "\" is not a known measure\n" ) unless $m;
	return 'count(*)' if !$m->{agg} || $m->{agg} eq 'count';
	return $m->{agg} . '(' . $m->{col} . ')';
}

# The text value expression for a grouped/listed column: host() for inet columns
# (bare address), a text cast otherwise.
sub _val_expr {
	my ( $self, $col ) = @_;
	return $INET{$col} ? "host($col)" : "($col)::text";
}

# A group/count dimension, whitelisted against the source's Allani::Sources dims.
sub _dim {
	my ( $self, $meta, $col ) = @_;
	die("a column is required\n")                            unless defined $col && $col ne '';
	die( '"' . $col . "\" is not an aggregatable column\n" ) unless $meta->{dims}{$col};
	return $col;
}

# minutes-back window, integer, defaulting to a day.
sub _minutes {
	my ($v) = @_;
	return 1440 unless defined $v && $v =~ /^[0-9]+$/;
	return $v + 0;
}

# a clamped integer with a default.
sub _int {
	my ( $v, $default, $min, $max ) = @_;
	return $default unless defined $v && $v =~ /^[0-9]+$/;
	$v += 0;
	$v = $min if defined $min && $v < $min;
	$v = $max if defined $max && $v > $max;
	return $v;
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
