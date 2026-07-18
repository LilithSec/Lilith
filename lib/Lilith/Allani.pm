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

=head2 top

    my $rows = $reader->top( source => 'syslog', column => 'program', limit => 10 );

The most common non-null values of a dimension in the window, as an array ref
of C<< { value, count } >> ordered by count descending (ties by value).
C<column> is whitelisted against the source's C<dims>; C<limit> defaults to 10.

=cut

sub top {
	my ( $self, %opts )  = @_;
	my ( $meta, $tscol ) = $self->_agg_meta( $opts{source} );
	my $col   = $self->_dim( $meta, $opts{column} );
	my $limit = _int( $opts{limit}, 10, 1, 1000 );
	my @binds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@binds );
	push( @binds, $limit );
	my $sth = $self->_dbh->prepare( "SELECT ($col)::text AS value, count(*) AS count FROM $meta->{table}"
			. " WHERE $tc AND $col IS NOT NULL GROUP BY $col ORDER BY count DESC, value ASC LIMIT ?" );
	$sth->execute(@binds);
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	return $rows || [];
} ## end sub top

=head2 timeseries

    my $rows = $reader->timeseries( source => 'syslog', bucket => 'hour' );

Row counts bucketed over time, as an array ref of C<< { bucket, count } >>
oldest first. C<bucket> is one of minute/hour/day/week/month (default hour).

=cut

sub timeseries {
	my ( $self, %opts )  = @_;
	my ( $meta, $tscol ) = $self->_agg_meta( $opts{source} );
	my $bucket = $self->_bucket( $opts{bucket} );
	my @binds;
	my $tc = $self->_time_clause( $tscol, \%opts, \@binds );
	my $sth
		= $self->_dbh->prepare(
			  "SELECT to_char(date_trunc('$bucket', $tscol), 'YYYY-MM-DD\"T\"HH24:MI:SS') AS bucket,"
			. " count(*) AS count FROM $meta->{table} WHERE $tc GROUP BY 1 ORDER BY 1 ASC" );
	$sth->execute(@binds);
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	return $rows || [];
} ## end sub timeseries

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

# date_trunc units the dashboard may bucket a timeseries on.
my %BUCKET = map { $_ => 1 } qw( minute hour day week month );

# Resolve an aggregate source to ( $meta, $timestamp_column ). Aggregation is
# over a single real table, so http_all (a view) and unknown sources die.
sub _agg_meta {
	my ( $self, $key ) = @_;
	$key = '' unless defined $key;
	my $entry = $SOURCE{$key} or die( '"' . $key . "\" is not a known log source\n" );
	die("http_all has no aggregate view\n") unless defined $entry->{src};
	my $meta = Allani::Sources::source( $entry->{src} ) or die("unknown source\n");
	return ( $meta, $meta->{default_ts} );
}

# A group/count dimension, whitelisted against the source's Allani::Sources dims.
sub _dim {
	my ( $self, $meta, $col ) = @_;
	die("a column is required\n")                            unless defined $col && $col ne '';
	die( '"' . $col . "\" is not an aggregatable column\n" ) unless $meta->{dims}{$col};
	return $col;
}

# A whitelisted date_trunc bucket unit, defaulting to hour.
sub _bucket {
	my ( $self, $b ) = @_;
	$b = 'hour' unless defined $b && $b ne '';
	die( '"' . $b . "\" is not a valid bucket\n" ) unless $BUCKET{$b};
	return $b;
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
