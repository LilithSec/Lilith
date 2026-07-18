package Lilith::Stats;

use strict;
use warnings;
use DBI ();

=head1 NAME

Lilith::Stats - aggregation queries over the alert tables for the dashboard.

=head1 SYNOPSIS

    my $stats = Lilith::Stats->new( lilith => $lilith );
    # or
    my $stats = Lilith::Stats->new( dsn => $dsn, user => $user, pass => $pass );

    my $n     = $stats->total( table => 'suricata', go_back_minutes => 1440 );
    my $uniq  = $stats->distinct( table => 'suricata', column => 'src_ip' );
    my $top   = $stats->top( table => 'suricata', column => 'classification', limit => 10 );
    my $line  = $stats->timeseries( table => 'suricata', bucket => 'hour' );
    my $stack = $stats->timeseries(
        table    => 'suricata',
        bucket   => 'hour',
        group_by => 'classification',
        top_groups => 5,
    );

=head1 DESCRIPTION

Read-only aggregation helpers over C<suricata_alerts>, C<sagan_alerts>,
C<cape_alerts>, and C<baphomet_alerts> for the web dashboard. Each method takes
a short table type (C<suricata>, C<sagan>, C<cape>, or C<baphomet>) and a
C<go_back_minutes> window (default
1440) and runs a single grouped query, leaning on the version-5 indexes so a
time-windowed C<GROUP BY> range-scans rather than reading the whole table.

Every table name, column name, and time bucket a caller passes is checked
against a fixed set of accepted names before it reaches SQL; the only
interpolated scalars (the relative window and any limit) are checked to be
integers, and an explicit C<start>/C<end> range is quoted, so callers may pass
request parameters straight through without an injection risk.

The time window is an explicit absolute range (C<start> and/or C<end>) when
given, otherwise the now-relative C<go_back_minutes>.

Every method also accepts an optional C<exclude_classification> value; when set,
rows with that classification are left out (this backs the dashboard's "hide
Generic Protocol Command Decode" toggle). The value is quoted via the DBI handle
rather than interpolated raw, and it is ignored for cape, which has no
classification column.

=cut

# short type -> real table
my %TABLE = (
	suricata => 'suricata_alerts',
	sagan    => 'sagan_alerts',
	cape     => 'cape_alerts',
	baphomet => 'baphomet_alerts',
);

# The column each table is windowed and time-bucketed on. CAPE has no ingest
# 'timestamp'; its analysis 'stop' time is the closest analogue and is what
# search() orders it by.
my %TIME_COL = (
	suricata => 'timestamp',
	sagan    => 'timestamp',
	cape     => 'stop',
	baphomet => 'timestamp',
);

# Columns that may be grouped/counted by, per table. Deliberately excludes raw,
# event_id, and the flow byte/packet counters -- the dimensions a dashboard cuts
# on, not every column.
my %DIMENSION = (
	suricata => {
		map { $_ => 1 }
			qw( instance host in_iface src_ip dest_ip src_port dest_port
			proto app_proto classification signature gid sid )
	},
	sagan => {
		map { $_ => 1 }
			qw( instance instance_host host in_iface src_ip dest_ip src_port dest_port
			proto facility level priority program classification signature gid sid )
	},
	cape => {
		map { $_ => 1 }
			qw( instance target pkg md5 sha1 sha256 slug url_hostname
			proto src_ip dest_ip src_port dest_port malscore )
	},
	baphomet => {
		map { $_ => 1 }
			qw( instance host kur event_type severity classification
			src_ip dest_ip subject signature country )
	},
);

# date_trunc units accepted for timeseries buckets.
my %BUCKET = map { $_ => 1 } qw( minute hour day week month );

# inet columns, whose text form we want as the bare host address ('1.2.3.4')
# rather than the '1.2.3.4/32' that ::text yields.
my %INET = map { $_ => 1 } qw( src_ip dest_ip );

# Virtual (computed) dimensions: pseudo-column names that map to a SQL expression
# rather than a real column, so a widget can group by a field kept only in the
# raw EVE record. Each entry has an 'expr' (the value it groups/filters by) and
# an optional 'label' expression giving the display value. 'severity' is the
# Suricata alert severity (raw->alert->severity), which is not promoted to a
# column; its label maps the 1-4 numbers to names. mitre_tactic/mitre_technique
# read the ATT&CK annotations rulesets (e.g. Emerging Threats) put in
# alert.metadata as single-element arrays of underscored names; the label spaces
# them out. Sagan is not listed: it does not populate alert.severity or MITRE
# metadata, carrying severity in its priority/level columns.
my %VIRTUAL = (
	suricata => {
		severity => {
			expr  => "raw->'alert'->>'severity'",
			label => "case (raw->'alert'->>'severity')"
				. " when '1' then 'High' when '2' then 'Medium'"
				. " when '3' then 'Low' when '4' then 'Informational'"
				. " else (raw->'alert'->>'severity') end",
			# natural rank so top() orders High -> Low rather than by count
			order => "case (raw->'alert'->>'severity')"
				. " when '1' then 1 when '2' then 2 when '3' then 3 when '4' then 4 else 99 end",
		},
		mitre_tactic => {
			expr  => "raw->'alert'->'metadata'->'mitre_tactic_name'->>0",
			label => "replace(raw->'alert'->'metadata'->'mitre_tactic_name'->>0, '_', ' ')",
		},
		mitre_technique => {
			expr  => "raw->'alert'->'metadata'->'mitre_technique_name'->>0",
			label => "replace(raw->'alert'->'metadata'->'mitre_technique_name'->>0, '_', ' ')",
		},
	},
);

# Measures: what a top/timeseries widget aggregates, beyond the default count of
# rows. Each is a named preset resolved to a SQL aggregate: 'sum'/'avg'/'max' of
# a numeric 'expr', or 'distinct' count of a dimension 'col'. Ordered per table
# for the widget picker; 'count' is always first. expr/col are server-defined, so
# only a name defined here reaches SQL. This is what turns the flow byte/packet
# counters into top-talker and bandwidth panels and the ports into fan-out ones.
my %MEASURE = (
	suricata => [
		{ name => 'count', label => 'Count of alerts' },
		{
			name  => 'bytes',
			label => 'Total bytes',
			agg   => 'sum',
			expr  => 'coalesce(flow_bytes_toserver,0) + coalesce(flow_bytes_toclient,0)'
		},
		{
			name  => 'packets',
			label => 'Total packets',
			agg   => 'sum',
			expr  => 'coalesce(flow_pkts_toserver,0) + coalesce(flow_pkts_toclient,0)'
		},
		{ name => 'distinct_dest_ip', label => 'Distinct destination IPs', agg => 'distinct', col => 'dest_ip' },
		{
			name  => 'distinct_dest_port',
			label => 'Distinct destination ports',
			agg   => 'distinct',
			col   => 'dest_port'
		},
		{ name => 'distinct_src_ip', label => 'Distinct source IPs', agg => 'distinct', col => 'src_ip' },
	],
	sagan => [
		{ name => 'count', label => 'Count of alerts' },
		{ name => 'distinct_dest_ip', label => 'Distinct destination IPs', agg => 'distinct', col => 'dest_ip' },
		{
			name  => 'distinct_dest_port',
			label => 'Distinct destination ports',
			agg   => 'distinct',
			col   => 'dest_port'
		},
		{ name => 'distinct_src_ip', label => 'Distinct source IPs', agg => 'distinct', col => 'src_ip' },
	],
	cape => [
		{ name => 'count',        label => 'Count of detonations' },
		{ name => 'avg_malscore', label => 'Average malscore', agg => 'avg', expr => 'malscore' },
		{ name => 'max_malscore', label => 'Max malscore',     agg => 'max', expr => 'malscore' },
		{ name => 'sum_size',     label => 'Total size',       agg => 'sum', expr => 'size' },
	],
	baphomet => [
		{ name => 'count',            label => 'Count of judgments' },
		{ name => 'avg_score',        label => 'Average score',         agg => 'avg',      expr => 'score' },
		{ name => 'max_score',        label => 'Max score',             agg => 'max',      expr => 'score' },
		{ name => 'distinct_src_ip',  label => 'Distinct source IPs',      agg => 'distinct', col => 'src_ip' },
		{ name => 'distinct_dest_ip', label => 'Distinct destination IPs', agg => 'distinct', col => 'dest_ip' },
	],
);

=head1 METHODS

=head2 new

    my $stats = Lilith::Stats->new( lilith => $lilith );
    my $stats = Lilith::Stats->new( dsn => $dsn, user => $user, pass => $pass );

Builds a stats object from an existing L<Lilith> object (reusing its connection
details) or from an explicit C<dsn>/C<user>/C<pass>.

=cut

sub new {
	my ( $class, %opts ) = @_;

	my $self = {};
	if ( $opts{lilith} ) {
		$self->{dsn}  = $opts{lilith}{dsn};
		$self->{user} = $opts{lilith}{user};
		$self->{pass} = $opts{lilith}{pass};
	} else {
		$self->{dsn}  = $opts{dsn};
		$self->{user} = $opts{user};
		$self->{pass} = $opts{pass};
	}

	return bless $self, $class;
} ## end sub new

=head2 total

    my $n = $stats->total( table => 'suricata', go_back_minutes => 1440 );

Total number of alerts in the window.

=cut

sub total {
	my ( $self, %opts ) = @_;

	my $type = $self->_table( $opts{table} );
	my $mins = $self->_minutes( $opts{go_back_minutes} );
	my ( $tbl, $tc ) = ( $TABLE{$type}, $TIME_COL{$type} );

	my $dbh = $self->_dbh;
	my $exf = $self->_exclude_frag( $dbh, $type, \%opts );
	my $win = $self->_window_frag( $dbh, $tc, \%opts, $mins );
	my $sql = "select count(*) from $tbl where $win$exf";
	my ($n) = $dbh->selectrow_array($sql);

	return ( $n // 0 ) + 0;
} ## end sub total

=head2 escalated

    my $n = $stats->escalated( table => 'suricata', go_back_minutes => 1440 );

Number of alerts in the window that carry a non-empty escalations array (i.e.
have been escalated at least once).

=cut

sub escalated {
	my ( $self, %opts ) = @_;

	my $type = $self->_table( $opts{table} );
	my $mins = $self->_minutes( $opts{go_back_minutes} );
	my ( $tbl, $tc ) = ( $TABLE{$type}, $TIME_COL{$type} );

	my $dbh = $self->_dbh;
	my $exf = $self->_exclude_frag( $dbh, $type, \%opts );
	my $win = $self->_window_frag( $dbh, $tc, \%opts, $mins );
	my $sql
		= "select count(*) from $tbl where $win$exf "
		. "and escalations is not null and array_length(escalations, 1) > 0";
	my ($n) = $dbh->selectrow_array($sql);

	return ( $n // 0 ) + 0;
} ## end sub escalated

=head2 distinct

    my $n = $stats->distinct( table => 'suricata', column => 'src_ip' );

Number of distinct non-null values of C<column> in the window.

=cut

sub distinct {
	my ( $self, %opts ) = @_;

	my $type = $self->_table( $opts{table} );
	my $col  = $self->_dimension( $type, $opts{column} );
	my $mins = $self->_minutes( $opts{go_back_minutes} );
	my ( $tbl, $tc ) = ( $TABLE{$type}, $TIME_COL{$type} );

	my $dbh     = $self->_dbh;
	my $exf     = $self->_exclude_frag( $dbh, $type, \%opts );
	my $win     = $self->_window_frag( $dbh, $tc, \%opts, $mins );
	my $colexpr = $self->_col_expr( $type, $col );
	my $sql     = "select count(distinct $colexpr) from $tbl where $win$exf";
	my ($n)     = $dbh->selectrow_array($sql);

	return ( $n // 0 ) + 0;
} ## end sub distinct

=head2 top

    my $rows = $stats->top( table => 'suricata', column => 'classification', limit => 10 );

The most common non-null values of C<column> in the window, as an array ref of
C<< { value => ..., count => ... } >> ordered by count descending (ties broken
by value). C<limit> defaults to 10.

=cut

sub top {
	my ( $self, %opts ) = @_;

	my $type  = $self->_table( $opts{table} );
	my $col   = $self->_dimension( $type, $opts{column} );
	my $mins  = $self->_minutes( $opts{go_back_minutes} );
	my $limit = $self->_limit( $opts{limit}, 10 );
	my ( $tbl, $tc ) = ( $TABLE{$type}, $TIME_COL{$type} );

	my $dbh     = $self->_dbh;
	my $exf     = $self->_exclude_frag( $dbh, $type, \%opts );
	my $win     = $self->_window_frag( $dbh, $tc, \%opts, $mins );
	my $vexpr   = $self->_value_expr( $type, $col );
	my $colexpr = $self->_col_expr( $type, $col );
	my $magg    = $self->_measure_expr( $type, $opts{measure} );

	# A virtual column with a natural rank (e.g. severity) orders by that rank via
	# min() -- an aggregate, so it needs no GROUP BY entry -- rather than by the
	# measure (which is what everything else orders by, descending).
	my $ord
		= ( $VIRTUAL{$type} && $VIRTUAL{$type}{$col} && $VIRTUAL{$type}{$col}{order} )
		? 'min(' . $VIRTUAL{$type}{$col}{order} . ') asc'
		: '2 desc, 1 asc';

	my $sql
		= "select $vexpr as value, $magg as count from $tbl "
		. "where $win$exf and $colexpr is not null "
		. "group by 1 order by $ord limit $limit";

	my $rows = $dbh->selectall_arrayref( $sql, { Slice => {} } );

	return [ map { { value => $_->{value}, count => $_->{count} + 0 } } @$rows ];
} ## end sub top

=head2 timeseries

    my $line  = $stats->timeseries( table => 'suricata', bucket => 'hour' );
    my $stack = $stats->timeseries(
        table => 'suricata', bucket => 'hour',
        group_by => 'classification', top_groups => 5,
    );

Alert counts bucketed over time. C<bucket> is a C<date_trunc> unit (one of
minute, hour, day, week, month; default hour). Each row is
C<< { bucket => <epoch seconds>, count => ... } >>, ordered by bucket.

With C<group_by> the counts are split per value of that column and each row also
carries C<group>; passing C<top_groups> restricts the split to that many
busiest values in the window (so a stacked chart stays to a handful of series).

=cut

sub timeseries {
	my ( $self, %opts ) = @_;

	my $type   = $self->_table( $opts{table} );
	my $mins   = $self->_minutes( $opts{go_back_minutes} );
	my $bucket = $self->_bucket( $opts{bucket} );
	my ( $tbl, $tc ) = ( $TABLE{$type}, $TIME_COL{$type} );

	my $dbh    = $self->_dbh;
	my $exf    = $self->_exclude_frag( $dbh, $type, \%opts );
	my $magg   = $self->_measure_expr( $type, $opts{measure} );
	my $window = $self->_window_frag( $dbh, $tc, \%opts, $mins ) . $exf;
	my $epoch  = "extract(epoch from date_trunc('$bucket', $tc))::bigint";

	if ( defined $opts{group_by} && $opts{group_by} ne '' ) {
		my $g     = $self->_dimension( $type, $opts{group_by} );
		my $gcol  = $self->_col_expr( $type, $g );
		my $gexpr = $self->_value_expr( $type, $g );
		my $where = "$window and $gcol is not null";

		if ( defined $opts{top_groups} ) {
			my $k = $self->_limit( $opts{top_groups}, 5 );
			$where
				.= " and $gcol in (select $gcol from $tbl where $window and $gcol is not null "
				. "group by 1 order by $magg desc, 1 asc limit $k)";
		}

		# A virtual group with a natural rank (e.g. severity) orders its series by
		# that rank via min() rather than alphabetically by the label, so the
		# stack reads High -> Low.
		my $gord
			= ( $VIRTUAL{$type} && $VIRTUAL{$type}{$g} && $VIRTUAL{$type}{$g}{order} )
			? 'min(' . $VIRTUAL{$type}{$g}{order} . ') asc'
			: '2 asc';

		my $sql
			= "select $epoch as bucket, $gexpr as \"group\", $magg as count "
			. "from $tbl where $where group by 1, 2 order by 1 asc, $gord";
		my $rows = $dbh->selectall_arrayref( $sql, { Slice => {} } );

		return [ map { { bucket => $_->{bucket} + 0, group => $_->{group}, count => $_->{count} + 0 } } @$rows ];
	} ## end if ( defined $opts{group_by} && $opts{group_by...})

	my $sql  = "select $epoch as bucket, $magg as count from $tbl where $window group by 1 order by 1 asc";
	my $rows = $dbh->selectall_arrayref( $sql, { Slice => {} } );

	return [ map { { bucket => $_->{bucket} + 0, count => $_->{count} + 0 } } @$rows ];
} ## end sub timeseries

=head2 columns

    my $cols = $stats->columns('suricata');

The sorted list of columns that may be grouped/counted by for a table -- the
same set of accepted columns the other methods validate against, exposed so the
dashboard's widget pickers stay in sync with what the backend will accept.

=cut

sub columns {
	my ( $self, $table ) = @_;
	my $type = $self->_table($table);
	my @cols = keys %{ $DIMENSION{$type} };
	push( @cols, keys %{ $VIRTUAL{$type} } ) if $VIRTUAL{$type};
	return [ sort @cols ];
}

=head2 measures

    my $m = $stats->measures('suricata');

The measures a top/timeseries widget on that table may aggregate by, as an array
ref of C<< { name, label } >> (C<count> first), driving the widget picker from
the same catalog the API resolves against.

=cut

sub measures {
	my ( $self, $table ) = @_;
	my $type = $self->_table($table);
	return [ map { { name => $_->{name}, label => $_->{label} } } @{ $MEASURE{$type} } ];
}

#
# internals
#

sub _dbh {
	my ($self) = @_;

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass}, { RaiseError => 1 } ); };
	if ( $@ || !$dbh ) {
		die( 'Lilith::Stats: DBI->connect_cached failure... ' . $@ );
	}

	return $dbh;
} ## end sub _dbh

# The time-window WHERE fragment for time column $tc: an explicit absolute range
# (start and/or end, quoted and cast to timestamptz, so read in the DB session's
# timezone) when either is given, else the now-relative go_back_minutes. Quoted
# rather than interpolated raw, mirroring _exclude_frag; a bad value is a query
# error, not an injection. Callers append $exf (the classification exclude).
sub _window_frag {
	my ( $self, $dbh, $tc, $opts, $mins ) = @_;

	my $start = ( defined $opts->{start} && $opts->{start} ne '' ) ? $opts->{start} : undef;
	my $end   = ( defined $opts->{end}   && $opts->{end} ne '' )   ? $opts->{end}   : undef;
	if ( $start || $end ) {
		my @conds;
		push( @conds, "$tc >= " . $dbh->quote($start) . '::timestamptz' ) if $start;
		push( @conds, "$tc <= " . $dbh->quote($end) . '::timestamptz' )   if $end;
		return join( ' and ', @conds );
	}

	return "$tc >= CURRENT_TIMESTAMP - interval '$mins minutes'";
} ## end sub _window_frag

sub _table {
	my ( $self, $type ) = @_;
	$type = 'suricata' unless defined $type && $type ne '';
	die( '"' . $type . '" is not a known table type' . "\n" ) unless $TABLE{$type};
	return $type;
}

sub _dimension {
	my ( $self, $type, $col ) = @_;
	die("a column is required\n") unless defined $col && $col ne '';
	die( '"' . $col . '" is not an aggregatable column for ' . $type . "\n" )
		unless $DIMENSION{$type}{$col} || ( $VIRTUAL{$type} && $VIRTUAL{$type}{$col} );
	return $col;
}

# The SQL aggregate a measure resolves to (count(*) by default). expr/col come
# from the server-defined %MEASURE catalog, never from the request.
sub _measure_expr {
	my ( $self, $type, $name ) = @_;
	$name = 'count' unless defined $name && $name ne '';

	my ($m) = grep { $_->{name} eq $name } @{ $MEASURE{$type} };
	die( '"' . $name . '" is not a known measure for ' . $type . "\n" ) unless $m;

	my $agg = $m->{agg} || 'count';
	return 'count(*)' if $agg eq 'count';
	return 'count(distinct ' . $self->_col_expr( $type, $self->_dimension( $type, $m->{col} ) ) . ')'
		if $agg eq 'distinct';
	return 'coalesce(round(avg(' . $m->{expr} . ')::numeric, 1), 0)' if $agg eq 'avg';
	return $agg . '(' . $m->{expr} . ')';    # sum / max / min
} ## end sub _measure_expr

# The raw SQL reference for an already-validated column: a virtual column's grouping
# expression, or the bare column name. This is what null checks, distinct, and
# the timeseries top-groups subquery reference.
sub _col_expr {
	my ( $self, $type, $col ) = @_;
	return $VIRTUAL{$type}{$col}{expr} if $VIRTUAL{$type} && $VIRTUAL{$type}{$col};
	return $col;
}

# The SQL expression yielding a column's display value: a virtual column's label
# expression (or its bare expression when unlabelled), an inet column's bare host
# address, everything else cast to text.
sub _value_expr {
	my ( $self, $type, $col ) = @_;
	if ( $VIRTUAL{$type} && $VIRTUAL{$type}{$col} ) {
		my $v = $VIRTUAL{$type}{$col};
		return $v->{label} // '(' . $v->{expr} . ')';
	}
	return "host($col)" if $INET{$col};
	return "$col\::text";
}

# Optional "and classification <> ..." fragment for the exclude_classification
# option (the dashboard's "hide Generic Protocol Command Decode" toggle). The
# value is quoted into a literal so the fragment is safe to splice straight into
# the SQL and to reuse verbatim inside subqueries (no bind bookkeeping). Only
# tables that have a classification column honor it; cape silently ignores it.
sub _exclude_frag {
	my ( $self, $dbh, $type, $opts ) = @_;
	return '' unless $DIMENSION{$type}{classification};
	my $ex = $opts->{exclude_classification};
	return '' unless defined $ex && $ex ne '';
	return ' and (classification is null or classification <> ' . $dbh->quote($ex) . ')';
}

sub _bucket {
	my ( $self, $bucket ) = @_;
	$bucket = 'hour' unless defined $bucket && $bucket ne '';
	die( '"' . $bucket . '" is not a valid bucket (minute, hour, day, week, month)' . "\n" )
		unless $BUCKET{$bucket};
	return $bucket;
}

sub _minutes {
	my ( $self, $mins ) = @_;
	$mins = 1440 unless defined $mins && $mins ne '';
	die( '"' . $mins . '" for go_back_minutes is not a non-negative integer' . "\n" )
		unless $mins =~ /^[0-9]+$/;
	return $mins + 0;
}

sub _limit {
	my ( $self, $limit, $default ) = @_;
	$limit = $default unless defined $limit && $limit ne '';
	die( '"' . $limit . '" is not a positive integer limit' . "\n" )
		unless $limit =~ /^[0-9]+$/ && $limit + 0 > 0;
	return $limit + 0;
}

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
