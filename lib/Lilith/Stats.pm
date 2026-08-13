package Lilith::Stats;

use strict;
use warnings;
use Lilith::DBUtil
	qw( column_exists connect_cached_dbh distinct_by_skip_scan host_or_text_expr local_networks_frag measure_expr skip_scan_viable time_window_clause validate_bucket );

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
C<go_back_minutes> window (default 1440) and runs a single grouped query,
leaning on the C<< (column, timestamp) >> indexes so a time-windowed
C<GROUP BY> range-scans rather than reading the whole table.

The Suricata severity and MITRE fields live in the raw EVE record. From schema
13 they are also stored generated columns, which is what those queries read
when the database has them -- digging them out of raw instead means fetching a
15KB document back per row. A database still on an older schema falls back to
the expression automatically.

Beyond the columns an alert carries, the tables that name an outside host also
offer B<Shodan enrichment> dimensions: what C<shodan_cache> holds about the
alert's C<src_ip> or C<dest_ip>, joined on. Those are the C<shodan_src_*> and
C<shodan_dest_*> columns, and L</shodan_coverage> says, per end, how much of a
window they actually describe. They are offered only when the database has the
C<shodan_cache> table (schema version 15), which is detected rather than
assumed.

Two dimension families take their meaning from the request rather than from
the alert alone. The C<shodan_src_freshness> / C<shodan_dest_freshness> pair
buckets that end's addresses into C<Enriched> / C<Stale> / C<Not looked up>
per the caller's C<ttl> (seconds, default 2592000) and C<source> (C<api> or
C<internetdb>; absent means either tier counts) -- the dimension form of
L</shodan_coverage>, sharing its freshness rule. The C<src_locality> /
C<dest_locality> pair buckets each end into C<Internal> / C<External> against
the caller's C<local_networks> (an array ref of CIDRs; absent means the
unroutable ranges), and is offered for every table with the address column,
needing no C<shodan_cache> at all.

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

# How many distinct values a skip scan will walk before it stops being worth it.
# Each value costs one index descent, so a few thousand is still quick, while a
# column with far more than this is one where reading the rows outright wins.
my $SKIP_SCAN_CAP = 5000;

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
			src_ip src_port dest_ip dest_port username signature gid sid country )
	},
);

# Dimensions that are not plain columns: fields of the raw EVE record a widget
# can still group by. Each entry carries
#
#   - column :: the generated column holding the value from schema 13, which is
#     preferred when the database has it. See _virtual_base for why, and for
#     what happens on an older database.
#   - expr :: the expression digging the value out of raw, used before 13.
#   - label :: optional code ref taking whichever of those is in play and
#     returning the display expression.
#   - order :: optional code ref, likewise, giving a natural rank to sort series
#     by instead of the label.
#
# severity is the Suricata alert severity, whose label maps the 1-4 numbers to
# names and whose rank sorts High before Low. mitre_tactic and mitre_technique
# read the ATT&CK annotations rulesets (e.g. Emerging Threats) put in
# alert.metadata as single-element arrays of underscored names; the label spaces
# them out. Sagan is not listed: it does not populate alert.severity or MITRE
# metadata, carrying severity in its priority/level columns.
my %VIRTUAL = (
	suricata => {
		severity => {
			column => 'severity',
			expr   => "raw->'alert'->>'severity'",
			label  => sub {
				return
					  "case $_[0] when '1' then 'High' when '2' then 'Medium'"
					. " when '3' then 'Low' when '4' then 'Informational'"
					. " else $_[0] end";
			},
			# natural rank so top() orders High -> Low rather than by count
			order => sub {
				return "case $_[0] when '1' then 1 when '2' then 2 when '3' then 3 when '4' then 4 else 99 end";
			},
		},
		mitre_tactic => {
			column => 'mitre_tactic',
			expr   => "raw->'alert'->'metadata'->'mitre_tactic_name'->>0",
			label  => sub { return "replace($_[0], '_', ' ')" },
		},
		mitre_technique => {
			column => 'mitre_technique',
			expr   => "raw->'alert'->'metadata'->'mitre_technique_name'->>0",
			label  => sub { return "replace($_[0], '_', ' ')" },
		},
	},
);

# Tables whose addresses are worth asking Shodan about, and so the ones the
# %ENRICH dimensions below are offered for. cape is deliberately absent: a
# detonation's src_ip is whoever submitted the sample, not an offender, so
# enriching it would describe the submitter.
my %ENRICH_TABLE = map { $_ => 1 } qw( suricata sagan baphomet );

# The two ends an alert names, each enriched separately -- which end an outside
# host lands on is up to the rule that fired, so a source-only view hides every
# alert about traffic going the other way. src is the attacker on inbound
# traffic; dest is what was reached out to, which is where the C2 and download
# side shows up. Each side keys its join and its unnested rows by its own alias
# so a board can panel both at once without the two colliding.
my %ENRICH_SIDE = (
	src  => { ip_column => 'src_ip',  port_column => 'src_port',  alias => 'shodan_src' },
	dest => { ip_column => 'dest_ip', port_column => 'dest_port', alias => 'shodan_dest' },
);

# Shodan enrichment: dimensions that describe not the alert but the host at one
# end of it, read from shodan_cache by joining on that end's address. This is
# what lets a board keep alert volume on the axis and cut it by what the host
# is -- alerts over time by tag, top attacker CPEs, and so on.
#
# Two shapes, which is what the keys pick between:
#
#   - array :: the shodan_cache array column the values come from. One alert
#     counts once per element, so the slices of such a panel sum to more than
#     the alert total. An address with no cache row, or an empty array, drops
#     out of the panel entirely -- these describe the enriched subset, which is
#     what shodan_coverage is for. text_cast marks an array whose elements are
#     not already text (ports).
#   - columns/expr/order :: a scalar dimension built from the named
#     shodan_cache columns, which travel into the query as <alias>_<column>.
#     expr is the CASE yielding the label and order gives it a natural rank, so
#     a chart reads worst-first rather than by count. These join outward, so an
#     address never looked up still lands in the panel, in its own bucket.
#
# expr and order are written against the side's alias and address and port
# columns, which is why they are code refs: the same shape is built twice, once
# per side.
#
# A shape marked dynamic depends on values that only arrive with the request
# (freshness needs the caller's ttl and source), so the catalog loop below
# keeps its expr/order as code and _col_expr/_order_expr call them at query
# time with the request options. Everything else is still a string built once
# at load.
#
# Either shape drops an alert that names no address on that end (a Baphomet
# judgment passed on a username, say): there is nothing for Shodan to describe,
# and counting it as "not looked up" would read as one that had been missed.
#
# cvss folds "crawled, nothing known" together with "crawled, no CVEs" into
# 'None known': both say the same thing about the host's exposure, and known is
# the dimension that tells them apart.
#
# Neither join needs an index of its own: shodan_cache is one row per address
# and keyed on it, so it joins onto whatever the window already returned.
my %ENRICH_SHAPE = (
	tag   => { array => 'tags' },
	vuln  => { array => 'vulns' },
	cpe   => { array => 'cpes' },
	port  => { array => 'ports', text_cast => 1 },
	known => {
		columns => ['found'],
		expr    => sub {
			my ( $alias, $ip ) = @_;
			return
				  "case when $ip is null then null"
				. " when $alias.${alias}_found is null then 'Not looked up'"
				. " when $alias.${alias}_found then 'Known to Shodan' else 'Not on Shodan' end";
		},
		order => sub {
			my ($alias) = @_;
			return "case when $alias.${alias}_found is null then 3"
				. " when $alias.${alias}_found then 1 else 2 end";
		},
	},
	cvss => {
		columns => [ 'found', 'max_cvss' ],
		expr    => sub {
			my ( $alias, $ip ) = @_;
			return
				  "case when $ip is null then null"
				. " when $alias.${alias}_found is null then 'Not looked up'"
				. " when $alias.${alias}_max_cvss is null then 'None known'"
				. " when $alias.${alias}_max_cvss >= 9.0 then 'Critical (9+)'"
				. " when $alias.${alias}_max_cvss >= 7.0 then 'High (7-8.9)'"
				. " when $alias.${alias}_max_cvss >= 4.0 then 'Medium (4-6.9)'"
				. " else 'Low (<4)' end";
		},
		order => sub {
			my ($alias) = @_;
			return
				  "case when $alias.${alias}_found is null then 6"
				. " when $alias.${alias}_max_cvss is null then 5"
				. " when $alias.${alias}_max_cvss >= 9.0 then 1"
				. " when $alias.${alias}_max_cvss >= 7.0 then 2"
				. " when $alias.${alias}_max_cvss >= 4.0 then 3"
				. " else 4 end";
		},
	},

	# The correlation the two halves above only imply: whether the rule that
	# fired names a CVE that end's cache entry lists it as vulnerable to --
	# "an exploit thrown at a host actually vulnerable to it". The rule's
	# ids come from the cves generated column (schema 16, suricata only, which
	# is what tables/needs_cves say), so the comparison is one array overlap
	# per row and never opens raw. Built for both ends like everything else
	# here: src and dest are the triggering packet's direction, not attacker
	# and victim, so which end the vulnerable host lands on is up to the rule
	# that fired.
	#
	# 'No CVE in rule' leads the tests because with no ids to compare the
	# lookup state of the host is beside the point.
	cve_match => {
		tables     => { suricata => 1 },
		needs_cves => 1,
		columns    => [ 'found', 'vulns' ],
		expr       => sub {
			my ( $alias, $ip ) = @_;
			# the cast because cves is text[] while vulns is varchar[], and &&
			# does not resolve across the two on its own
			return
				  "case when $ip is null then null"
				. " when cves is null then 'No CVE in rule'"
				. " when $alias.${alias}_found is null then 'Not looked up'"
				. " when cves && ($alias.${alias}_vulns)::text[] then 'Matched'"
				. " else 'Not matched' end";
		},
		order => sub {
			my ($alias) = @_;
			return
				  "case when cves is null then 3"
				. " when $alias.${alias}_found is null then 4"
				. " when cves && ($alias.${alias}_vulns)::text[] then 1"
				. " else 2 end";
		},
	},

	# The port half of the same correlation: was the port the flow names at
	# that end one Shodan sees open on that end's host? An exploit at a closed
	# port is scan noise; the same packet at a confirmed listener is an
	# attempt against a live service. Each side reads its own port column --
	# src_port against the source's entry, dest_port against the
	# destination's -- since which end the service sits on is up to the rule
	# that fired.
	#
	# 'Port not seen open' rather than 'closed', deliberately: Shodan's port
	# coverage is protocol weighted rather than a full sweep, so absence from
	# the list is weaker evidence than presence on it. A row cached as "not on
	# Shodan" lands there too -- nothing is known open on it.
	#
	# No needs_cves and no table scoping: the port columns are real columns on
	# every enriched table, and both tiers send ports.
	# Whether the cache's answer for that end would still be used: 'Enriched'
	# (a fresh row from the configured tier), 'Stale' (held, but past the ttl
	# or written by the other tier), or 'Not looked up'. The dimension form of
	# shodan_coverage -- a chart grouped by this and the coverage tile must
	# agree, so both build their freshness test through _freshness_frag. With
	# measure distinct_<side>_ip a timeseries of it says whether the
	# `lilith shodan_cache` timer has been keeping up, and when it fell behind.
	freshness => {
		dynamic => 1,
		columns => [ 'fetched', 'source' ],
		expr    => sub {
			my ( $alias, $ip, $port, $opts ) = @_;
			my $fresh = _freshness_frag( $alias, $opts );
			return
				  "case when $ip is null then null"
				. " when $alias.${alias}_ip is null then 'Not looked up'"
				. " when $fresh then 'Enriched' else 'Stale' end";
		},
		order => sub {
			my ( $alias, $ip, $port, $opts ) = @_;
			my $fresh = _freshness_frag( $alias, $opts );
			return "case when $alias.${alias}_ip is null then 3" . " when $fresh then 1 else 2 end";
		},
	},

	port_match => {
		columns => [ 'found', 'ports' ],
		expr    => sub {
			my ( $alias, $ip, $port ) = @_;
			return
				  "case when $ip is null then null"
				. " when $port is null then 'No port'"
				. " when $alias.${alias}_found is null then 'Not looked up'"
				. " when $port = any($alias.${alias}_ports) then 'Hit an exposed port'"
				. " else 'Port not seen open' end";
		},
		order => sub {
			my ( $alias, $ip, $port ) = @_;
			return
				  "case when $port is null then 3"
				. " when $alias.${alias}_found is null then 4"
				. " when $port = any($alias.${alias}_ports) then 1"
				. " else 2 end";
		},
	},
);

# What the host runs and who it belongs to (schema version 17), as bare
# columns: the dimension groups by the value itself rather than by a CASE
# over it. One appliance OS or one hosting org across many addresses is a
# fleet's fingerprint, which is the read these are for. The join is the
# outward one, but the queries drop null values, so like the array shapes
# these describe the enriched subset -- and the keyless tier stores none of
# the four, so on an InternetDB-only install the panels stay empty.
for my $host_column (qw( os org isp asn )) {
	$ENRICH_SHAPE{$host_column} = {
		columns            => [$host_column],
		needs_host_columns => 1,
		expr               => sub {
			my ($alias) = @_;
			return $alias . '.' . $alias . '_' . $host_column;
		},
	};
} ## end for my $host_column (qw( os org isp asn ))

# The dimension catalog the rest of this file reads: every shape on every side,
# named shodan_<side>_<shape> (shodan_src_tag, shodan_dest_cvss, ...) and with
# the side's alias and address column already folded into its expressions.
# Built rather than written out so the two sides cannot drift apart.
my %ENRICH;
for my $side ( keys %ENRICH_SIDE ) {
	my ( $alias, $ip, $port ) = @{ $ENRICH_SIDE{$side} }{qw( alias ip_column port_column )};

	for my $shape ( keys %ENRICH_SHAPE ) {
		my $spec = $ENRICH_SHAPE{$shape};

		$ENRICH{ 'shodan_' . $side . '_' . $shape } = {
			%{$spec},
			alias     => $alias,
			ip_column => $ip,
			# an array dimension groups by the unnested value; a scalar one by
			# the CASE the shape describes -- kept as code for a dynamic shape,
			# whose CASE needs the request options
			expr => $spec->{array} ? $alias . '_val.v'
			: $spec->{dynamic} ? sub { $spec->{expr}->( $alias, $ip, $port, @_ ) }
			: $spec->{expr}->( $alias, $ip, $port ),
			order => !$spec->{order} ? undef
			: $spec->{dynamic} ? sub { $spec->{order}->( $alias, $ip, $port, @_ ) }
			:                    $spec->{order}->( $alias, $ip, $port ),
		};
	} ## end for my $shape ( keys %ENRICH_SHAPE )
} ## end for my $side ( keys %ENRICH_SIDE )

# Where each end of an alert sits relative to the deployment's own networks:
# 'Internal' when the address is inside one of the local_networks CIDRs the
# caller passes (the web layer passes the config's), 'External' otherwise, and
# left out when the alert names no address on that end. This is what separates
# lateral movement from inbound noise -- "top signatures with an internal
# source" is a different read from the same chart of everything.
#
# No join and no schema requirement: the CASE tests the alert's own address
# column, so it is offered for every table that has the column, cape included.
# Like freshness these are dynamic -- the CIDR list only arrives with the
# request -- so _col_expr/_order_expr build the CASE per query through
# _locality_exprs. The membership test itself (and what Internal means when no
# networks are configured) lives in Lilith::DBUtil::local_networks_frag,
# shared with the search filters of the same names.
my %LOCALITY = (
	src_locality  => 'src_ip',
	dest_locality => 'dest_ip',
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
		{ name => 'avg_score',        label => 'Average score',            agg => 'avg',      expr => 'score' },
		{ name => 'max_score',        label => 'Max score',                agg => 'max',      expr => 'score' },
		{ name => 'distinct_src_ip',  label => 'Distinct source IPs',      agg => 'distinct', col  => 'src_ip' },
		{ name => 'distinct_dest_ip', label => 'Distinct destination IPs', agg => 'distinct', col  => 'dest_ip' },
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

	return $self->_count_where( \%opts, '' );
}

=head2 escalated

    my $n = $stats->escalated( table => 'suricata', go_back_minutes => 1440 );

Number of alerts in the window that carry a non-empty escalations array (i.e.
have been escalated at least once).

=cut

sub escalated {
	my ( $self, %opts ) = @_;

	return $self->_count_where( \%opts, ' and escalations is not null and array_length(escalations, 1) > 0' );
}

=head2 distinct

    my $n = $stats->distinct( table => 'suricata', column => 'src_ip' );

Number of distinct non-null values of C<column> in the window.

=cut

sub distinct {
	my ( $self, %opts ) = @_;

	my $type = $self->_table( $opts{table} );
	my $col  = $self->_dimension( $type, $opts{column} );
	my ( $tbl, $tc, $dbh, $where ) = $self->_query_ctx( $type, \%opts );
	my $colexpr = $self->_col_expr( $type, $col, \%opts );

	# A virtual or enriched column is an expression -- dug out of raw, or read
	# from the joined shodan_cache -- so there is no column for an index to lead
	# with and nothing to walk.
	if ( $colexpr eq $col ) {
		my $walked = $self->_distinct_by_skip_scan( $tbl, $col, $tc, $where );
		return $walked if defined $walked;
	}

	my $from = $self->_from_frag( $type, $col );
	my ($n) = $dbh->selectrow_array("select count(distinct $colexpr) from $from where $where");

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
	my $limit = $self->_limit( $opts{limit}, 10 );
	my ( $tbl, $tc, $dbh, $where ) = $self->_query_ctx( $type, \%opts );

	my $vexpr   = $self->_value_expr( $type, $col, \%opts );
	my $colexpr = $self->_col_expr( $type, $col, \%opts );
	my $magg    = $self->_measure_expr( $type, $opts{measure}, \%opts );
	my $from    = $self->_from_frag( $type, $col );

	# A column with a natural rank (severity, or a Shodan CVSS band) orders by
	# that rank via min() -- an aggregate, so it needs no GROUP BY entry --
	# rather than by the measure (which is what everything else orders by,
	# descending).
	my $rank = $self->_order_expr( $type, $col, \%opts );
	my $ord  = defined $rank ? 'min(' . $rank . ') asc' : '2 desc, 1 asc';

	my $sql
		= "select $vexpr as value, $magg as count from $from "
		. "where $where and $colexpr is not null "
		. "group by 1 order by $ord limit $limit";

	my $rows = $dbh->selectall_arrayref( $sql, { Slice => {} } );

	return [ map { { value => $_->{value}, count => ( $_->{count} // 0 ) + 0 } } @$rows ];
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
	my $bucket = $self->_bucket( $opts{bucket} );
	my ( $tbl, $tc, $dbh, $window ) = $self->_query_ctx( $type, \%opts );

	my $magg  = $self->_measure_expr( $type, $opts{measure}, \%opts );
	my $epoch = "extract(epoch from date_trunc('$bucket', $tc))::bigint";

	if ( defined $opts{group_by} && $opts{group_by} ne '' ) {
		my $g     = $self->_dimension( $type, $opts{group_by} );
		my $gcol  = $self->_col_expr( $type, $g, \%opts );
		my $gexpr = $self->_value_expr( $type, $g, \%opts );
		my $gfrom = $self->_from_frag( $type, $g );
		my $where = "$window and $gcol is not null";

		# A group with a natural rank (severity, or a Shodan CVSS band) orders its
		# series by that rank via min() rather than alphabetically by the label, so
		# the stack reads High -> Low.
		my $grank   = $self->_order_expr( $type, $g, \%opts );
		my $ordered = defined $grank;
		my $gord    = $ordered ? 'min(' . $grank . ') asc' : '2 asc';

		my $sql;
		if ( defined $opts{top_groups} ) {
			my $k = $self->_limit( $opts{top_groups}, 5 );

			# Bucket every group once, then rank the busiest from that result. The
			# obvious form -- naming the top groups in a subquery and joining it
			# against a second pass -- spells the window clause twice and so walks
			# the window twice, and the window is the expensive part. What gets
			# ranked here is already aggregated, a few hundred rows however wide
			# the window. Measured 1.6x quicker at a day and at a month.
			#
			# The rank column travels through the CTE so a virtual group can still
			# order by it rather than by its label.
			my $rank = $ordered ? ', min(' . $grank . ') as rank' : '';
			my $sort = $ordered ? 'per_bucket.rank asc'           : '2 asc';
			$sql
				= "with per_bucket as ("
				. "select $epoch as bucket, $gexpr as grp, $magg as count$rank "
				. "from $gfrom where $where group by 1, 2"
				. "), busiest as ("
				. "select grp from per_bucket group by grp order by sum(count) desc, grp asc limit $k"
				. ") select per_bucket.bucket, per_bucket.grp as \"group\", per_bucket.count "
				. "from per_bucket join busiest using (grp) order by 1 asc, $sort";
		} else {
			$sql = "select $epoch as bucket, $gexpr as \"group\", $magg as count "
				. "from $gfrom where $where group by 1, 2 order by 1 asc, $gord";
		}
		my $rows = $dbh->selectall_arrayref( $sql, { Slice => {} } );

		return [ map { { bucket => $_->{bucket} + 0, group => $_->{group}, count => ( $_->{count} // 0 ) + 0 } }
				@$rows ];
	} ## end if ( defined $opts{group_by} && $opts{group_by...})

	my $sql  = "select $epoch as bucket, $magg as count from $tbl where $window group by 1 order by 1 asc";
	my $rows = $dbh->selectall_arrayref( $sql, { Slice => {} } );

	return [ map { { bucket => $_->{bucket} + 0, count => ( $_->{count} // 0 ) + 0 } } @$rows ];
} ## end sub timeseries

=head2 shodan_coverage

    my $cov = $stats->shodan_coverage(
        table => 'suricata', go_back_minutes => 1440,
        side  => 'src',      ttl => 2592000, source => 'api',
    );
    # { addresses => 200, enriched => 124, percent => 62,
    #   stale => 15, stale_percent => 12 }

How much of the window one side's C<shodan_*> dimensions actually describe, and
how much of that has gone off: the distinct addresses on that end, how many of
those C<shodan_cache> holds an answer for (C<percent> of the addresses), and how
many of those answers would no longer be used (C<stale_percent> of the answers).

C<side> is C<src> (the default) or C<dest>, matching the two families of
enrichment dimensions -- a board panelling both ends wants a figure for each,
since the two are cached to very different depths. On inbound traffic the
destination is usually your own asset, which is private and so never sent to
Shodan at all; a destination coverage near zero there is the truth about the
window rather than a gap to fix.

Worth a panel of its own beside any enrichment chart. The cache holds whatever
has been looked up -- addresses someone opened the IP info modal for, plus what
C<lilith shodan_cache> has warmed -- so an enrichment panel describes that
subset rather than the whole window, and only this says how large a subset it
is, and how much of it still stands.

Staleness follows the same rule the reads do: an answer is stale once it is
older than C<ttl> seconds (default 2592000, a month, as in the config), and
also when C<source> is given and the row came from the other tier, the keyless
summary and the keyed host API differing too much in depth for one to stand in
for the other. A C<ttl> of 0 is caching turned off, and leaves every row stale,
which is what it means.

Both halves come from one pass: the widgets asking for them are two views of
the same question.

Dies for a table that carries no enrichment (C<cape>, whose C<src_ip> is the
submitter), for an unknown side, and when the database has no C<shodan_cache>
table.

=cut

sub shodan_coverage {
	my ( $self, %opts ) = @_;

	my $type = $self->_table( $opts{table} );
	die( $type . " alerts carry no Shodan enrichment\n" )                    unless $ENRICH_TABLE{$type};
	die("the shodan_cache table is not present (needs schema version 15)\n") unless $self->_shodan_available;

	my $side = defined $opts{side} && $opts{side} ne '' ? $opts{side} : 'src';
	die( '"' . $side . '" is not a known side (src, dest)' . "\n" ) unless $ENRICH_SIDE{$side};
	my $ip = $ENRICH_SIDE{$side}{ip_column};

	my ( $tbl, $tc, $dbh, $where ) = $self->_query_ctx( $type, \%opts );

	# the same rule the freshness dimension applies, so this tile and a chart
	# grouped by shodan_*_freshness cannot disagree
	my $fresh = _freshness_frag( 'shodan', \%opts );

	# The addresses are collected first and matched after, so the cache is
	# touched once per distinct address rather than once per alert.
	my $sql
		= "with addresses as (select distinct $ip as ip from $tbl where $where and $ip is not null) "
		. "select count(*), count(shodan.shodan_ip), "
		. "count(*) filter (where shodan.shodan_ip is not null and not ($fresh)) from addresses "
		. "left join (select ip as shodan_ip, fetched as shodan_fetched, source as shodan_source"
		. " from shodan_cache) shodan on shodan.shodan_ip = addresses.ip";

	my ( $addresses, $enriched, $stale ) = $dbh->selectrow_array($sql);
	$addresses = ( $addresses // 0 ) + 0;
	$enriched  = ( $enriched  // 0 ) + 0;
	$stale     = ( $stale     // 0 ) + 0;

	return {
		addresses     => $addresses,
		enriched      => $enriched,
		percent       => $addresses ? int( ( $enriched * 100 / $addresses ) + 0.5 ) : 0,
		stale         => $stale,
		stale_percent => $enriched ? int( ( $stale * 100 / $enriched ) + 0.5 ) : 0,
	};
} ## end sub shodan_coverage

=head2 columns

    my $cols = $stats->columns('suricata');

The sorted list of columns that may be grouped/counted by for a table -- the
same set of accepted columns the other methods validate against, exposed so the
dashboard's widget pickers stay in sync with what the backend will accept.

The C<shodan_*> enrichment dimensions are listed only for a table that has them
and only when the database has the C<shodan_cache> table, so a picker never
offers a column that would come back as an error. The locality pair rides each
side's address column and is listed wherever that column is.

=cut

sub columns {
	my ( $self, $table ) = @_;
	my $type = $self->_table($table);
	my @cols = keys %{ $DIMENSION{$type} };
	push( @cols, keys %{ $VIRTUAL{$type} } ) if $VIRTUAL{$type};
	push( @cols, grep { $DIMENSION{$type}{ $LOCALITY{$_} } } keys %LOCALITY );
	if ( $ENRICH_TABLE{$type} ) {
		push(
			@cols,
			grep {
				my $enrich = $ENRICH{$_};
				( !$enrich->{tables} || $enrich->{tables}{$type} )
					&& !defined( $self->_enrich_unavailable_reason($enrich) )
			} keys %ENRICH
		);
	} ## end if ( $ENRICH_TABLE{$type} )
	return [ sort @cols ];
} ## end sub columns

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

# The DBI handle for this object's dsn/user/pass. Every query in here is read
# only, so the handle is shared through DBI's connect_cached rather than a fresh
# connection per call. The class name goes in as the error prefix so a failure
# to connect names Lilith::Stats rather than the shared helper.
#
# Args: none.
#
# Returns: a DBI database handle with RaiseError set. Dies with
# 'Lilith::Stats: DBI->connect_cached failure... ' and the DBI error when the
# database cannot be reached.
#
#     my $dbh = $self->_dbh;
sub _dbh {
	my ($self) = @_;
	return connect_cached_dbh( ref($self), $self->{dsn}, $self->{user}, $self->{pass} );
}

# The per-query context every aggregation method starts from: the window
# validated, the handle connected, and the WHERE pieces rendered. Split from
# the callers so the six of them do not each spell out the same five lines.
# The caller does its own _table (and any column/side validation) first, so a
# request bad in those ways still dies before anything touches the database.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $opts :: the caller's option hash ref, read for go_back_minutes,
#     start/end, and exclude_classification.
#
# Returns: a list of ( $tbl, $tc, $dbh, $where ) -- the real table name, its
# time column, the shared handle, and the window fragment with any exclusion
# already appended, ready to sit after "where".
#
#     my ( $tbl, $tc, $dbh, $where ) = $self->_query_ctx( $type, \%opts );
#     my ($n) = $dbh->selectrow_array("select count(*) from $tbl where $where");
sub _query_ctx {
	my ( $self, $type, $opts ) = @_;

	my $mins = $self->_minutes( $opts->{go_back_minutes} );
	my ( $tbl, $tc ) = ( $TABLE{$type}, $TIME_COL{$type} );

	my $dbh = $self->_dbh;
	my $exf = $self->_exclude_frag( $dbh, $type, $opts );
	my $win = $self->_window_frag( $dbh, $tc, $opts, $mins );

	return ( $tbl, $tc, $dbh, $win . $exf );
} ## end sub _query_ctx

# count(*) over the window with an optional extra WHERE tail -- the whole of
# total and escalated once the context is built.
#
# Args:
#
#   - $opts :: the caller's option hash ref, as _query_ctx reads it plus
#     'table'.
#   - $extra :: SQL appended after the window fragment, carrying its own
#     leading ' and ', or '' for a bare count.
#
# Returns: the count as an integer, 0 when the window is empty.
#
#     $self->_count_where( \%opts, '' );
sub _count_where {
	my ( $self, $opts, $extra ) = @_;

	my $type = $self->_table( $opts->{table} );
	my ( $tbl, $tc, $dbh, $where ) = $self->_query_ctx( $type, $opts );
	my ($n) = $dbh->selectrow_array("select count(*) from $tbl where $where$extra");

	return ( $n // 0 ) + 0;
}

# The time-window WHERE fragment for time column $tc: an explicit absolute range
# (start and/or end, quoted and cast to timestamptz, so read in the DB session's
# timezone) when either is given, else the now-relative go_back_minutes. Quoted
# rather than interpolated raw, mirroring _exclude_frag; a bad value is a query
# error, not an injection, and the fragment carries no binds so it can be reused
# verbatim inside subqueries. Callers append $exf (the classification exclude).
#
# Args:
#
#   - $dbh :: the handle the timestamps are quoted through, from _dbh.
#   - $tc :: the column to window on, out of %TIME_COL -- 'timestamp' for every
#     table but cape, which has only its analysis 'stop' time.
#   - $opts :: the caller's option hash ref. Read for 'start' and 'end', each a
#     timestamp string Postgres can cast, e.g. '2026-08-05 13:00:00'. Both are
#     optional and either may be given alone.
#   - $mins :: the fallback relative window in minutes, already through
#     _minutes.
#
# Returns: a SQL boolean expression as a string, carrying no bind placeholders
# and no leading 'and' -- either "timestamp >= CURRENT_TIMESTAMP - interval
# '1440 minutes'" or, for an absolute range, "timestamp >= '...'::timestamptz
# and timestamp <= '...'::timestamptz".
#
#     my $win = $self->_window_frag( $dbh, 'timestamp', \%opts, 1440 );
#     my $sql = "select count(*) from suricata_alerts where $win";
sub _window_frag {
	my ( $self, $dbh, $tc, $opts, $mins ) = @_;

	return time_window_clause(
		time_column => $tc,
		opts        => $opts,
		quote_dbh   => $dbh,
		minutes     => $mins,
		and_joiner  => ' and ',
		now_sql     => 'CURRENT_TIMESTAMP',
	);
} ## end sub _window_frag

# The SQL boolean saying one side's joined shodan_cache row would still be
# used, per the request's freshness rule: fetched within the last ttl seconds,
# and (when a source is named) written by that tier. The one place the rule
# lives -- the freshness dimension and the shodan_coverage tile both build
# their test here, so a chart grouped by one and the tile beside it cannot
# disagree.
#
# The ttl is spliced into an interval literal, which cannot take a placeholder,
# so it is proven a number first; the source is checked against the two tier
# names, so both scalars reach the SQL checked. Plain function, not a method.
#
# Args:
#
#   - $alias :: the join alias whose renamed columns the test reads --
#     '<alias>.<alias>_fetched' and '<alias>.<alias>_source'. 'shodan_src' or
#     'shodan_dest' for the dimension joins, 'shodan' for the coverage CTE.
#   - $opts :: the caller's option hash ref, read for ttl (seconds, default
#     2592000; 0 is caching off and leaves every row stale) and source ('api'
#     or 'internetdb'; absent means either tier counts).
#
# Returns: the boolean as a string, no binds. Dies for a ttl that is not a
# non-negative integer or a source outside the two tiers.
#
#     _freshness_frag( 'shodan_src', { ttl => 86400, source => 'api' } );
#     # "shodan_src.shodan_src_fetched > now() - interval '86400 seconds'
#     #  and shodan_src.shodan_src_source = 'api'"
sub _freshness_frag {
	my ( $alias, $opts ) = @_;

	my $ttl = defined $opts->{ttl} && $opts->{ttl} ne '' ? $opts->{ttl} : 2592000;
	die( '"' . $ttl . '" for ttl is not a non-negative integer' . "\n" ) unless $ttl =~ /^[0-9]+$/;

	my $fresh = "$alias.${alias}_fetched > now() - interval '$ttl seconds'";
	if ( defined $opts->{source} && $opts->{source} ne '' ) {
		my $source = $opts->{source};
		die( '"' . $source . '" is not a known source (api, internetdb)' . "\n" )
			unless $source eq 'api' || $source eq 'internetdb';
		$fresh .= " and $alias.${alias}_source = '$source'";
	}

	return $fresh;
} ## end sub _freshness_frag

# The grouping and rank expressions for a locality dimension: which side of the
# deployment's own networks an address column sits on. The membership test (and
# what Internal means when no networks were given, and the checking of each
# entry before it is spliced) is DBUtil's local_networks_frag, shared with the
# search filters. Plain function, not a method.
#
# Args:
#
#   - $ip_column :: the address column the dimension is on, out of %LOCALITY --
#     'src_ip' or 'dest_ip'.
#   - $opts :: the caller's option hash ref, read for local_networks: an array
#     ref of CIDR strings (a bare address counts as its /32 or /128). Absent or
#     empty means the unroutable ranges.
#
# Returns: two strings -- the CASE yielding 'Internal' / 'External' (null for a
# row naming no address, which the callers' is-not-null guard then drops), and
# the rank putting Internal first. Dies naming the entry for a local_networks
# value outside the address character set.
#
#     my ( $expr, $order ) = _locality_exprs( 'src_ip', \%opts );
sub _locality_exprs {
	my ( $ip_column, $opts ) = @_;

	my $inside = local_networks_frag( $ip_column, $opts->{local_networks} );

	return (
		"case when $ip_column is null then null when $inside then 'Internal' else 'External' end",
		"case when $inside then 1 else 2 end",
	);
} ## end sub _locality_exprs

# Check the caller's short table type and hand it back. Everything public here
# takes the short form ('suricata', not 'suricata_alerts'), and this is the one
# gate keeping an unchecked request parameter from reaching %TABLE and, through
# it, the SQL. An undefined or empty type becomes suricata rather than dying,
# that being the dashboard's default view.
#
# Args:
#
#   - $type :: the short table type -- 'suricata', 'sagan', 'cape', or
#     'baphomet'. undef or '' is taken as 'suricata'.
#
# Returns: the checked short type as a string, ready to index %TABLE,
# %TIME_COL, %DIMENSION, and %MEASURE. Dies with '"$type" is not a known table
# type' for anything outside that set.
#
#     my $type = $self->_table( $opts{table} );    # 'suricata'
#     my $tbl  = $TABLE{$type};                    # 'suricata_alerts'
sub _table {
	my ( $self, $type ) = @_;
	$type = 'suricata' unless defined $type && $type ne '';
	die( '"' . $type . '" is not a known table type' . "\n" ) unless $TABLE{$type};
	return $type;
}

# Check a column a caller wants to group or count by against the ones that table
# accepts. The real dimensions (%DIMENSION), the computed ones (%VIRTUAL, such
# as suricata's 'severity' dug out of the raw EVE), and the Shodan enrichment
# ones (%ENRICH, for the tables in %ENRICH_TABLE) all pass. This is what lets
# the web layer hand a request parameter straight through: an unknown column
# comes back as a 400, never as SQL.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the column to group or count by, e.g. 'src_ip' or
#     'classification', a virtual one such as 'severity', or an enrichment one
#     such as 'shodan_tag'.
#
# Returns: the checked column name as a string, unchanged. Dies with 'a column
# is required' when undef or empty, and '"$col" is not an aggregatable column
# for $type' when that table does not accept it. An enrichment column on a
# database with no shodan_cache table dies naming that instead, since the
# column is right and only the database is behind.
#
#     my $col = $self->_dimension( 'suricata', 'src_ip' );
sub _dimension {
	my ( $self, $type, $col ) = @_;
	die("a column is required\n") unless defined $col && $col ne '';

	if ( my $enrich = $self->_enrich_for( $type, $col ) ) {
		my $unavailable = $self->_enrich_unavailable_reason($enrich);
		die($unavailable) if defined $unavailable;
		return $col;
	}

	# a locality dimension rides its side's address column, so it is accepted
	# exactly where that column is
	return $col if $LOCALITY{$col} && $DIMENSION{$type}{ $LOCALITY{$col} };

	die( '"' . $col . '" is not an aggregatable column for ' . $type . "\n" )
		unless $DIMENSION{$type}{$col} || ( $VIRTUAL{$type} && $VIRTUAL{$type}{$col} );
	return $col;
} ## end sub _dimension

# Why an enrichment dimension cannot be served right now, or undef when it
# can: the shodan_cache table itself, then the schema-version-gated columns
# the entry needs. The one list of these checks -- _dimension dies with the
# reason and columns() drops the dimension on any reason, so the picker and
# the validator cannot drift when a new needs_* flag arrives.
#
# Args:
#
#   - $enrich :: the dimension's %ENRICH entry, already table-scoped by the
#     caller (via _enrich_for or columns()'s own tables check).
#
# Returns: undef when the dimension can be served, else the reason as a
# newline-terminated string ready to die with.
#
#     my $unavailable = $self->_enrich_unavailable_reason( $ENRICH{shodan_src_tag} );
sub _enrich_unavailable_reason {
	my ( $self, $enrich ) = @_;

	return "the shodan_cache table is not present (needs schema version 15)\n" unless $self->_shodan_available;
	return "the suricata_alerts cves column is not present (needs schema version 16)\n"
		if $enrich->{needs_cves} && !$self->_column_available( 'suricata_alerts', 'cves' );
	return "the shodan_cache os/org/isp/asn columns are not present (needs schema version 17)\n"
		if $enrich->{needs_host_columns} && !$self->_column_available( 'shodan_cache', 'os' );

	return undef;
} ## end sub _enrich_unavailable_reason

# The %ENRICH entry for a dimension, when that dimension applies to the table
# in play: the table must be one whose addresses are enriched at all, and the
# entry must not be scoped to other tables (cve_match is suricata only).
# Everything reading %ENRICH goes through this so a scoped dimension cannot be
# joined onto a table it does not describe.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the dimension name as the caller has it. Anything -- undef and
#     names that are not enrichment dimensions simply return undef.
#
# Returns: the catalog entry as a hash ref, or undef when the name is not an
# enrichment dimension or does not apply to the table.
#
#     my $enrich = $self->_enrich_for( 'suricata', 'shodan_dest_cve_match' );
sub _enrich_for {
	my ( $self, $type, $col ) = @_;

	my $enrich = defined $col ? $ENRICH{$col} : undef;
	return undef unless $enrich && $ENRICH_TABLE{$type};
	return undef if $enrich->{tables} && !$enrich->{tables}{$type};
	return $enrich;
}

# Whether the database has a column a dimension is gated on: the cves generated
# column (schema version 16) behind cve_match, or shodan_cache's os column
# standing in for the version-17 os/org/isp/asn four, which shipped together so
# one probe answers for all of them.
#
# Detected the same way _virtual_base detects its generated columns, and cached
# the same way _shodan_available caches its answer: per table-and-column pair,
# and only when the question was actually answered, so an unreachable database
# does not hide the dimension for good once it comes back.
#
# Args:
#
#   - $table :: the table the column would be on, e.g. 'suricata_alerts'.
#   - $column :: the column probed for, e.g. 'cves'.
#
# Returns: 1 when the column is there, 0 when it is not or when the catalog
# could not be read.
#
#     $self->_column_available( 'suricata_alerts', 'cves' );    # 1
sub _column_available {
	my ( $self, $table, $column ) = @_;

	my $cached = $self->{_column_available_cache}{$table}{$column};
	return $cached if defined $cached;

	my $present = eval { column_exists( $self->_dbh, $table, $column ) };
	return 0 unless defined $present;

	$self->{_column_available_cache}{$table}{$column} = $present;
	return $present;
} ## end sub _column_available

# Whether the database has the shodan_cache table, and so whether the %ENRICH
# dimensions can be offered and joined.
#
# Detected rather than assumed for the same reason _virtual_base detects its
# generated columns: nothing stops Lilith running against a database still on a
# schema before 15, and an enrichment column is better absent from a picker
# than present and erroring.
#
# The answer is cached for the life of the object, but only when the question
# was actually answered -- a database that could not be reached is not an
# answer, and caching it would hide the columns for good once it came back.
#
# Args: none.
#
# Returns: 1 when the table is there, 0 when it is not or when the catalog
# could not be read.
#
#     $self->_shodan_available;    # 1
sub _shodan_available {
	my ($self) = @_;

	return $self->{_shodan_cache_present} if defined $self->{_shodan_cache_present};

	my $present = eval {
		my ($reg) = $self->_dbh->selectrow_array("select to_regclass('shodan_cache')");
		return defined $reg ? 1 : 0;
	};
	return 0 unless defined $present;

	$self->{_shodan_cache_present} = $present;
	return $present;
} ## end sub _shodan_available

# What a query reads from: the table on its own, or the table with shodan_cache
# joined on when the dimension in play is an enrichment one.
#
# The join goes through a subquery that renames every column it takes to
# <alias>_<column>, so nothing it brings into scope can collide with a column of
# the alert table -- raw is in both, and an unqualified reference to it (which
# is what a pre-schema-13 virtual dimension is) would otherwise be ambiguous.
# The alias carries the side, so the source and destination joins cannot collide
# with each other either.
#
# An array dimension joins inward and unnests, so an alert counts once per
# element and an address with no cache row or an empty array drops out. A scalar
# one joins outward, so an address never looked up still has a row and lands in
# whichever bucket its CASE puts it.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the dimension the query groups or counts by, already through
#     _dimension. undef for a query with no dimension at all.
#
# Returns: the FROM clause body as a string -- just the table name for an
# ordinary column, table plus join (and lateral unnest) for an enrichment one.
#
#     $self->_from_frag( 'suricata', 'src_ip' );
#     # 'suricata_alerts'
#     $self->_from_frag( 'suricata', 'shodan_src_cvss' );
#     # 'suricata_alerts left join (select ip as shodan_src_ip, ...) shodan_src on ...'
sub _from_frag {
	my ( $self, $type, $col ) = @_;

	my $tbl    = $TABLE{$type};
	my $enrich = $self->_enrich_for( $type, $col );
	return $tbl unless $enrich;

	my $alias = $enrich->{alias};
	my $on    = ' on ' . $alias . '.' . $alias . '_ip = ' . $tbl . '.' . $enrich->{ip_column};

	if ( $enrich->{array} ) {
		return
			  $tbl
			. ' join (select ip as '
			. $alias . '_ip, '
			. $enrich->{array} . ' as '
			. $alias
			. '_arr from shodan_cache) '
			. $alias
			. $on
			. ' cross join lateral unnest('
			. $alias . '.'
			. $alias
			. '_arr) as '
			. $alias
			. '_val(v)';
	} ## end if ( $enrich->{array} )

	my $cols = join( ', ', map { $_ . ' as ' . $alias . '_' . $_ } @{ $enrich->{columns} } );
	return $tbl . ' left join (select ip as ' . $alias . '_ip, ' . $cols . ' from shodan_cache) ' . $alias . $on;
} ## end sub _from_frag

# The expression giving a dimension its natural rank, for the columns where
# ordering by count would read wrong: severity (High before a more numerous
# Medium) and the Shodan CVSS bands (Critical first, "not looked up" last).
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the column name, already through _dimension.
#
# Returns: the rank as a SQL expression string, always an integer, or undef for
# a column with no natural order -- which is every ordinary one, and means the
# caller should order by the measure instead.
#
#     $self->_order_expr( 'suricata', 'severity' );    # 'case severity when ...'
#     $self->_order_expr( 'suricata', 'src_ip' );      # undef
sub _order_expr {
	my ( $self, $type, $col, $opts ) = @_;

	if ( my $enrich = $self->_enrich_for( $type, $col ) ) {
		return ref $enrich->{order} eq 'CODE' ? $enrich->{order}->($opts) : $enrich->{order};
	}
	if ( $LOCALITY{$col} ) {
		return ( _locality_exprs( $LOCALITY{$col}, $opts ) )[1];
	}

	return undef unless $VIRTUAL{$type} && $VIRTUAL{$type}{$col} && $VIRTUAL{$type}{$col}{order};
	return $VIRTUAL{$type}{$col}{order}->( $self->_virtual_base( $type, $col ) );
} ## end sub _order_expr

# The SQL aggregate a measure resolves to (count(*) by default). expr/col come
# from the server-defined %MEASURE catalog, never from the request. A distinct
# measure's column resolves through _col_expr so a virtual column would count
# by its expression.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $name :: the measure name out of %MEASURE for that table, e.g. 'count',
#     'sum_bytes', 'distinct_dest_port', 'avg_malscore'. undef or '' is taken
#     as 'count'.
#
# Returns: the aggregate as a SQL expression string, ready to drop into a
# select list -- 'count(*)', 'coalesce(sum(...), 0)', 'count(distinct
# dest_port)', and so on. Dies with '"$name" is not a known measure for $type'
# when the table has no such measure.
#
#     my $agg = $self->_measure_expr( 'suricata', 'sum_bytes' );
#     my $sql = "select $agg from suricata_alerts where $win";
sub _measure_expr {
	my ( $self, $type, $name, $opts ) = @_;
	return measure_expr(
		list            => $MEASURE{$type},
		name            => $name,
		context         => $type,
		column_expr_for => sub { $self->_col_expr( $type, $self->_dimension( $type, $_[0] ), $opts ) },
	);
}

# What a virtual dimension is read from: the generated column when the database
# has one, otherwise the expression that digs it out of raw.
#
# Schema 13 promoted the Suricata severity and MITRE annotations into stored
# generated columns, because reading them from raw is far more expensive than it
# looks. raw averages around 15KB on a real store and is held out of line, so
# every read of a one character severity fetches the whole document back. Over
# thirty days that measured 11.5 seconds against 90 milliseconds for an ordinary
# column, and an index on the expression does not help: Postgres will use one to
# filter by a value but will not hand the value back to satisfy a grouping.
#
# Detected rather than assumed, because nothing stops Lilith running against a
# database still on 12 -- schema_version reports the mismatch but does not
# refuse. On an older database this keeps the previous behaviour.
#
# The answer is cached for the life of the object, since it changes only when
# the schema is migrated.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the virtual dimension name, already through _dimension. The
#     caller has established it is in %VIRTUAL.
#
# Returns: the SQL to read the value, as a string -- a bare column name on
# schema 13 and later, the raw-digging expression before that. Also the
# expression when the catalog cannot be read, so a database that will not answer
# keeps working rather than failing on what is only a speed-up.
#
#     $self->_virtual_base( 'suricata', 'severity' );
#     # 'severity' on schema 13, "raw->'alert'->>'severity'" on 12
sub _virtual_base {
	my ( $self, $type, $col ) = @_;

	my $virtual = $VIRTUAL{$type}{$col};
	my $column  = $virtual->{column};
	return $virtual->{expr} unless defined $column;

	my $cached = $self->{_generated_column_cache}{$type}{$col};
	return ( $cached ? $column : $virtual->{expr} ) if defined $cached;

	my $present = eval { column_exists( $self->_dbh, $TABLE{$type}, $column ) };
	$present = 0 unless defined $present;

	$self->{_generated_column_cache}{$type}{$col} = $present;
	return $present ? $column : $virtual->{expr};
} ## end sub _virtual_base

# The raw SQL reference for an already-validated column: a virtual column's grouping
# expression, an enrichment or locality column's, or the bare column name. This
# is what null checks, distinct, and the timeseries top-groups subquery
# reference.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the column name, already through _dimension.
#   - $opts :: the caller's option hash ref, handed to a dynamic dimension's
#     expression builder (freshness reads ttl/source, locality
#     local_networks). Unread for everything else.
#
# Returns: the SQL to group and filter by, as a string. A real column comes
# back as its own name; a virtual, enrichment, or locality one comes back as
# the expression it stands for, parenthesised by whoever needs it. Anything but
# a real column assumes the FROM clause _from_frag built for the same column.
#
#     $self->_col_expr( 'suricata', 'src_ip' );          # 'src_ip'
#     $self->_col_expr( 'suricata', 'severity' );        # "raw->'alert'->>'severity'"
#     $self->_col_expr( 'suricata', 'shodan_src_tag' );  # 'shodan_src_val.v'
sub _col_expr {
	my ( $self, $type, $col, $opts ) = @_;
	if ( my $enrich = $self->_enrich_for( $type, $col ) ) {
		return ref $enrich->{expr} eq 'CODE' ? $enrich->{expr}->($opts) : $enrich->{expr};
	}
	if ( $LOCALITY{$col} ) {
		return ( _locality_exprs( $LOCALITY{$col}, $opts ) )[0];
	}
	return $self->_virtual_base( $type, $col ) if $VIRTUAL{$type} && $VIRTUAL{$type}{$col};
	return $col;
} ## end sub _col_expr

# The SQL expression yielding a column's display value: a virtual column's label
# expression (or its bare expression when unlabelled), an inet column's bare host
# address, everything else cast to text.
#
# Kept apart from _col_expr because what a chart groups by and what it puts on
# the axis are not always the same string: severity groups by the number and
# shows the name, and an inet column groups by the address but shows it without
# the /32 Postgres would otherwise render.
#
# Args:
#
#   - $type :: the short table type, already through _table.
#   - $col :: the column name, already through _dimension.
#
# Returns: the SQL yielding the label, as a string always producing text.
#
#     $self->_value_expr( 'suricata', 'src_ip' );    # 'host(src_ip)'
#     $self->_value_expr( 'suricata', 'sid' );       # '(sid)::text'
sub _value_expr {
	my ( $self, $type, $col, $opts ) = @_;
	if ( my $enrich = $self->_enrich_for( $type, $col ) ) {
		my $expr = $self->_col_expr( $type, $col, $opts );
		return $enrich->{text_cast} ? '(' . $expr . ')::text' : $expr;
	}
	if ( $LOCALITY{$col} ) {
		return $self->_col_expr( $type, $col, $opts );
	}
	if ( $VIRTUAL{$type} && $VIRTUAL{$type}{$col} ) {
		my $base = $self->_virtual_base( $type, $col );
		my $v    = $VIRTUAL{$type}{$col};
		return $v->{label} ? $v->{label}->($base) : '(' . $base . ')';
	}
	return host_or_text_expr($col);
} ## end sub _value_expr

# Count a column's distinct values in the window by walking an index rather than
# reading the rows, when that is the better trade. The walk itself lives in
# Lilith::DBUtil::distinct_by_skip_scan, shared with Lilith::Allani.
#
# Whether it is worth doing is decided by skip_scan_viable, which wants both
# an index of the right shape and few enough values to be worth walking. Getting
# either wrong is worse than not trying: over a day's window a walk with only a
# (column, id) index measured ten times slower than the count it replaces. The
# cache belongs to this object because the two readers are pointed at different
# databases.
#
# Args:
#
#   - $tbl :: the real table name, out of %TABLE.
#   - $col :: the column to count. A real column only -- a virtual one is an
#     expression with no index to lead with, which the caller checks.
#   - $tc :: the column the window is on, out of %TIME_COL.
#   - $where :: the window fragment plus any exclusion, already rendered with
#     quoted literals so it can be spliced into the subquery as-is.
#
# Returns: the number of distinct non-null values with at least one row in the
# window, as an integer. undef when a skip scan is not the right choice for this
# column, when the walk hit the cap, or when the query failed -- in every case
# meaning the caller should count the rows instead.
#
#     $self->_distinct_by_skip_scan( 'suricata_alerts', 'classification',
#         'timestamp', $win . $exf );
#     # 16
sub _distinct_by_skip_scan {
	my ( $self, $tbl, $col, $tc, $where ) = @_;

	my $dbh = $self->_dbh;
	return undef
		unless skip_scan_viable(
			dbh          => $dbh,
			table        => $tbl,
			column       => $col,
			time_column  => $tc,
			max_distinct => $SKIP_SCAN_CAP,
			cache        => ( $self->{_skip_scan_cache} ||= {} ),
		);

	return distinct_by_skip_scan(
		dbh    => $dbh,
		table  => $tbl,
		column => $col,
		where  => $where,
		cap    => $SKIP_SCAN_CAP,
	);
} ## end sub _distinct_by_skip_scan

# Optional "and classification <> ..." fragment for the exclude_classification
# option (the dashboard's "hide Generic Protocol Command Decode" toggle). The
# value is quoted into a literal so the fragment is safe to splice straight into
# the SQL and to reuse verbatim inside subqueries (no bind bookkeeping). Only
# tables that have a classification column honor it; cape silently ignores it.
#
# Args:
#
#   - $dbh :: the handle the value is quoted through, from _dbh.
#   - $type :: the short table type, already through _table.
#   - $opts :: the caller's option hash ref. Read for
#     'exclude_classification', the classification to leave out, e.g.
#     'Generic Protocol Command Decode'. Optional.
#
# Returns: a SQL fragment as a string, already carrying its leading ' and ' so
# it appends straight onto a where clause, or '' when there is nothing to
# exclude (no value given, or a table with no classification column). Rows with
# a null classification are kept.
#
#     my $exf = $self->_exclude_frag( $dbh, $type, \%opts );
#     my $sql = "select count(*) from $tbl where $win$exf";
sub _exclude_frag {
	my ( $self, $dbh, $type, $opts ) = @_;
	return '' unless $DIMENSION{$type}{classification};
	my $ex = $opts->{exclude_classification};
	return '' unless defined $ex && $ex ne '';
	return ' and (classification is null or classification <> ' . $dbh->quote($ex) . ')';
}

# Check a timeseries bucket before it reaches date_trunc. The unit is spliced
# into the SQL rather than bound, so it has to come off a fixed list; hour is
# the default because it suits the dashboard's usual day-long window.
#
# Args:
#
#   - $bucket :: the date_trunc unit -- 'minute', 'hour', 'day', 'week', or
#     'month'. undef or '' is taken as 'hour'. Note that 'auto' is not accepted
#     here: the frontend sizes that to the window before the value ever reaches
#     the API.
#
# Returns: the checked unit as a string, safe to interpolate. Dies with
# '"$bucket" is not a valid bucket (minute, hour, day, week, month)' otherwise.
#
#     my $unit = $self->_bucket( $opts{bucket} );    # 'hour'
sub _bucket {
	my ( $self, $bucket ) = @_;
	$bucket = 'hour' unless defined $bucket && $bucket ne '';
	return validate_bucket($bucket);
}

# Check the now-relative window before it is interpolated into an interval
# literal. It cannot be bound (Postgres will not take a placeholder inside an
# interval), so it has to be proven an integer first.
#
# Args:
#
#   - $mins :: how far back to look, in minutes, as a string or number. undef
#     or '' is taken as 1440, a day.
#
# Returns: the window as a number, safe to interpolate. Dies with '"$mins" for
# go_back_minutes is not a non-negative integer' for anything that is not
# digits -- negatives and decimals included, since neither is a window.
#
#     my $mins = $self->_minutes( $opts{go_back_minutes} );    # 1440
sub _minutes {
	my ( $self, $mins ) = @_;
	$mins = 1440 unless defined $mins && $mins ne '';
	die( '"' . $mins . '" for go_back_minutes is not a non-negative integer' . "\n" )
		unless $mins =~ /^[0-9]+$/;
	return $mins + 0;
}

# Check a row limit before it is interpolated into a LIMIT clause. Zero is
# refused along with the rest: a limit of none returns nothing, which is never
# what a widget meant to ask for.
#
# Args:
#
#   - $limit :: the caller's requested limit, as a string or number. undef or
#     '' falls back to $default.
#   - $default :: the limit to use when none was asked for, e.g. 10 for a top
#     values widget.
#
# Returns: the limit as a number, safe to interpolate. Dies with '"$limit" is
# not a positive integer limit' for anything that is not a positive integer.
#
#     my $limit = $self->_limit( $opts{limit}, 10 );
sub _limit {
	my ( $self, $limit, $default ) = @_;
	$limit = $default unless defined $limit && $limit ne '';
	die( '"' . $limit . '" is not a positive integer limit' . "\n" )
		unless $limit =~ /^[0-9]+$/ && $limit + 0 > 0;
	return $limit + 0;
}

1;
