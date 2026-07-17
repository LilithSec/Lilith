package Lilith::Web::Controller::Dashboard;

use Mojo::Base 'Mojolicious::Controller';

# The noisy classification the search page also hides by default. The dashboard
# shows it unless the "Show GPCD" checkbox is cleared (show_gpcd=0).
my $GPCD = 'Generic Protocol Command Decode';

# Widget model: the types a saved layout may contain and the config keys each may
# carry. Anything else is dropped when a layout is stored, so an arbitrary posted
# body cannot smuggle unknown widget types or config into the database.
my %WIDGET_TYPE = map { $_ => 1 } qw( timeseries top countries );
my %CONFIG_KEY  = map { $_ => 1 } qw( column group_by limit style measure );

=head1 NAME

Lilith::Web::Controller::Dashboard - dashboard page and its aggregation API.

=head1 DESCRIPTION

Serves the C</dashboard> shell and the C</api/dashboard/*> JSON endpoints that
back its charts. All aggregation runs through L<Lilith::Stats> (reached via the
C<lilith> helper), which whitelists every table/column/bucket, so request
parameters are passed straight through and a bad one comes back as a 400 rather
than reaching SQL.

=cut

# Shared parameter parsing: the table type (defaulted/sanitized like Search) and
# the go_back_minutes window (Lilith::Stats re-validates, but keep the shell and
# the API consistent).
sub _params {
	my $self = shift;

	my $table = $self->param('table') // 'suricata';
	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape)$/;

	my $mins = $self->param('go_back_minutes');
	$mins = 1440 unless defined $mins && $mins =~ /^[0-9]+$/;

	# GPCD is noisy, so it is hidden by default (like the search page); the
	# checkbox, when set, posts show_gpcd=1 to include it. When hidden we pass
	# exclude_classification through to every Lilith::Stats call (Stats ignores it
	# for cape, which has no classification).
	my $sg     = $self->param('show_gpcd');
	my @filter = ( defined $sg && $sg eq '1' ) ? () : ( exclude_classification => $GPCD );

	return ( $table, $mins, @filter );
} ## end sub _params

# Render whatever $code returns as JSON, turning a Lilith::Stats die (bad
# column, unreachable database, ...) into a 400 with the message.
sub _json {
	my ( $self, $code ) = @_;

	my $data = eval { $code->() };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}
	return $self->render( json => $data );
} ## end sub _json

=head2 index

C<GET /dashboard> -- the shell page. Data is pulled by the browser from the API
endpoints below, so this renders even when the database is unreachable.

=cut

sub index {
	my $self = shift;
	my ( $table, $mins ) = $self->_params;
	my $sg = $self->param('show_gpcd');
	$self->stash(
		table           => $table,
		go_back_minutes => $mins,
		show_gpcd       => ( defined $sg && $sg eq '1' ) ? 1 : 0,
	);
	return;
} ## end sub index

=head2 summary

C<GET /api/dashboard/summary> -- the stat-card numbers: total alerts, distinct
source IPs, a per-table "detail" distinct (signatures for suricata/sagan,
targets for cape), and the busiest instance.

=cut

sub summary {
	my $self = shift;
	my ( $table, $mins, @filter ) = $self->_params;

	# suricata/sagan carry signatures; cape does not, so fall back to target.
	my $detail_col = ( $table eq 'cape' ) ? 'target' : 'signature';

	return $self->_json(
		sub {
			my $stats   = $self->lilith->stats;
			my $busiest = $stats->top(
				table           => $table,
				column          => 'instance',
				limit           => 1,
				go_back_minutes => $mins,
				@filter
			);
			return {
				total           => $stats->total( table => $table, go_back_minutes => $mins, @filter ),
				escalated       => $stats->escalated( table => $table, go_back_minutes => $mins, @filter ),
				distinct_src_ip =>
					$stats->distinct( table => $table, column => 'src_ip', go_back_minutes => $mins, @filter ),
				distinct_detail =>
					$stats->distinct( table => $table, column => $detail_col, go_back_minutes => $mins, @filter ),
				detail_label     => $detail_col,
				busiest_instance => $busiest->[0],
			};
		}
	);
} ## end sub summary

=head2 top

C<GET /api/dashboard/top?column=&limit=> -- the most common values of a column,
as C<< { rows => [ { value, count }, ... ] } >>.

=cut

sub top {
	my $self = shift;
	my ( $table, $mins, @filter ) = $self->_params;
	my $column = $self->param('column');
	my $limit  = $self->param('limit');

	my $measure = $self->param('measure');

	return $self->_json(
		sub {
			my $rows = $self->lilith->stats->top(
				table           => $table,
				column          => $column,
				go_back_minutes => $mins,
				( defined $limit   && $limit ne ''   ? ( limit   => $limit )   : () ),
				( defined $measure && $measure ne '' ? ( measure => $measure ) : () ),
				@filter,
			);
			return { rows => $rows };
		}
	);
} ## end sub top

=head2 timeseries

C<GET /api/dashboard/timeseries?bucket=&group_by=&top_groups=> -- alert counts
bucketed over time, optionally split by a column. Returns
C<< { grouped => 0|1, rows => [ ... ] } >>.

=cut

sub timeseries {
	my $self = shift;
	my ( $table, $mins, @filter ) = $self->_params;
	my $bucket     = $self->param('bucket');
	my $group_by   = $self->param('group_by');
	my $top_groups = $self->param('top_groups');
	my $measure    = $self->param('measure');

	my $grouped = ( defined $group_by && $group_by ne '' ) ? 1 : 0;

	return $self->_json(
		sub {
			my $rows = $self->lilith->stats->timeseries(
				table           => $table,
				go_back_minutes => $mins,
				( defined $bucket && $bucket ne ''         ? ( bucket     => $bucket )     : () ),
				( $grouped                                 ? ( group_by   => $group_by )   : () ),
				( defined $top_groups && $top_groups ne '' ? ( top_groups => $top_groups ) : () ),
				( defined $measure && $measure ne ''       ? ( measure    => $measure )    : () ),
				@filter,
			);
			return { grouped => $grouped, rows => $rows };
		}
	);
} ## end sub timeseries

=head2 countries

C<GET /api/dashboard/countries> -- top source countries, resolved from the
busiest source IPs through the GeoIP databases the web UI already opens. Returns
C<< { enabled => 0|1, rows => [ { country, count }, ... ] } >>; C<enabled> is 0
(and rows empty) when no MMDB is configured, so the panel can note that rather
than showing everything as unknown.

=cut

sub countries {
	my $self = shift;
	my ( $table, $mins, @filter ) = $self->_params;

	return $self->render( json => { enabled => 0, rows => [] } )
		unless scalar @{ $self->geoip_mmdbs };

	return $self->_json(
		sub {
			# Aggregate the busiest source IPs into countries. Only the top IPs are
			# geolocated, so this is the country breakdown of the top talkers, not
			# every row -- enough for a dashboard and cheap.
			my $ips = $self->lilith->stats->top(
				table           => $table,
				column          => 'src_ip',
				go_back_minutes => $mins,
				limit           => 500,
				@filter,
			);

			my %by;
			for my $r (@$ips) {
				my $cc = $self->ip_country( $r->{value} );
				$cc = '??' unless defined $cc && $cc ne '';
				$by{$cc} += $r->{count};
			}

			my @rows = map { { country => $_, count => $by{$_} } }
				sort { $by{$b} <=> $by{$a} || $a cmp $b } keys %by;
			@rows = @rows[ 0 .. 14 ] if @rows > 15;

			return { enabled => 1, rows => \@rows };
		}
	);
} ## end sub countries

=head2 layout

C<GET /api/dashboard/layout> -- the saved global dashboard layout, as
C<< { name, layout => [ { id, x, y, w, h }, ... ], is_default } >>. Falls back
to an empty layout (the panels' built-in default positions) when none is saved.

=cut

sub layout {
	my $self = shift;
	return $self->_json(
		sub {
			my $board = $self->lilith->dashboard_get( name => 'default' );
			return $board || { name => 'default', layout => [], is_default => 1 };
		}
	);
}

=head2 columns

C<GET /api/dashboard/columns?table=> -- the columns a widget on that table may
group/count by, as C<< { table, columns => [ ... ] } >>. Drives the widget
config pickers from the same whitelist the API validates against.

=cut

sub columns {
	my $self = shift;
	my ($table) = $self->_params;
	return $self->_json(
		sub {
			return { table => $table, columns => $self->lilith->stats->columns($table) };
		}
	);
}

=head2 measures

C<GET /api/dashboard/measures?table=> -- the measures a top/timeseries widget on
that table may aggregate by, as C<< { table, measures => [ { name, label } ] } >>.

=cut

sub measures {
	my $self = shift;
	my ($table) = $self->_params;
	return $self->_json(
		sub {
			return { table => $table, measures => $self->lilith->stats->measures($table) };
		}
	);
}

=head2 layout_save

C<POST /api/dashboard/layout> -- persist the global dashboard layout. The body is
JSON C<< { layout => [ { id, type, config, x, y, w, h }, ... ] } >>; anything else
is a 400. Widgets without a known type, and any unknown config keys, are dropped.

=cut

sub layout_save {
	my $self = shift;

	my $body = $self->req->json;
	unless ( ref $body eq 'HASH' && ref $body->{layout} eq 'ARRAY' ) {
		return $self->render( json => { error => 'expected a JSON body with a layout array' }, status => 400 );
	}

	# Keep only known widget types, their whitelisted config keys, and the integer
	# geometry, so an arbitrary posted body cannot smuggle anything into storage.
	my @clean;
	for my $w ( @{ $body->{layout} } ) {
		next unless ref $w eq 'HASH'   && defined $w->{id};
		next unless defined $w->{type} && $WIDGET_TYPE{ $w->{type} };

		my %cfg;
		if ( ref $w->{config} eq 'HASH' ) {
			for my $k ( keys %{ $w->{config} } ) {
				next unless $CONFIG_KEY{$k};
				my $v = $w->{config}{$k};
				next if ref $v;
				$cfg{$k} = ( $k eq 'limit' ) ? int($v) : '' . $v;
			}
		}

		push(
			@clean,
			{
				id     => '' . $w->{id},
				type   => $w->{type},
				config => \%cfg,
				x      => int( $w->{x} // 0 ),
				y      => int( $w->{y} // 0 ),
				w      => int( $w->{w} // 1 ),
				h      => int( $w->{h} // 1 ),
			}
		);
	} ## end for my $w ( @{ $body->{layout} } )

	return $self->_json(
		sub {
			$self->lilith->dashboard_save( name => 'default', layout => \@clean );
			return { ok => 1, count => scalar @clean };
		}
	);
} ## end sub layout_save

1;
