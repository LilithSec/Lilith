package Lilith::Web::Controller::Logs;

use Mojo::Base 'Mojolicious::Controller';
use JSON qw(decode_json);

=head1 NAME

Lilith::Web::Controller::Logs - browse the logs stored in Allani.

=head1 DESCRIPTION

Serves the C</logs> search page and the C</logs/:source/:id> record view over a
configured Allani log store (the C<[allani]> block in the config). Reached via
the C<allani> helper, a L<Lilith::Allani> reader; the page is inert (and the nav
entry hidden) unless C<allani_enabled>.

=cut

=head2 index

C<GET /logs> -- the log search form and results. Mirrors the alert Search page:
a sanitized C<source>, a C<go_back_minutes> window, C<limit>/C<offset>, an
C<order_dir>, and per-source filters. With C<partial=1> only the results
fragment is rendered (for auto-refresh).

=cut

sub index {
	my $self = shift;

	# Building the reader can die (e.g. [allani] set but Allani not installed);
	# treat that as the feature being unavailable rather than a 500.
	my ( $reader, $error );
	if ( $self->allani_enabled ) {
		eval { $reader = $self->allani };
		$error = $@ if $@;
	} else {
		$error = 'Allani is not configured; add an [allani] block to the config.';
	}
	my $sources = $reader ? $reader->sources : [];

	my $source = $self->param('source') // 'syslog';
	$source = 'syslog' unless $reader && $reader->valid_source($source);

	my $go_back_minutes = $self->param('go_back_minutes') // 1440;
	my $limit           = $self->param('limit')           // 100;
	my $offset          = $self->param('offset')          // 0;
	my $order_dir       = $self->param('order_dir')       // 'DESC';
	$order_dir = 'DESC' unless $order_dir =~ /^(?:ASC|DESC)$/;

	# Optional time anchor (deep-linked from the event view): show rows within
	# 'window' minutes either side of 'around' instead of the now-relative
	# window. The reader validates/binds both; blank 'around' just means unset.
	my $around = $self->param('around');
	my $window = $self->param('window');
	undef $around if defined $around && $around eq '';

	# Optional absolute range from the time control (start/end); the reader binds
	# them and prefers them over the now-relative go_back_minutes.
	my $start = $self->param('start');
	my $end   = $self->param('end');
	undef $start if defined $start && $start eq '';
	undef $end   if defined $end   && $end eq '';

	# Forward only the filter params this source accepts (the reader derives that
	# set of accepted filters from Allani::Sources), so a param meant for another
	# source cannot reach the query.
	my %filters;
	if ($reader) {
		for my $name ( @{ $reader->filters($source) } ) {
			my $val = $self->param($name);
			$filters{$name} = $val if defined $val && $val ne '';
		}
	}

	my $result;
	if ($reader) {
		eval {
			$result = $reader->search(
				source          => $source,
				go_back_minutes => $go_back_minutes,
				order_dir       => $order_dir,
				limit           => $limit,
				offset          => $offset,
				filters         => \%filters,
				( defined $around ? ( around => $around, window_minutes => $window ) : () ),
				( defined $start  ? ( start  => $start )                             : () ),
				( defined $end    ? ( end    => $end )                               : () ),
			);
		};
		$error = $@ if $@;
	} ## end if ($reader)

	$self->stash(
		sources         => $sources,
		source          => $source,
		result          => $result,
		error           => $error,
		go_back_minutes => $go_back_minutes,
		order_dir       => $order_dir,
		limit           => $limit,
		offset          => $offset,
		filters         => \%filters,
		around          => $around,
		window          => ( $window // 60 ),
	);

	if ( $self->param('partial') && defined $result ) {
		return $self->render( 'logs/_results', layout => undef );
	}

	return;
} ## end sub index

=head2 view

C<GET /logs/:source/:id> -- one log record, with its C<raw> JSON pretty-printed.

=cut

sub view {
	my $self = shift;

	my $source = $self->param('source');
	my $id     = $self->param('id');

	unless ( $self->allani_enabled ) {
		return $self->render( text => 'Allani is not configured', status => 404 );
	}

	my $reader = $self->allani;
	my ( $row, $error, $pretty_raw );
	eval { $row = $reader->row( $source, $id ); };
	$error = $@ if $@;

	if ( $row && defined $row->{raw} ) {
		my $decoded = ref $row->{raw} ? $row->{raw} : eval { decode_json( $row->{raw} ) };
		if ( ref $decoded ) {
			eval { $pretty_raw = JSON->new->pretty->canonical->encode($decoded); };
		} else {
			$pretty_raw = $row->{raw};
		}
	}

	$self->stash(
		source     => $source,
		id         => $id,
		row        => $row,
		error      => $error,
		pretty_raw => $pretty_raw,
	);

	return;
} ## end sub view

=head2 dashboard

C<GET /logs/dashboard> -- the log dashboard shell. Data is pulled by the browser
from the C</api/logs/*> endpoints, so it renders even when the database is
unreachable. Aggregation is over the real single-table sources only (syslog,
http, http_error); the interleaved C<http_all> is not offered here.

=cut

sub dashboard {
	my $self = shift;

	my ( $reader, $error );
	if ( $self->allani_enabled ) {
		eval { $reader = $self->allani };
		$error = $@ if $@;
	} else {
		$error = 'Allani is not configured; add an [allani] block to the config.';
	}

	# real (aggregatable) sources only
	my @sources = $reader ? ( grep { $_->{key} ne 'http_all' } @{ $reader->sources } ) : ();

	my $source = $self->param('source') // 'syslog';
	$source = 'syslog' unless grep { $_->{key} eq $source } @sources;

	my $mins = $self->param('go_back_minutes');
	$mins = 1440 unless defined $mins && $mins =~ /^[0-9]+$/;

	$self->stash(
		sources         => \@sources,
		source          => $source,
		dims            => ( $reader                        ? $reader->dims($source)     : [] ),
		measures        => ( $reader                        ? $reader->measures($source) : [] ),
		geoip           => ( scalar @{ $self->geoip_mmdbs } ? 1                          : 0 ),
		go_back_minutes => $mins,
		error           => $error,
	);

	return;
} ## end sub dashboard

=head2 summary

C<GET /api/logs/summary> -- C<< { total, distinct_host } >> for the source/window.

=cut

sub summary {
	my $self = shift;
	my ( $source, $mins ) = $self->_dparams;
	return $self->_ljson(
		sub {
			my $r = shift;
			return {
				total         => $r->total( source => $source, go_back_minutes => $mins ),
				distinct_host => $r->distinct( source => $source, column => 'host', go_back_minutes => $mins ),
			};
		}
	);
} ## end sub summary

=head2 top

C<GET /api/logs/top?column=&limit=&measure=> -- the top values of a dimension,
as C<< { rows => [ { value, count }, ... ] } >>. C<measure> (default count)
selects what C<count> holds.

=cut

sub top {
	my $self = shift;
	my ( $source, $mins ) = $self->_dparams;
	my $column  = $self->param('column');
	my $limit   = $self->param('limit');
	my $measure = $self->param('measure');
	return $self->_ljson(
		sub {
			my $r    = shift;
			my $rows = $r->top(
				source          => $source,
				column          => $column,
				go_back_minutes => $mins,
				( defined $limit   && $limit ne ''   ? ( limit   => $limit )   : () ),
				( defined $measure && $measure ne '' ? ( measure => $measure ) : () ),
			);
			return { rows => $rows };
		}
	);
} ## end sub top

=head2 timeseries

C<GET /api/logs/timeseries?bucket=&group_by=&measure=> -- counts bucketed over
time, as C<< { rows, bucket, grouped } >>. With C<group_by> each row carries a
C<group> and C<grouped> is 1 (for a stacked chart); C<bucket> is the unit
actually used, so an C<auto> request can be labelled.

=cut

sub timeseries {
	my $self = shift;
	my ( $source, $mins ) = $self->_dparams;
	my $bucket   = $self->param('bucket');
	my $group_by = $self->param('group_by');
	my $measure  = $self->param('measure');
	my $grouped  = ( defined $group_by && $group_by ne '' ) ? 1 : 0;
	return $self->_ljson(
		sub {
			my $r    = shift;
			my $rows = $r->timeseries(
				source          => $source,
				go_back_minutes => $mins,
				( defined $bucket && $bucket ne ''   ? ( bucket   => $bucket )   : () ),
				( $grouped                           ? ( group_by => $group_by ) : () ),
				( defined $measure && $measure ne '' ? ( measure  => $measure )  : () ),
			);
			return { rows => $rows, bucket => $r->bucket( $bucket, $mins ), grouped => $grouped };
		}
	);
} ## end sub timeseries

=head2 countries

C<GET /api/logs/countries> -- the busiest source countries for the source/window,
resolved from the top source IPs through the GeoIP databases the web UI opens, as
C<< { enabled => 0|1, rows => [ { country, count }, ... ] } >>. C<enabled> is 0
(rows empty) when no MMDB is configured. Mirrors the alert dashboard's panel.

=cut

sub countries {
	my $self = shift;
	my ( $source, $mins ) = $self->_dparams;

	return $self->render( json => { enabled => 0, rows => [] } )
		unless scalar @{ $self->geoip_mmdbs };

	return $self->_ljson(
		sub {
			my $r   = shift;
			my $ips = $r->top_ips( source => $source, go_back_minutes => $mins, limit => 500 );

			my %by;
			for my $row (@$ips) {
				my $cc = $self->ip_country( $row->{value} );
				$cc = '??' unless defined $cc && $cc ne '';
				$by{$cc} += $row->{count};
			}

			my @rows = map { { country => $_, count => $by{$_} } }
				sort { $by{$b} <=> $by{$a} || $a cmp $b } keys %by;
			@rows = @rows[ 0 .. 14 ] if @rows > 15;

			return { enabled => 1, rows => \@rows };
		}
	);
} ## end sub countries

# Shared source/window parsing for the dashboard API. The source is validated by
# the reader (a bad one dies -> 400 via _ljson), so it is passed through as-is.
sub _dparams {
	my $self   = shift;
	my $source = $self->param('source') // 'syslog';
	my $mins   = $self->param('go_back_minutes');
	$mins = 1440 unless defined $mins && $mins =~ /^[0-9]+$/;
	return ( $source, $mins );
}

# Render whatever $code->($reader) returns as JSON, turning a reader die (bad
# source/column, unreachable database) into a 400 with the message, and a
# missing [allani] into a 400 rather than a 500.
sub _ljson {
	my ( $self, $code ) = @_;
	return $self->render( json => { error => 'Allani is not configured' }, status => 400 )
		unless $self->allani_enabled;
	my $data = eval { $code->( $self->allani ) };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( json => { error => $why }, status => 400 );
	}
	return $self->render( json => $data );
} ## end sub _ljson

1;
