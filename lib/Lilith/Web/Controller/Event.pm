package Lilith::Web::Controller::Event;

use Mojo::Base 'Mojolicious::Controller';
use JSON               qw(decode_json);
use MIME::Base64       qw(decode_base64);
use File::Temp         ();
use Time::Piece::Guess ();
use Mojo::IOLoop       ();
use URI::Escape        qw(uri_escape);
use Lilith::Shodan     ();
use Lilith::CVEDB      ();

=head1 NAME

Lilith::Web::Controller::Event - Event detail controller for Lilith::Web.

=head1 DESCRIPTION

Fetches and displays a single alert event by row ID.

=cut

=head2 view

Renders the detail page for a single event.

=cut

sub view {
	my $self = shift;

	my $table = $self->param('table');
	my $id    = $self->param('id');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape|baphomet)$/;

	my ( $event, $error ) = $self->_load_event( $table, $id );

	# A Baphomet score says nothing the per subject scores do not, and says it for
	# the record as a whole, so the info grid carries the same subjects line the
	# search results Subjects column does in its place. It is nested detail rather
	# than a column, so build it off raw here. A record with no subject vars at
	# all simply gets neither field.
	if ( $table eq 'baphomet' && $event ) {
		delete $event->{score};
		my $subjects = $self->baphomet_subjects_line( $event->{raw} );
		$event->{subjects} = $subjects if ( $subjects ne '' );
	}

	my $pretty_raw;
	if ( $event && ref $event->{raw} eq 'HASH' ) {
		eval {
			my $j = JSON->new->pretty->canonical;
			$pretty_raw = $j->encode( $event->{raw} );
		};
	} elsif ( $event && defined $event->{raw} ) {
		$pretty_raw = $event->{raw};
	}

	# PCAP download availability + the configured Virani remotes to choose from.
	# The default selection is the remote whose name matches the event instance.
	# The filter/start/end are stashed so the UI can also show a local virani
	# command for fetching the same flow on the box holding the PCAPs.
	my @remotes        = sort keys %{ $self->virani_remotes };
	my $pcap_available = 0;
	my ( $pcap_filter, $pcap_start, $pcap_end, $pcap_default );
	if ( $self->virani_enabled && $table eq 'suricata' && $event ) {
		my ( $filter, $start, $end );
		eval { ( $filter, $start, $end ) = _virani_fetch_args( $event, 60 ); };
		if ( !$@ && defined $filter ) {
			$pcap_available = 1;
			$pcap_filter    = $filter;
			$pcap_start     = $start->epoch;
			$pcap_end       = $end->epoch;
			if ( defined $event->{instance} && $self->virani_remotes->{ $event->{instance} } ) {
				$pcap_default = $event->{instance};
			}
		}
	} ## end if ( $self->virani_enabled && $table eq 'suricata'...)

	# CAPE detonation results (screenshots + lite.json signatures) are shown for a
	# cape event only when its instance has a configured results endpoint. The
	# section itself loads asynchronously from /event/cape/<id>/cape_results, so
	# here we only decide whether to render its container at all.
	my $cape_results_available
		= ( $table eq 'cape' && $event && $self->cape_results_for( $event->{instance} ) ) ? 1 : 0;

	# What the Shodan cache holds for each end of the flow, rendered as a
	# summary line per end, and -- the loud one -- whether the rule names a CVE
	# the destination is cached as vulnerable to. Cache only, never a lookup;
	# the modal stays the place the full detail lives.
	my ( $shodan_strip, $cve_match ) = $self->_shodan_strip( $table, $event );

	$self->stash(
		event                  => $event,
		table                  => $table,
		id                     => $id,
		error                  => $error,
		pretty_raw             => $pretty_raw,
		shodan_strip           => $shodan_strip,
		cve_match              => $cve_match,
		cape_results_available => $cape_results_available,
		log_links              => ( $self->allani_enabled ? $self->_log_links($event) : [] ),
		pcap_available         => $pcap_available,
		pcap_remotes           => \@remotes,
		pcap_default           => $pcap_default,
		pcap_filter            => $pcap_filter,
		pcap_start             => $pcap_start,
		pcap_end               => $pcap_end,
	);
} ## end sub view

# The per-end Shodan summary for the event view, plus the CVE match.
#
# Reads the cache and nothing else, by way of shodan_cache_info -- an event has
# two ends, so this is one small query, and an end with no fresh entry simply
# gets no line. Each end that has one is normalized the same way the modal's
# data is, so the strip and the modal cannot disagree about what Shodan said.
#
# The keyless tier sends no CVSS scores of its own; the CVEDB cache stands in
# where it holds one, the same way the search badges coalesce. One read covers
# both ends and the matched ids' KEV flags.
#
# The match itself -- the rule naming a CVE the destination's entry lists it
# as vulnerable to -- is suricata only, since only suricata rules carry CVE
# metadata. It is the same comparison the search page's cve_matches helper
# makes; here the ids come annotated so the banner can say how bad.
#
# Args:
#
#   - $table :: the table the event is from. cape gets nothing -- its
#     addresses are the submitter's, not an attacker's, the same reasoning
#     that keeps it out of the dashboard's enrichment dimensions.
#
#   - $event :: the loaded event row, raw already decoded, as _load_event
#     returns it. Its src_ip, dest_ip, and raw are read.
#
# Returns: two values, the strip and the match.
#
# The strip is a hash ref with a key per end that had a fresh cache entry:
#
#     {
#       dest => {
#         ip         => '192.0.2.10',
#         found      => 1,          # 0 = cached as "not on Shodan"
#         age        => '3d',       # how long ago Lilith fetched it
#         info       => {...},      # Lilith::Shodan::normalize output
#         vuln_count => 3,
#         worst_cvss => 9.8,        # undef when nothing anywhere scored them
#       },
#     }
#
# The match is undef, or an array ref of the matched ids with what is known
# of each: [ { cve => 'CVE-2021-44228', cvss => 10.0, kev => 1 }, ... ].
#
#     my ( $strip, $match ) = $self->_shodan_strip( $table, $event );
sub _shodan_strip {
	my ( $self, $table, $event ) = @_;

	return ( {}, undef ) unless $self->shodan_enable;
	my $ttl = $self->shodan_cache_ttl;
	return ( {}, undef ) unless $ttl > 0;
	return ( {}, undef ) unless defined $table && $table =~ /^(?:suricata|sagan|baphomet)$/;
	return ( {}, undef ) unless ref $event eq 'HASH';

	# Filtered to what may be handed to Postgres as an inet, the same as the
	# badges read: one unparseable value would fail the whole statement.
	my %end_ip;
	for my $end (qw(src dest)) {
		my $ip = $event->{ $end . '_ip' };
		$end_ip{$end} = $ip if defined $ip && $ip =~ /^[0-9a-fA-F:.]+$/;
	}
	return ( {}, undef ) unless %end_ip;

	my $cached = eval {
		$self->lilith->shodan_cache_info(
			ips    => [ sort values %end_ip ],
			source => $self->shodan_source,
			ttl    => $ttl,
		);
	};
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		$self->app->log->warn( 'shodan strip lookup failed: ' . $why );
		return ( {}, undef );
	}

	my %strip;
	for my $end ( keys %end_ip ) {
		my $entry = $cached->{ $end_ip{$end} };
		next unless ref $entry eq 'HASH';

		my $info = Lilith::Shodan::normalize( $entry->{raw}, $self->shodan_source, $end_ip{$end} );
		$strip{$end} = {
			ip         => $end_ip{$end},
			found      => $entry->{found},
			age        => _age_string( $entry->{age_seconds} ),
			info       => $info,
			vuln_count => scalar @{ ref $info->{vulns} eq 'ARRAY' ? $info->{vulns} : [] },
		};
	} ## end for my $end ( keys %end_ip )
	return ( {}, undef ) unless %strip;

	# the match: the rule's ids against what the destination is cached as
	# vulnerable to
	my @matched;
	my %dest_vuln;
	if ( $table eq 'suricata' && ref $strip{dest} eq 'HASH' ) {
		%dest_vuln = map { $_->{cve} => $_ }
			grep { ref eq 'HASH' && defined $_->{cve} }
			@{ ref $strip{dest}{info}{vulns} eq 'ARRAY' ? $strip{dest}{info}{vulns} : [] };
		@matched = grep { $dest_vuln{$_} } @{ Lilith::CVEDB::rule_cves( $event->{raw} ) };
	}

	# What the CVEDB cache is wanted for: a score where Shodan sent none, and
	# the matched ids' KEV flags. Absent rows just leave those blank.
	my %annotations;
	{
		my %want = map { $_ => 1 } @matched;
		for my $end ( keys %strip ) {
			for my $vuln ( @{ ref $strip{$end}{info}{vulns} eq 'ARRAY' ? $strip{$end}{info}{vulns} : [] } ) {
				next unless ref $vuln eq 'HASH' && defined $vuln->{cve};
				$want{ $vuln->{cve} } = 1 if !defined $vuln->{cvss} || $vuln->{cvss} eq '';
			}
		}
		if (%want) {
			my $rows = eval { $self->lilith->cvedb_cache_annotations( cves => [ sort keys %want ] ) };
			if ($@) {
				( my $why = $@ ) =~ s/\s+\z//;
				$self->app->log->warn( 'cvedb cache read failed, strip CVEs left unannotated: ' . $why );
			}
			%annotations = %{$rows} if ref $rows eq 'HASH';
		}
	}

	# the worst score per end, CVEDB standing in for the scoreless
	for my $end ( keys %strip ) {
		my $worst;
		for my $vuln ( @{ ref $strip{$end}{info}{vulns} eq 'ARRAY' ? $strip{$end}{info}{vulns} : [] } ) {
			next unless ref $vuln eq 'HASH';
			my $cvss = defined $vuln->{cvss} && $vuln->{cvss} ne '' ? $vuln->{cvss} : undef;
			if ( !defined($cvss) && defined $vuln->{cve} && ref $annotations{ $vuln->{cve} } eq 'HASH' ) {
				my $stand_in = $annotations{ $vuln->{cve} }{cvss};
				$cvss = $stand_in if defined $stand_in && $stand_in ne '';
			}
			next unless defined $cvss && $cvss =~ /^[0-9.]+$/;
			$worst = $cvss if !defined($worst) || $cvss > $worst;
		} ## end for my $vuln ( @{ ref $strip{$end}{info}{vulns...}})
		$strip{$end}{worst_cvss} = $worst;
	} ## end for my $end ( keys %strip )

	my $cve_match;
	if (@matched) {
		my @detail;
		for my $cve (@matched) {
			my $annotation = ref $annotations{$cve} eq 'HASH' ? $annotations{$cve} : {};
			my $cvss
				= defined $dest_vuln{$cve}{cvss} && $dest_vuln{$cve}{cvss} ne ''
				? $dest_vuln{$cve}{cvss}
				: $annotation->{cvss};
			push(
				@detail,
				{
					cve  => $cve,
					cvss => ( defined $cvss && $cvss ne '' ? $cvss : undef ),
					kev  => ( $annotation->{kev}           ? 1     : 0 ),
				}
			);
		} ## end for my $cve (@matched)
		$cve_match = \@detail;
	} ## end if (@matched)

	return ( \%strip, $cve_match );
} ## end sub _shodan_strip

# A compact "how old" for the strip's cache age: days once it is a day old,
# then hours, then minutes. The reader wants "roughly how much to trust this",
# not a timestamp. Plain function, not a method.
#
# Args:
#
#   - $seconds :: the age in seconds, as shodan_cache_info returns it.
#     Anything non-numeric reads as 0.
#
# Returns: the age as a short string.
#
#     _age_string(259200);   # '3d'
#     _age_string(7200);     # '2h'
#     _age_string(90);       # '1m'
#     _age_string(30);       # '<1m'
sub _age_string {
	my $seconds = shift;

	$seconds = 0 unless defined $seconds && $seconds =~ /^[0-9]+$/;
	return int( $seconds / 86400 ) . 'd' if $seconds >= 86400;
	return int( $seconds / 3600 ) . 'h'  if $seconds >= 3600;
	return int( $seconds / 60 ) . 'm'    if $seconds >= 60;
	return '<1m';
}

=head2 pcap

Fetches the PCAP for a Suricata event from a configured remote Virani instance
(selected via the C<remote> query parameter) and streams it back as a download.

=cut

sub pcap {
	my $self = shift;

	my $table  = $self->param('table');
	my $id     = $self->param('id');
	my $remote = $self->param('remote');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape|baphomet)$/;

	unless ( $self->virani_enabled ) {
		return $self->render( text => 'PCAP retrieval is not configured', status => 404 );
	}
	unless ( $table eq 'suricata' ) {
		return $self->render( text => 'PCAP is only available for Suricata events', status => 400 );
	}
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( text => 'invalid id', status => 400 );
	}

	my $cfg    = ( defined $remote ) ? $self->virani_remotes->{$remote} : undef;
	my $client = $self->virani_client_for($remote);
	unless ( $cfg && $client ) {
		return $self->render( text => 'unknown or unusable virani instance', status => 400 );
	}

	# An explicit ?set= overrides the remote's default set. Empty means default.
	my $set = $self->param('set');
	if ( defined $set && $set ne '' ) {
		return $self->render( text => 'invalid set', status => 400 )
			unless $set =~ /^[A-Za-z0-9._-]+$/;
	} else {
		$set = $cfg->{set};
	}

	my ( $event, $error ) = $self->_load_event( $table, $id );
	if ( $error || !$event ) {
		return $self->render( text => 'event not found', status => 404 );
	}

	my ( $filter, $start, $end );
	eval { ( $filter, $start, $end ) = _virani_fetch_args( $event, 60 ); };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		return $self->render( text => 'cannot build PCAP query: ' . $why, status => 400 );
	}

	return $self->virani_stream_pcap(
		sub {
			my $file = shift;
			$client->fetch(
				start  => $start,
				end    => $end,
				filter => $filter,
				file   => $file,
				( ( defined $set && $set ne '' ) ? ( set  => $set )         : () ),
				( defined $cfg->{type}           ? ( type => $cfg->{type} ) : () ),
			);
		},
		'event-' . $id . '.pcap',
	);
} ## end sub pcap

# Turn an event into the arguments a Virani PCAP fetch wants: a BPF filter for
# the flow and the window to look for it in.
#
# The filter matches both endpoints rather than a direction, so the reply
# traffic comes back with the request. Ports are added only when both are
# present and numeric -- an event without them (ICMP, say) still gets a usable
# host-pair filter rather than a broken expression.
#
# The window is widened by $buffer on each end because flow_start and timestamp
# bound the flow as the sensor saw it, and the capture on disk is rotated on its
# own schedule. Without the slack the handshake or the tail of the conversation
# routinely falls outside the query.
#
# Plain function, not a method.
#
# Args:
#
#   - $event :: the event as a hash ref, straight off the alerts table. Needs
#     src_ip and dest_ip, plus flow_start and timestamp as anything
#     Time::Piece::Guess can read. src_port and dest_port are used when both
#     are set and numeric.
#   - $buffer :: seconds to widen the window by at each end. Optional, 60 when
#     undef.
#
# Returns: a three element list -- the BPF filter as a string, and the start
# and end as Time::Piece objects.
#
# Dies rather than returning something unusable when the event cannot describe
# a flow: "event has no source/destination IP\n" without both addresses,
# "could not parse flow_start\n" or "could not parse timestamp\n" when a bound
# will not parse. The caller turns these into the error shown on the page.
#
#     my ( $filter, $start, $end ) = _virani_fetch_args( $event );
#     # 'host 192.0.2.10 and host 198.51.100.7 and ( port 44321 or port 443 )'
#     # start and end are the flow bounds, each 60 seconds wider
#
#     # no ports on the event, so the flow is matched by address alone
#     my ( $filter ) = _virani_fetch_args( { src_ip => '192.0.2.10', dest_ip => '198.51.100.7', ... } );
#     # 'host 192.0.2.10 and host 198.51.100.7'
sub _virani_fetch_args {
	my ( $event, $buffer ) = @_;
	$buffer = 60 unless defined $buffer;

	die "event has no source/destination IP\n"
		unless defined $event->{src_ip} && defined $event->{dest_ip};

	my $filter = 'host ' . $event->{src_ip} . ' and host ' . $event->{dest_ip};
	if (   defined $event->{src_port}
		&& defined $event->{dest_port}
		&& $event->{src_port}  =~ /^\d+$/
		&& $event->{dest_port} =~ /^\d+$/ )
	{
		$filter .= ' and ( port ' . $event->{src_port} . ' or port ' . $event->{dest_port} . ' )';
	}

	my $start = eval { Time::Piece::Guess->guess_to_object( $event->{flow_start}, 1 ) };
	die "could not parse flow_start\n" unless defined $start;
	$start = $start - $buffer;

	my $end = eval { Time::Piece::Guess->guess_to_object( $event->{timestamp}, 1 ) };
	die "could not parse timestamp\n" unless defined $end;
	$end = $end + $buffer;

	return ( $filter, $start, $end );
} ## end sub _virani_fetch_args

# minutes on each side of an event the "logs around this event" links span.
my $LOG_WINDOW = 60;

# The Logs dropdown on the event view: deep links into the Allani /logs page,
# each already filtered and windowed so it lands on the log lines that go with
# this alert.
#
# One link comes off the event's host, and two off each endpoint IP -- that
# address as the client of the interleaved http logs, and that address as a
# substring of the syslog messages. Both angles are offered for both endpoints
# because which one holds the answer is not known in advance: an attacker may
# appear as the client of a request or only as a string in something a daemon
# logged.
#
# The host link matches the FQDN and its first label together, since a syslog
# store may record either. That is skipped when the host is an IP, where a
# leading label means nothing.
#
# Links anchor on the event's own time (around) with a window either side, so
# the view opens on what surrounded the alert rather than everything since. An
# unparseable time falls back to /logs' default now-relative window rather than
# dropping the link.
#
# Args:
#
#   - $event :: the event as a hash ref, straight off the alerts table. host,
#     src_ip, and dest_ip are what links are built from; the timestamp comes
#     from timestamp, stop, or start, whichever the table has. undef is
#     allowed and yields no links.
#
# Returns: an array ref of { label, url } hash refs, in menu order: the host
# link first, then source and destination. label is what the menu shows, url is
# an absolute path with its query already built. A blank or repeated address is
# skipped, so a flow whose source and destination match yields one pair, and an
# event with neither a host nor an address yields [].
#
#     my $links = $self->_log_links($event);
#     # [ { label => 'syslog · host gate1.example.org / gate1',
#     #     url   => '/logs?source=syslog&host=gate1.example.org+gate1&around=...&window=60' },
#     #   { label => 'http · client (src) 192.0.2.10',
#     #     url   => '/logs?source=http_all&client_ip=192.0.2.10&around=...&window=60' },
#     #   { label => 'syslog · message (src) 192.0.2.10', url => '...' } ]
#
#     $self->_log_links(undef);
#     # []
sub _log_links {
	my ( $self, $event ) = @_;
	return [] unless $event;

	# Anchor on the event time when it parses (query() encodes the value; the
	# reader binds it). Fall back to no anchor -> /logs' default window.
	my $ts     = $event->{timestamp} // $event->{stop} // $event->{start};
	my $t      = ( defined $ts ) ? eval { Time::Piece::Guess->guess_to_object( $ts, 1 ) } : undef;
	my @anchor = ( defined $t )  ? ( around => $ts, window => $LOG_WINDOW )               : ();

	my @links;
	if ( defined $event->{host} && $event->{host} ne '' ) {
		my $host      = $event->{host};
		my @host_vals = ($host);
		# Also match the short hostname (the first label) so a syslog store that
		# records bare hostnames turns up alongside the FQDN; host accepts both as
		# whitespace-separated values. Skip when the host is an IP address, where a
		# leading label is meaningless.
		if ( $host =~ /\./ && $host !~ /:/ && $host !~ /^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/ ) {
			my ($short) = split( /\./, $host, 2 );
			push( @host_vals, $short ) if length $short && $short ne $host;
		}
		push(
			@links,
			{
				label => 'syslog · host ' . join( ' / ', @host_vals ),
				url   => $self->url_for('/logs')
					->query( source => 'syslog', host => join( ' ', @host_vals ), @anchor )
					->to_string,
			}
		);
	} ## end if ( defined $event->{host} && $event->{host...})

	# Each endpoint IP is worth chasing two ways: as the client IP of the
	# interleaved http (access+error) logs, and as a substring of the syslog
	# messages. Offer both for the source and the destination as separate menu
	# options, skipping a blank or duplicated address.
	my %seen;
	for my $endpoint ( [ src => $event->{src_ip} ], [ dest => $event->{dest_ip} ] ) {
		my ( $role, $ip ) = @$endpoint;
		next unless defined $ip && $ip ne '';
		next if $seen{$ip}++;
		push(
			@links,
			{
				label => "http · client ($role) " . $ip,
				url   => $self->url_for('/logs')->query( source => 'http_all', client_ip => $ip, @anchor )->to_string,
			},
			{
				label => "syslog · message ($role) " . $ip,
				url   => $self->url_for('/logs')->query( source => 'syslog', message => $ip, @anchor )->to_string,
			},
		);
	} ## end for my $endpoint ( [ src => $event->{src_ip...}])

	return \@links;
} ## end sub _log_links

=head2 body_zip

Serves the HTTP request or response body as a password protected zip. The
password is the conventional "infected" used for sharing potentially malicious
samples; it exists only to keep the file from being opened by mistake, so it is
intentionally not a secret.

=cut

sub body_zip {
	my $self = shift;

	my $table = $self->param('table');
	my $id    = $self->param('id');
	my $which = $self->param('which');

	$table = 'suricata' unless $table =~ /^(?:suricata|sagan|cape|baphomet)$/;

	unless ( $which =~ /^(?:request|response)$/ ) {
		return $self->render( text => 'invalid body', status => 400 );
	}
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( text => 'invalid id', status => 400 );
	}

	my ( $event, $error ) = $self->_load_event( $table, $id );
	if ( $error || !$event ) {
		return $self->render( text => 'event not found', status => 404 );
	}

	my $http = ref $event->{raw} eq 'HASH' ? $event->{raw}{http}                   : undef;
	my $b64  = ref $http eq 'HASH'         ? $http->{ 'http_' . $which . '_body' } : undef;
	unless ( defined $b64 && $b64 ne '' ) {
		return $self->render( text => 'no body available', status => 404 );
	}

	my $bytes = decode_base64($b64);

	my $member = $which . '-body-' . $id;
	my $zipdata;
	my $zip_error;
	eval { $zipdata = _zip_with_password( $member, $bytes ); };
	$zip_error = $@ if $@;

	if ( $zip_error || !defined $zipdata ) {
		return $self->render( text => 'failed to build zip', status => 500 );
	}

	$self->res->headers->content_type('application/zip');
	$self->res->headers->content_disposition( 'attachment; filename="' . $member . '.zip"' );
	return $self->render( data => $zipdata );
} ## end sub body_zip

=head2 cape_results

For a cape event, fetches the list of that task's detonation results from the
matching nergal C<< /results/<task_id> >> endpoint and returns a JSON summary:
the screenshot paths, whether the report/summary html exist, and the parsed
C<reports/lite.json> (for the malscore + signatures info card). The upstream
calls are blocking, so they run in a subprocess to keep the event loop
responsive, mirroring the Virani lookups in L<Lilith::Web::Controller::Api>.

=cut

sub cape_results {
	my $self = shift;

	my $id = $self->param('id');
	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'invalid id' }, status => 400 );
	}

	my ( $event, $error ) = $self->_load_event( 'cape', $id );
	if ( $error || !$event ) {
		return $self->render( json => { error => 'event not found' }, status => 404 );
	}

	my $endpoint = $self->cape_results_for( $event->{instance} );
	unless ($endpoint) {
		return $self->render(
			json => {
				error => 'no cape results endpoint configured for instance "' . ( $event->{instance} // '' ) . '"'
			},
			status => 400
		);
	}

	my $task = $event->{task};
	unless ( defined $task && $task =~ /^[0-9]+$/ ) {
		return $self->render( json => { error => 'event has no task id' }, status => 400 );
	}

	# built here so the subprocess closure captures only plain strings
	my $query
		= ( defined $endpoint->{apikey} && $endpoint->{apikey} ne '' )
		? '?apikey=' . uri_escape( $endpoint->{apikey} )
		: '';
	my $list_url = $endpoint->{url} . '/results/' . $task . $query;
	my $lite_url = $endpoint->{url} . '/results/' . $task . '/reports/lite.json' . $query;

	# link out to the box's CAPEv2 web UI for the full styled report, when one is
	# configured for this instance; added to the response after the fetch below
	my $web_report_url
		= ( defined $endpoint->{web_url} ) ? $endpoint->{web_url} . '/analysis/' . $task . '/' : undef;

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub {
			require LWP::UserAgent;
			my $ua = LWP::UserAgent->new(
				timeout  => 30,
				ssl_opts => { verify_hostname => 0, SSL_verify_mode => 0 },
			);

			my $list_res = $ua->get($list_url);
			die 'results list failed: ' . $list_res->status_line . "\n" unless $list_res->is_success;

			my $files = decode_json( $list_res->decoded_content );
			die "unparsable results list\n" unless ref $files eq 'ARRAY';

			my %have  = map       { $_ => 1 } @$files;
			my @shots = sort grep { m{^shots/[A-Za-z0-9_-]+\.jpg$} } @$files;

			# lite.json carries the signatures + malscore the cape row does not, so
			# pull it too when present; a failure there is non-fatal to the listing.
			my $lite;
			if ( $have{'reports/lite.json'} ) {
				my $lite_res = $ua->get($lite_url);
				if ( $lite_res->is_success ) {
					my $decoded = eval { decode_json( $lite_res->decoded_content ) };
					$lite = $decoded if ref $decoded eq 'HASH';
				}
			}

			return {
				shots             => \@shots,
				report_available  => ( $have{'reports/report.html'}         ? 1 : 0 ),
				summary_available => ( $have{'reports/summary-report.html'} ? 1 : 0 ),
				lite              => $lite,
			};
		},
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || !$result ) {
				chomp( my $why = ( defined $err ? $err : 'no data' ) );
				return $self->render( json => { error => 'cape results fetch failed: ' . $why }, status => 502 );
			}
			$result->{web_report_url} = $web_report_url if defined $web_report_url;
			return $self->render( json => $result );
		},
	);

	return;
} ## end sub cape_results

=head2 cape_result

Proxies a single detonation result file (a screenshot, or a report file) for a
cape event from the matching nergal C<< /results/<task_id>/<subpath> >> endpoint
and streams it back with the upstream content type. The subpath is restricted to
the same allowlist nergal enforces (shot jpgs and the fixed report files), so
this cannot be turned into an open proxy, and the results API key stays
server-side rather than being exposed in a browser URL.

=cut

sub cape_result {
	my $self = shift;

	my $id      = $self->param('id');
	my $subpath = $self->param('subpath');

	unless ( defined $id && $id =~ /^[0-9]+$/ ) {
		return $self->render( text => 'invalid id', status => 400 );
	}

	# mirror nergal's own allowlist: a shot jpg or one of the fixed report files
	unless (
		defined $subpath
		&& (   $subpath =~ m{^shots/[A-Za-z0-9_-]+\.jpg$}
			|| $subpath =~ m{^reports/(?:lite|report)\.json$}
			|| $subpath =~ m{^reports/(?:report|summary-report)\.html$} )
		)
	{
		return $self->render( text => 'invalid result path', status => 400 );
	}

	my ( $event, $error ) = $self->_load_event( 'cape', $id );
	if ( $error || !$event ) {
		return $self->render( text => 'event not found', status => 404 );
	}

	my $endpoint = $self->cape_results_for( $event->{instance} );
	unless ($endpoint) {
		return $self->render( text => 'no cape results endpoint configured', status => 400 );
	}

	my $task = $event->{task};
	unless ( defined $task && $task =~ /^[0-9]+$/ ) {
		return $self->render( text => 'event has no task id', status => 400 );
	}

	my $url = $endpoint->{url} . '/results/' . $task . '/' . $subpath;
	if ( defined $endpoint->{apikey} && $endpoint->{apikey} ne '' ) {
		$url .= '?apikey=' . uri_escape( $endpoint->{apikey} );
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub {
			require LWP::UserAgent;
			my $ua = LWP::UserAgent->new(
				timeout  => 30,
				ssl_opts => { verify_hostname => 0, SSL_verify_mode => 0 },
			);
			my $res = $ua->get($url);
			die 'upstream ' . $res->status_line . "\n" unless $res->is_success;
			return { content_type => scalar $res->header('Content-Type'), body => $res->content };
		},
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || !$result ) {
				chomp( my $why = ( defined $err ? $err : 'no data' ) );
				return $self->render( text => 'result fetch failed: ' . $why, status => 502 );
			}
			$self->res->headers->content_type( $result->{content_type} || 'application/octet-stream' );
			return $self->render( data => $result->{body} );
		},
	);

	return;
} ## end sub cape_result

# Fetch one event by table and id, with its raw EVE record decoded so the page
# can walk it. Every action on this controller that needs an event goes through
# here, so they all agree on what an event looks like and on how a failure to
# fetch one is reported.
#
# The search is run with a year of go_back_minutes. An id is unique on its own,
# so the time window is only in the way -- without this an event older than the
# default window would 404 rather than open.
#
# Decoding is best effort at two levels. raw is promoted from its JSON text to
# a hash ref, and for a baphomet row the EVE record it judged, nested under
# raw->{raw}, is promoted too when it arrived as a string -- that is what lets
# the protocol cards render a Baphomet verdict the same as the alert behind it.
# Either promotion silently leaves the value alone when it will not decode,
# since an event with unreadable raw is still worth showing.
#
# Args:
#
#   - $table :: which alert table to read, one of suricata, sagan, cape, or
#     baphomet. Passed through to Lilith::search, which rejects anything else.
#   - $id :: the row id, as it appears in the URL.
#
# Returns: a two element list, ( $event, $error ).
#
# $event is the row as a hash ref keyed by column name, with raw decoded, or
# undef when no row has that id. $error is undef on success, or the message
# search died with -- an unreachable database, an unknown table. Both undef
# means the query worked and matched nothing, which the caller shows as a
# missing event rather than an error.
#
#     my ( $event, $error ) = $self->_load_event( 'suricata', 4211 );
#     # $event->{signature} is 'ET SCAN Potential SSH Scan'
#     # $event->{raw} is the decoded EVE record as a hash ref
#
#     my ( $event, $error ) = $self->_load_event( 'suricata', 999999999 );
#     # ( undef, undef ) -- no such event, but nothing went wrong
sub _load_event {
	my ( $self, $table, $id ) = @_;

	my $event;
	my $error;

	eval {
		# Use a large go_back_minutes to bypass the time window when fetching
		# a specific event by ID.
		my $results = $self->lilith->search(
			table           => $table,
			id              => [$id],
			go_back_minutes => 525600,    # ~1 year
			limit           => 1,
		);
		$event = $results->[0];

		if ( $event && defined $event->{raw} ) {
			my $decoded;
			eval { $decoded = decode_json( $event->{raw} ) };
			if ( !$@ && ref $decoded ) {
				$event->{raw} = $decoded;
			}
		}

		# A Baphomet verdict that judged a Suricata line carries the original EVE
		# record under its own raw key. That nested raw is generally already a
		# hash, but may sometimes arrive as a JSON string; promote it to a hash
		# so the protocol cards can render it. Leave anything else untouched.
		if (   $table eq 'baphomet'
			&& $event
			&& ref $event->{raw} eq 'HASH'
			&& defined $event->{raw}{raw}
			&& !ref $event->{raw}{raw} )
		{
			my $inner;
			eval { $inner = decode_json( $event->{raw}{raw} ) };
			if ( !$@ && ref $inner eq 'HASH' ) {
				$event->{raw}{raw} = $inner;
			}
		} ## end if ( $table eq 'baphomet' && $event && ref...)
	};
	$error = $@ if $@;

	return ( $event, $error );
} ## end sub _load_event

# Wrap a request or response body in a password protected zip before it is
# served, so a browser, a mail gateway, or an antivirus scanner does not open or
# quarantine what may be a live sample on the way past.
#
# The password is the conventional "infected". It is not a secret and is not
# meant to be one -- it only stops the archive being unpacked by accident, which
# is why it is written here in the clear rather than configured.
#
# Done by shelling out to zip rather than with a Perl module because the
# encryption formats the archive modules produce are not the one every
# desktop unzip tool reads without complaint. Everything happens under a
# File::Temp directory that is removed when it goes out of scope.
#
# Plain function, not a method.
#
# Args:
#
#   - $member :: the name the data gets inside the archive, e.g.
#     'event-4211-response.bin'. Also the temp file name, so it must be a bare
#     filename rather than a path.
#   - $bytes :: the body itself, as raw bytes. Written and read back binary, so
#     it survives whatever encoding the body was in.
#
# Returns: the zip archive as a string of raw bytes, ready to be handed
# straight to render( data => ... ).
#
# Dies on any failure rather than returning a partial archive: "zip command
# failed\n" when zip is missing or exits non-zero, or the errno message when
# the temp files cannot be written or read back.
#
#     my $zipdata = _zip_with_password( 'event-4211-response.bin', $body );
#     $self->render( data => $zipdata, format => 'zip' );
sub _zip_with_password {
	my ( $member, $bytes ) = @_;

	my $dir     = File::Temp->newdir;
	my $infile  = $dir . '/' . $member;
	my $zipfile = $dir . '/' . $member . '.zip';

	open( my $ifh, '>:raw', $infile ) or die "cannot write temp body: $!";
	print $ifh $bytes;
	close($ifh) or die "cannot close temp body: $!";

	# -j junks the temp path so only the member name is stored, -q keeps it
	# quiet. "infected" is a conventional, non-secret password.
	my $rc = system( 'zip', '-j', '-q', '-P', 'infected', $zipfile, $infile );
	die "zip command failed\n" if ( $rc != 0 || !-e $zipfile );

	open( my $zfh, '<:raw', $zipfile ) or die "cannot read zip: $!";
	local $/;
	my $zipdata = <$zfh>;
	close($zfh);

	return $zipdata;
} ## end sub _zip_with_password

1;
