package Lilith::Web::Controller::Api;

use Mojo::Base 'Mojolicious::Controller';
use Net::DNS              ();
use IO::Select            ();
use Mojo::IOLoop          ();
use Lilith::Shodan        ();
use Mojo::JSON            qw(decode_json);
use Time::Piece           ();
use Time::HiRes           ();
use Time::Local           ();
use IO::Socket::IP        ();
use IO::Socket::SSL       qw(SSL_VERIFY_PEER SSL_VERIFY_NONE);
use Net::SSLeay           ();
use Mozilla::CA           ();
use Mail::SPF             ();
use Mail::DMARC::PurePerl ();
use Mail::DMARC::Policy   ();
use Mail::DKIM::PublicKey ();

=head2 virani_sets

Returns the PCAP sets available on a configured remote Virani instance as JSON
C<< { sets => [ ... ], default_set => '...' } >>. The remote lookup runs in a
subprocess so it does not block the event loop.

=cut

sub virani_sets {
	my $self   = shift;
	my $remote = $self->param('remote');

	unless ( $self->virani_enabled && defined $remote && $self->virani_remotes->{$remote} ) {
		return $self->render( json => { error => 'unknown virani instance' }, status => 400 );
	}
	my $client = $self->virani_client_for($remote);
	unless ($client) {
		return $self->render( json => { error => 'virani client unavailable' }, status => 400 );
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return $client->get_sets; },    # raw JSON, dies on failure
		sub {
			my ( $subprocess, $err, $raw ) = @_;
			if ($err) {
				chomp( my $why = $err );
				return $self->render( json => { error => 'set lookup failed: ' . $why }, status => 502 );
			}
			my $data = eval { decode_json($raw) };
			if ( $@ || ref $data ne 'HASH' ) {
				return $self->render( json => { error => 'unparsable set list' }, status => 502 );
			}
			my @sets = ( ref $data->{sets} eq 'HASH' ) ? ( sort keys %{ $data->{sets} } ) : ();
			$self->render( json => { sets => \@sets, default_set => $data->{default_set} } );
		},
	);
	return;
} ## end sub virani_sets

=head2 virani_pcap

Standalone Virani PCAP search: fetches a capture for an arbitrary BPF filter and
time range (epoch seconds) from a configured remote and streams it back. Gated
by virani_search_enable, since it exposes arbitrary captures.

=cut

sub virani_pcap {
	my $self = shift;

	unless ( $self->virani_search_enable ) {
		return $self->render( text => 'virani search is disabled', status => 404 );
	}

	my $remote = $self->param('remote');
	my $cfg    = ( defined $remote ) ? $self->virani_remotes->{$remote} : undef;
	my $client = $self->virani_client_for($remote);
	unless ( $cfg && $client ) {
		return $self->render( text => 'unknown or unusable virani instance', status => 400 );
	}

	my $filter = $self->param('filter');
	unless ( defined $filter && $filter =~ /\S/ ) {
		return $self->render( text => 'a filter is required', status => 400 );
	}
	if ( length($filter) > 1024 ) {
		return $self->render( text => 'filter too long', status => 400 );
	}

	my $set = $self->param('set');
	if ( defined $set && $set ne '' ) {
		return $self->render( text => 'invalid set', status => 400 ) unless $set =~ /^[A-Za-z0-9._-]+$/;
	} else {
		$set = $cfg->{set};
	}

	my $s = $self->param('start');
	my $e = $self->param('end');
	unless ( defined $s && $s =~ /^[0-9]+$/ && defined $e && $e =~ /^[0-9]+$/ ) {
		return $self->render( text => 'start and end must be epoch seconds', status => 400 );
	}
	if ( $s >= $e ) {
		return $self->render( text => 'start must be before end', status => 400 );
	}

	return $self->virani_stream_pcap(
		sub {
			my $file = shift;
			$client->fetch(
				start  => Time::Piece->new( $s + 0 ),
				end    => Time::Piece->new( $e + 0 ),
				filter => $filter,
				file   => $file,
				( ( defined $set && $set ne '' ) ? ( set  => $set )         : () ),
				( defined $cfg->{type}           ? ( type => $cfg->{type} ) : () ),
			);
		},
		'virani-' . $s . '-' . $e . '.pcap',
	);
} ## end sub virani_pcap

=head2 virani_cached_list

Lists the most recent (up to 50) cached searches on a remote Virani instance,
enriched with the found/success counts from each one's metadata. Gated by
virani_search_enable. Runs in a subprocess.

=cut

sub virani_cached_list {
	my $self = shift;

	unless ( $self->virani_search_enable ) {
		return $self->render( json => { error => 'virani search is disabled' }, status => 404 );
	}
	my $remote = $self->param('remote');
	my $client = ( defined $remote && $self->virani_remotes->{$remote} ) ? $self->virani_client_for($remote) : undef;
	unless ($client) {
		return $self->render( json => { error => 'unknown virani instance' }, status => 400 );
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub {
			my $list = decode_json( $client->list_cached );
			return [] unless ref $list eq 'ARRAY';

			# newest first, capped at 50
			my @sorted = sort { ( $b->{start_s} // 0 ) <=> ( $a->{start_s} // 0 ) } @{$list};
			@sorted = @sorted[ 0 .. 49 ] if @sorted > 50;

			# the list lacks the found/success counts; pull them from metadata
			for my $item (@sorted) {
				my $meta = eval { decode_json( $client->fetch_cached( id => $item->{id}, meta_only => 1 ) ) };
				if ($@) {
					warn( 'Lilith: fetching cached metadata for "' . $item->{id} . '" failed: ' . $@ );
				} elsif ( ref $meta eq 'HASH' ) {
					# The metadata is authoritative; older list_cached versions do
					# not include the filter/size, so take them from here too.
					$item->{found}      = $meta->{pcap_count};
					$item->{success}    = $meta->{success_count};
					$item->{filter}     = $meta->{filter}     if defined $meta->{filter};
					$item->{final_size} = $meta->{final_size} if defined $meta->{final_size};
				}
			} ## end for my $item (@sorted)
			return \@sorted;
		},
		sub {
			my ( $subprocess, $err, $list ) = @_;
			if ($err) {
				chomp( my $why = $err );
				return $self->render( json => { error => 'cached list lookup failed: ' . $why }, status => 502 );
			}
			if ( ref $list ne 'ARRAY' ) {
				return $self->render( json => { error => 'cached list lookup returned no data' }, status => 502 );
			}
			$self->render( json => { cached => $list } );
		},
	);
	return;
} ## end sub virani_cached_list

=head2 virani_cached_pcap

Streams a cached PCAP by its cache ID from a remote Virani instance. Gated by
virani_search_enable.

=cut

sub virani_cached_pcap {
	my $self = shift;

	unless ( $self->virani_search_enable ) {
		return $self->render( text => 'virani search is disabled', status => 404 );
	}
	my $remote = $self->param('remote');
	my $id     = $self->param('id');
	my $client = ( defined $remote && $self->virani_remotes->{$remote} ) ? $self->virani_client_for($remote) : undef;
	unless ($client) {
		return $self->render( text => 'unknown virani instance', status => 400 );
	}
	unless ( defined $id && $id =~ /^[A-Za-z0-9._:-]+$/ ) {
		return $self->render( text => 'invalid cache id', status => 400 );
	}

	return $self->virani_stream_pcap(
		sub { my $file = shift; $client->fetch_cached( id => $id, file => $file ); },
		'virani-cached-' . $id . '.pcap',
	);
} ## end sub virani_cached_pcap

=head2 virani_cached_meta

Downloads the metadata JSON for a cached search by its cache ID. Gated by
virani_search_enable. Runs in a subprocess.

=cut

sub virani_cached_meta {
	my $self = shift;

	unless ( $self->virani_search_enable ) {
		return $self->render( text => 'virani search is disabled', status => 404 );
	}
	my $remote = $self->param('remote');
	my $id     = $self->param('id');
	my $client = ( defined $remote && $self->virani_remotes->{$remote} ) ? $self->virani_client_for($remote) : undef;
	unless ($client) {
		return $self->render( text => 'unknown virani instance', status => 400 );
	}
	unless ( defined $id && $id =~ /^[A-Za-z0-9._:-]+$/ ) {
		return $self->render( text => 'invalid cache id', status => 400 );
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return $client->fetch_cached( id => $id, meta_only => 1 ); },    # raw JSON, dies on failure
		sub {
			my ( $subprocess, $err, $raw ) = @_;
			if ( $err || !defined $raw ) {
				chomp( my $why = ( $err // 'no metadata' ) );
				return $self->render( text => 'metadata fetch failed: ' . $why, status => 502 );
			}
			$self->res->headers->content_type('application/json');
			$self->res->headers->content_disposition( 'attachment; filename="virani-cached-' . $id . '.json"' );
			$self->render( data => $raw );
		},
	);
	return;
} ## end sub virani_cached_meta

# Run an external command and hand back what it wrote to stdout, giving up
# after a deadline. Used for the lookups that have no usable Perl equivalent --
# whois, mostly -- where a slow or wedged registrar must not hold a worker.
#
# The command is passed as a list, so no shell sees it and nothing in a domain
# or an address can turn into shell syntax.
#
# The timeout is enforced with IO::Select rather than alarm()/SIGALRM, which is
# the obvious approach and the wrong one here. Under Mojo's EV reactor a
# SIGALRM does interrupt the read, but the child keeps running, and the
# close()/waitpid that follows then blocks forever waiting on it. So the
# deadline is checked around the read instead, and the child is killed when it
# passes, leaving nothing for close() to wait on.
#
# Plain function, not a method.
#
# Args:
#
#   - $timeout :: seconds to wait for output before giving up and killing the
#     child. Counted from the call, not reset per read, so it caps the whole
#     command rather than each chunk.
#   - @cmd :: the command and its arguments as separate elements, e.g.
#     ( 'whois', 'example.org' ). The first element is the program to run.
#
# Returns: whatever the command wrote to stdout, as a single string. stderr is
# not captured and the exit status is not checked.
#
# Never dies and never returns undef. A command that cannot be started, that
# fails, or that runs past the deadline gives the empty string, or whatever it
# managed to write before being killed -- callers treat a lookup that produced
# nothing as a lookup with no answer, which is the same thing to a reader.
#
#     my $out = _run_capture( 10, 'whois', 'example.org' );
#     # the whois response as text
#
#     _run_capture( 10, 'whois', 'nowhere.invalid' );
#     # '' -- no answer, no exception
sub _run_capture {
	my ( $timeout, @cmd ) = @_;

	my $pid = open( my $fh, '-|', @cmd );
	return '' unless $pid;

	my $out       = '';
	my $timed_out = 0;
	my $sel       = IO::Select->new($fh);
	my $deadline  = time() + $timeout;
	while (1) {
		my $remaining = $deadline - time();
		if ( $remaining <= 0 ) { $timed_out = 1; last; }
		if ( $sel->can_read($remaining) ) {
			my $n = sysread( $fh, my $chunk, 65536 );
			last if !defined $n || $n == 0;    # read error or EOF
			$out .= $chunk;
		} else {
			$timed_out = 1;
			last;
		}
	} ## end while (1)

	# Kill a still-running child so close()'s waitpid cannot hang on it.
	if ($timed_out) {
		kill( 'TERM', $pid );
		kill( 'KILL', $pid );
	}
	close($fh);

	return $out;
} ## end sub _run_capture

=head2 ipinfo

Reverse DNS + whois + GeoIP + optional Shodan for an IP, rendered as JSON. The
blocking lookups run in a subprocess so the web server's event loop stays
responsive; the Shodan half is served from the shodan_cache table when a fresh
entry is held, and cached back when it is not.

=cut

sub ipinfo {
	my $self = shift;
	my $ip   = $self->param('ip');

	# Strict validation — only digits, hex letters, dots, colons
	unless ( defined $ip && $ip =~ /^[0-9a-fA-F:.]+$/ ) {
		return $self->render( json => { error => 'Invalid IP' }, status => 400 );
	}

	# Read here rather than in the gather: the cache is a database round trip,
	# and the subprocess is forked from this process, where a DBI handle does not
	# survive being shared. Everything else in the modal is a live lookup either
	# way, so this only decides whether the Shodan section costs an API call.
	my $cached_shodan = $self->_shodan_cache_get($ip);

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return $self->_ipinfo_gather( $ip, $cached_shodan ); },
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || ref $result ne 'HASH' ) {
				return $self->render( json => { ip => $ip, error => 'lookup failed' }, status => 500 );
			}

			# Shodan's own response rides back from the subprocess only so it can
			# be cached here in the parent; the browser is sent the normalized
			# form and has no use for it. Absent when the lookup was cached,
			# skipped, failed, or never made.
			my $raw = delete $result->{shodan_raw};
			$self->_shodan_cache_put( $ip, $result->{shodan}, $raw ) if $raw;

			$self->render( json => $result );
		},
	);
	return;
} ## end sub ipinfo

# The cached Shodan response for an address, or undef when there is not a usable
# one -- caching off, no entry, a stale entry, or an entry from a shallower tier
# than the one now configured.
#
# Wraps Lilith::shodan_cache_get with the two things the controller owns: the
# config that decides whether the cache is consulted at all, and the promise
# that a cache problem never costs the modal. A database that cannot be reached,
# or one still on a schema without the table, degrades to doing the lookup live
# -- logged, since either is a misconfiguration worth seeing, but not fatal to a
# request whose other three sections are fine.
#
# Args:
#
#   - $ip :: the address, already validated by the caller.
#
# Returns: the decoded response as a hash ref, or undef. An empty hash ref is a
# hit, not a miss: it is what an address Shodan has never crawled is stored as,
# and re-fetching it would only get the same nothing back.
#
#     my $raw = $self->_shodan_cache_get('192.0.2.10');
sub _shodan_cache_get {
	my ( $self, $ip ) = @_;

	return undef unless $self->shodan_enable;
	my $ttl = $self->shodan_cache_ttl;
	return undef unless $ttl > 0;

	my $raw = eval { $self->lilith->shodan_cache_get( $ip, $self->shodan_source, $ttl ) };
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		$self->app->log->warn( 'shodan cache read failed, looking up live: ' . $why );
		return undef;
	}

	return $raw;
} ## end sub _shodan_cache_get

# Store a fresh Shodan response for an address. The counterpart to
# _shodan_cache_get, with the same config gate and the same promise that a cache
# problem costs nothing but the caching.
#
# Args:
#
#   - $ip :: the address, already validated by the caller.
#   - $info :: the normalized result, for the columns worth querying.
#   - $raw :: Shodan's response as it arrived, which is what is stored.
#
# Returns: nothing meaningful. Called for its effect on the table.
#
#     $self->_shodan_cache_put( '192.0.2.10', $result->{shodan}, $raw );
sub _shodan_cache_put {
	my ( $self, $ip, $info, $raw ) = @_;

	return unless $self->shodan_enable;
	my $ttl = $self->shodan_cache_ttl;
	return unless $ttl > 0;

	eval {
		$self->lilith->shodan_cache_put(
			ip     => $ip,
			source => $self->shodan_source,
			raw    => $raw,
			info   => $info,
			ttl    => $ttl,
		);
	};
	if ($@) {
		( my $why = $@ ) =~ s/\s+\z//;
		$self->app->log->warn( 'shodan cache write failed: ' . $why );
	}

	return;
} ## end sub _shodan_cache_put

# Everything the IP info modal shows, gathered in one go: reverse DNS, whois,
# whatever the configured GeoIP databases know, and -- when enable_shodan is set
# -- Shodan's view of what the address is running.
#
# All of them block, which is why this is only ever called inside a
# Mojo::IOLoop->subprocess -- run on the worker itself a slow resolver or
# registrar would stall every other request. Nothing here dies: each lookup
# reports its own failure in its own field, so one unreachable service still
# leaves the rest on the page.
#
# Args:
#
#   - $ip :: the address to look up, v4 or v6. The caller has already checked
#     it against /^[0-9a-fA-F:.]+$/, so it is safe to hand to a resolver and to
#     an external command.
#   - $cached_shodan :: a Shodan response the caller already held, as a hash
#     ref, normalized here in place of asking Shodan again. undef to do the
#     lookup. Only read when the feature is on.
#
# Returns: a hash ref, rendered to the browser as-is:
#
#     {
#       ip         => '192.0.2.10',
#       ptr_name   => '10.2.0.192.in-addr.arpa',  # the name queried, '' if not built
#       rdns       => 'gate1.example.org',        # comma joined for several PTRs
#       rdns_error => '',                         # resolver error, '' on success
#       whois      => "...",                      # the whois response as text
#       geo        => { 'country' => 'US', 'city' => 'Austin', ... },
#       geo_error  => '',                         # database error, '' on success
#       shodan     => { ... },                    # see Lilith::Shodan::gather; {} when off
#       shodan_error => '',                       # API error, '' on success
#       shodan_raw => { ... },                    # only after a live lookup
#     }
#
# shodan_raw is not for the browser. It is Shodan's own response, carried back
# across the subprocess boundary so the parent can cache it, and deleted there
# before the result is rendered. It is absent whenever there is nothing new
# worth caching -- a cached, skipped, failed, or never-made lookup.
#
# Every key is always present. A lookup that found nothing gives an empty
# string or an empty hash rather than undef, so the template never has to
# distinguish "not asked" from "no answer".
#
#     my $info = $self->_ipinfo_gather('192.0.2.10');
#     # $info->{rdns} is 'gate1.example.org'
#     # $info->{geo}{country} is 'US' when a GeoIP database is configured
sub _ipinfo_gather {
	my ( $self, $ip, $cached_shodan ) = @_;

	# Reverse DNS via Net::DNS PTR lookup
	my $rdns       = '';
	my $rdns_error = '';
	my $ptr_name   = '';
	eval {
		my $resolver = Net::DNS::Resolver->new;
		if ( $ip =~ /:/ ) {
			# IPv6 — expand, strip colons, reverse nibbles, append ip6.arpa
			require Net::IP;
			my $netip = Net::IP->new($ip);
			if ($netip) {
				my $expanded = $netip->ip;
				$expanded =~ s/://g;
				$ptr_name = join( '.', reverse split //, $expanded ) . '.ip6.arpa';
			}
		} else {
			# IPv4 — reverse octets, append in-addr.arpa
			$ptr_name = join( '.', reverse split /\./, $ip ) . '.in-addr.arpa';
		}
		if ($ptr_name) {
			my $reply = $resolver->query( $ptr_name, 'PTR' );
			if ($reply) {
				my @ptrs = map { $_->ptrdname } grep { $_->type eq 'PTR' } $reply->answer;
				$rdns = join( ', ', @ptrs ) if @ptrs;
			} else {
				$rdns_error = $resolver->errorstring;
			}
		}
	};
	$rdns_error = $@ if $@;

	# WHOIS — list-form (no shell) with a hard timeout that also kills the child.
	my $whois = _run_capture( 10, 'whois', $ip );

	# GeoIP / MMDB — query every configured database and merge the flattened
	# records into a single set of dotted key => value pairs.
	my %geo;
	my $geo_error = '';
	for my $db ( @{ $self->geoip_mmdbs } ) {
		my $record = eval { $db->record_for_address($ip) };
		if ($@) {
			( $geo_error = $@ ) =~ s/\s+\z//;
			next;
		}
		next unless ref $record eq 'HASH';
		_flatten_geo( $record, '', \%geo );
	}

	# Shodan, only when it has been turned on -- it is the one part of this that
	# tells an outside party which addresses are being looked at. A response the
	# caller had cached is normalized here rather than fetched, so a cache hit
	# and a fresh lookup produce the same thing by the same code.
	my $shodan       = {};
	my $shodan_error = '';
	my $shodan_raw;
	if ( $self->shodan_enable ) {
		if ( ref $cached_shodan eq 'HASH' ) {
			$shodan = Lilith::Shodan::normalize( $cached_shodan, $self->shodan_source, $ip );
			$shodan->{cached} = 1;
		} else {
			( $shodan, $shodan_error, $shodan_raw )
				= Lilith::Shodan::gather( $ip, $self->shodan_api_key, $self->shodan_source );
		}
	}

	my %info = (
		ip           => $ip,
		ptr_name     => $ptr_name,
		rdns         => $rdns,
		rdns_error   => $rdns_error,
		whois        => $whois,
		geo          => \%geo,
		geo_error    => $geo_error,
		shodan       => $shodan,
		shodan_error => $shodan_error,
	);
	$info{shodan_raw} = $shodan_raw if ref $shodan_raw eq 'HASH';

	return \%info;
} ## end sub _ipinfo_gather

# Flatten a GeoIP record into plain dotted key => value pairs, so the modal can
# list whatever a database happens to carry without knowing its shape. MMDB
# records nest differently between the City, Country, and ASN databases, and
# between vendors, so anything that walked a fixed path would only work for the
# databases it was written against.
#
# Localized names collapse onto their parent: a record's {country}{names}{en}
# becomes simply country, since a modal listing country.names.en beside
# country.names.de beside country.names.ja is noise. English is preferred, and
# whichever language sorts first is used when there is no English.
#
# Plain function, not a method. Fills a hash the caller owns rather than
# returning one, so several databases can be merged into a single set of pairs.
#
# Args:
#
#   - $data :: the value to flatten. A hash ref, an array ref, or a scalar --
#     it recurses into the first two and stores the third. The top level call
#     passes the whole record as returned by record_for_address.
#   - $prefix :: the dotted key reached so far, '' at the top level. Array
#     elements get their index appended, so a list becomes prefix.0, prefix.1.
#   - $out :: the hash ref to fill. Written into, not replaced, so calling this
#     for each database merges them.
#
# Returns: nothing. The result is in $out.
#
#     my %geo;
#     _flatten_geo( $db->record_for_address('192.0.2.10'), '', \%geo );
#     # %geo is (
#     #   'country'            => 'United States',
#     #   'country.iso_code'   => 'US',
#     #   'city'               => 'Austin',
#     #   'location.latitude'  => 30.2672,
#     # )
sub _flatten_geo {
	my ( $data, $prefix, $out ) = @_;

	if ( ref $data eq 'HASH' ) {
		for my $key ( sort keys %{$data} ) {
			my $value  = $data->{$key};
			my $dotted = ( $prefix eq '' ) ? $key : $prefix . '.' . $key;
			if ( $key eq 'names' && ref $value eq 'HASH' && $prefix ne '' ) {
				my $name = $value->{en} // ( sort values %{$value} )[0];
				$out->{$prefix} = $name if defined $name;
			} else {
				_flatten_geo( $value, $dotted, $out );
			}
		} ## end for my $key ( sort keys %{$data} )
	} elsif ( ref $data eq 'ARRAY' ) {
		for my $i ( 0 .. $#{$data} ) {
			_flatten_geo( $data->[$i], $prefix . '.' . $i, $out );
		}
	} elsif ( defined $data ) {
		# blessed scalars (e.g. JSON booleans) are stringified
		$out->{$prefix} = ref $data ? "$data" : $data;
	}

	return;
} ## end sub _flatten_geo

# Render the answers of one record type from a DNS reply as strings a person
# can read, since Net::DNS returns objects whose interesting fields differ per
# type. Each type is formatted the way it is conventionally written, so an MX
# reads "10 mx1.example.org" and an SOA carries its timers.
#
# A type with no special case falls through to the record's address, which
# covers A and AAAA. That means an unhandled type either renders sensibly or
# dies rather than silently rendering a stringified object.
#
# Plain function, not a method.
#
# Args:
#
#   - $reply :: the Net::DNS::Packet a query returned. Only its answer section
#     is read.
#   - $type :: which record type to pull out, as the string Net::DNS uses --
#     'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'PTR', 'SOA', 'CAA', or 'SRV'.
#     Records of other types in the same reply are skipped.
#
# Returns: an array ref of strings, in the order the reply listed them. Empty
# when the reply carries no answer of that type, which is the normal result for
# a domain that simply has no such record.
#
#     _dns_records( $reply, 'MX' );
#     # [ '10 mx1.example.org', '20 mx2.example.org' ]
#
#     _dns_records( $reply, 'SOA' );
#     # [ 'ns1.example.org hostmaster.example.org serial=2026080601 refresh=7200 ...' ]
sub _dns_records {
	my ( $reply, $type ) = @_;
	my @recs;
	for my $rr ( $reply->answer ) {
		next unless $rr->type eq $type;
		if    ( $type eq 'MX' )    { push @recs, $rr->preference . ' ' . $rr->exchange; }
		elsif ( $type eq 'TXT' )   { push @recs, join( '', $rr->txtdata ); }
		elsif ( $type eq 'NS' )    { push @recs, $rr->nsdname; }
		elsif ( $type eq 'CNAME' ) { push @recs, $rr->cname; }
		elsif ( $type eq 'PTR' )   { push @recs, $rr->ptrdname; }
		elsif ( $type eq 'SOA' ) {
			push @recs,
				  $rr->mname . ' '
				. $rr->rname
				. ' serial='
				. $rr->serial
				. ' refresh='
				. $rr->refresh
				. ' retry='
				. $rr->retry
				. ' expire='
				. $rr->expire . ' min='
				. $rr->minimum;
		} elsif ( $type eq 'CAA' ) {
			push @recs, $rr->flags . ' ' . $rr->tag . ' ' . $rr->value;
		} elsif ( $type eq 'SRV' ) {
			push @recs, $rr->priority . ' ' . $rr->weight . ' ' . $rr->port . ' ' . $rr->target;
		} else {
			push @recs, $rr->address;
		}
	} ## end for my $rr ( $reply->answer )
	return \@recs;
} ## end sub _dns_records

# Reduce a hostname to the domain actually worth asking whois about. A registry
# holds a record for the registrable domain, not for every name under it, so
# querying www.example.co.uk returns nothing useful while example.co.uk returns
# the registration.
#
# Where that boundary falls cannot be worked out from the number of labels:
# example.co.uk is registrable but example.com.au and example.com are too, at
# different depths. Mozilla::PublicSuffix knows the real list and is used when
# installed. Without it a short list of common two level suffixes is the
# fallback -- wrong for the long tail, right for most of what is met in
# practice, and better than not offering the lookup at all.
#
# Plain function, not a method.
#
# Args:
#
#   - $domain :: the hostname to reduce, e.g. 'www.example.co.uk'. Something
#     already registrable, or with two labels or fewer, comes back untouched.
#
# Returns: the registrable domain as a string. Never undef -- a name that
# cannot be reduced is returned as it came in, so the caller always has
# something to query.
#
#     _whois_domain('www.example.com');       # 'example.com'
#     _whois_domain('mail.www.example.co.uk') # 'example.co.uk'
#     _whois_domain('example.org');           # 'example.org'
sub _whois_domain {
	my ($domain) = @_;
	my @labels   = split /\./, $domain;
	return $domain unless @labels > 2;

	my $found = 0;
	my $whois_domain;
	eval {
		require Mozilla::PublicSuffix;
		my $suffix = Mozilla::PublicSuffix::public_suffix($domain);
		if ( defined $suffix && length $suffix ) {
			my $suffix_count = scalar( split /\./, $suffix );
			$whois_domain = join( '.', @labels[ -( $suffix_count + 1 ) .. -1 ] ) if @labels > $suffix_count;
			$found        = 1;
		}
	};
	return $whois_domain // $domain if $found;

	# Fallback heuristic: known two-level TLDs get 3 labels, rest get 2.
	my $two_level = join( '.', @labels[ -2 .. -1 ] );
	my %tld2      = map { $_ => 1 } qw(
		co.uk co.au co.nz co.za co.in co.jp co.kr co.id co.il
		com.au com.br com.cn com.mx com.ar com.sg com.hk com.tw
		org.uk net.uk me.uk org.au net.au
	);
	if ( $tld2{$two_level} && @labels > 3 ) {
		return join( '.', @labels[ -3 .. -1 ] );
	} elsif ( !$tld2{$two_level} ) {
		return join( '.', @labels[ -2 .. -1 ] );
	}
	return $domain;
} ## end sub _whois_domain

=head2 domaininfo

DNS + whois + optional dnstracer for a domain, rendered as JSON. Serves from the
optional cache when fresh; otherwise the blocking gather runs in a subprocess
(keeping the event loop responsive) and the result is cached back in the parent.

=cut

sub domaininfo {
	my $self   = shift;
	my $domain = $self->param('domain');

	# Basic domain validation
	unless ( defined $domain && $domain =~ /^[A-Za-z0-9._-]+$/ ) {
		return $self->render( json => { error => 'Invalid domain' }, status => 400 );
	}

	# Serve from cache when enabled and the entry is still fresh.
	my $cache_on = $self->domaininfo_cache_enabled;
	my $ttl      = $self->domaininfo_cache_ttl;
	if ( $cache_on && $ttl > 0 ) {
		my $entry = $self->domaininfo_cache->{$domain};
		if ( $entry && ( time() - $entry->{time} ) < $ttl ) {
			return $self->render( json => { %{ $entry->{data} }, cached => 1 } );
		}
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return $self->_domaininfo_gather($domain); },
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || ref $result ne 'HASH' ) {
				return $self->render( json => { domain => $domain, error => 'lookup failed' }, status => 500 );
			}
			if ( $cache_on && $ttl > 0 ) {
				my $cache = $self->domaininfo_cache;
				my $now   = time();
				for my $k ( keys %{$cache} ) {    # prune expired entries opportunistically
					delete $cache->{$k} if ( $now - $cache->{$k}{time} ) >= $ttl;
				}
				$cache->{$domain} = { time => $now, data => $result };
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub domaininfo

# Everything the domain info panel shows, gathered in one pass: ten kinds of DNS
# record, whois, and optionally a dnstracer delegation walk.
#
# Done all at once rather than in sequence. The DNS queries go out with bgsend
# and the external commands are opened as pipes, then a single IO::Select loop
# waits on all of them together, so the whole gather costs about as long as its
# slowest part instead of the sum. With ten record types against a slow resolver
# that is the difference between a panel that opens and one that does not.
#
# Everything carries its own deadline, and anything still outstanding when its
# deadline passes is abandoned with whatever it had -- a domain with no CAA
# record must not hold up the answers that did arrive. Nothing here dies.
#
# Blocking throughout, so it is only ever called inside a
# Mojo::IOLoop->subprocess.
#
# Args:
#
#   - $domain :: the domain to look up. The caller has already checked it
#     against /^[A-Za-z0-9._-]+$/, so it is safe to hand to a resolver and to
#     an external command.
#
# Returns: a hash ref, rendered to the browser as-is:
#
#     {
#       domain          => 'www.example.org',
#       whois_domain    => 'example.org',   # what was actually queried
#       dns             => {                # only types that answered
#         A   => [ '192.0.2.10' ],
#         MX  => [ '10 mx1.example.org' ],
#         TXT => [ 'v=spf1 include:_spf.example.org -all' ],
#       },
#       dns_error       => '',              # resolver error, '' on success
#       whois           => "...",           # the whois response as text
#       dnstracer       => '',              # empty unless dnstracer_enable
#       dnstracer_error => '',
#       cached          => 0,               # set by the caller on a cache hit
#     }
#
# Every key is always present. A record type with no answer is simply absent
# from dns rather than an empty list, so the template renders only what exists.
#
#     my $info = $self->_domaininfo_gather('www.example.org');
#     # $info->{dns}{A} is [ '192.0.2.10' ]
#     # $info->{whois_domain} is 'example.org' -- the registrable domain
sub _domaininfo_gather {
	my ( $self, $domain ) = @_;

	my $whois_domain = _whois_domain($domain);

	# Launch whois and (optionally) dnstracer as external processes, and fire the
	# DNS queries, then read all of them together in one select loop so the work
	# runs concurrently instead of one after another. Each source honours its own
	# deadline; any subprocess still running at its deadline is killed.
	my $start = time();
	my %pending;    # fileno => source descriptor

	if ( my $pid = open( my $fh, '-|', 'whois', $whois_domain ) ) {
		$pending{ fileno($fh) } = { kind => 'whois', fh => $fh, pid => $pid, deadline => $start + 10, buf => '' };
	}
	if ( $self->dnstracer_enable ) {
		my @dt_flags = @{ $self->dnstracer_flags };
		if ( my $pid = open( my $fh, '-|', 'dnstracer', @dt_flags, $domain ) ) {
			$pending{ fileno($fh) }
				= { kind => 'dnstracer', fh => $fh, pid => $pid, deadline => $start + 30, buf => '' };
		}
	}

	my %dns;
	my $dns_error = '';
	my $resolver;
	eval {
		$resolver = Net::DNS::Resolver->new;
		for my $type (qw(A AAAA CNAME MX NS TXT SOA CAA SRV PTR)) {
			my $sock = $resolver->bgsend( $domain, $type );
			$pending{ fileno($sock) }
				= { kind => 'dns', sock => $sock, type => $type, deadline => $start + $self->dns_bg_timeout }
				if $sock;
		}
	};
	$dns_error = $@ if $@;

	my $whois         = '';
	my $dnstracer_out = '';
	my $sel           = IO::Select->new;
	$sel->add( $_->{sock} // $_->{fh} ) for values %pending;

	while (%pending) {
		my $next;
		for my $p ( values %pending ) {
			$next = $p->{deadline} if !defined $next || $p->{deadline} < $next;
		}
		my $wait = $next - time();
		$wait = 0 if $wait < 0;

		for my $h ( $sel->can_read($wait) ) {
			my $fn = fileno($h);                            # capture before any close() invalidates it
			my $p  = defined $fn ? $pending{$fn} : undef;
			next unless $p;
			if ( $p->{kind} eq 'dns' ) {
				my $reply = eval { $resolver->bgread( $p->{sock} ) };
				if ($reply) {
					my $recs = _dns_records( $reply, $p->{type} );
					$dns{ $p->{type} } = $recs if @{$recs};
				}
				$sel->remove( $p->{sock} );
				delete $pending{$fn};
			} else {
				my $n = sysread( $p->{fh}, my $chunk, 65536 );
				if ( !defined $n || $n == 0 ) {    # read error or EOF
					$sel->remove( $p->{fh} );
					close( $p->{fh} );
					if   ( $p->{kind} eq 'whois' ) { $whois         = $p->{buf}; }
					else                           { $dnstracer_out = $p->{buf}; }
					delete $pending{$fn};
				} else {
					$p->{buf} .= $chunk;
				}
			} ## end else [ if ( $p->{kind} eq 'dns' ) ]
		} ## end for my $h ( $sel->can_read($wait) )

		# Retire any source that has passed its deadline; kill live subprocesses
		# so close() cannot block on them.
		for my $fn ( keys %pending ) {
			my $p = $pending{$fn};
			next if time() < $p->{deadline};
			if ( $p->{kind} eq 'dns' ) {
				$sel->remove( $p->{sock} );
			} else {
				kill( 'TERM', $p->{pid} );
				kill( 'KILL', $p->{pid} );
				$sel->remove( $p->{fh} );
				close( $p->{fh} );
				if   ( $p->{kind} eq 'whois' ) { $whois         = $p->{buf}; }
				else                           { $dnstracer_out = $p->{buf}; }
			}
			delete $pending{$fn};
		} ## end for my $fn ( keys %pending )
	} ## end while (%pending)

	return {
		domain          => $domain,
		whois_domain    => $whois_domain,
		dns             => \%dns,
		dns_error       => $dns_error,
		whois           => $whois,
		dnstracer       => $dnstracer_out,
		dnstracer_error => '',
		cached          => 0,
	};
} ## end sub _domaininfo_gather

=head2 httpsinfo

Connects to https://DOMAIN:PORT/ and reports the certificate details, the HTTP
status of GET /, per-phase and total timing, whether the cert is expired, and
whether it validates (full chain + hostname). Runs in a subprocess.

=cut

sub httpsinfo {
	my $self   = shift;
	my $domain = $self->param('domain');
	my $port   = $self->param('port') // 443;

	unless ( defined $domain && $domain =~ /^[A-Za-z0-9._-]+$/ ) {
		return $self->render( json => { error => 'Invalid domain' }, status => 400 );
	}
	unless ( $port =~ /^[0-9]+$/ && $port >= 1 && $port <= 65535 ) {
		return $self->render( json => { error => 'Invalid port' }, status => 400 );
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return _httpsinfo_gather( $domain, $port ) },
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || ref $result ne 'HASH' ) {
				chomp( my $why = ( $err // 'lookup failed' ) );
				return $self->render(
					json   => { domain => $domain, error => 'httpsinfo failed: ' . $why },
					status => 500
				);
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub httpsinfo

# Milliseconds elapsed since a high resolution timestamp, for the per-phase
# timings the HTTPS panel reports. One decimal is enough to compare a handshake
# against a connect without pretending to more precision than a network
# measurement has.
#
# Plain function, not a method.
#
# Args:
#
#   - $start :: the earlier time, as Time::HiRes::time() returned it -- a float
#     of seconds since the epoch.
#
# Returns: the elapsed milliseconds as a number rounded to one decimal. A
# number rather than the string sprintf gives, so it encodes as a JSON number
# and the frontend can compare and sort it.
#
#     my $start = Time::HiRes::time();
#     ...
#     _ms_since($start);   # 12.4
sub _ms_since { return sprintf( '%.1f', ( Time::HiRes::time() - $_[0] ) * 1000 ) + 0 }

# Turn a certificate validity time into an epoch, so notAfter can be compared
# against now to say whether a certificate has expired.
#
# Net::SSLeay hands these back as ISO8601 UTC. Parsed here with a regex and
# timegm rather than a date module because it is the one format that ever
# arrives and the panel should not gain a dependency for it.
#
# Plain function, not a method.
#
# Args:
#
#   - $iso :: the time as Net::SSLeay produced it, e.g.
#     '2027-01-14T09:22:31Z'. Anything after the seconds is ignored. undef is
#     allowed.
#
# Returns: the epoch as an integer, or undef when the value is missing, is not
# in that format, or will not convert. Callers treat undef as "expiry unknown"
# and leave the expired flag off rather than guessing.
#
#     _isotime_to_epoch('2027-01-14T09:22:31Z');   # 1799234551
#     _isotime_to_epoch('sometime next year');     # undef
sub _isotime_to_epoch {
	my ($iso) = @_;
	return undef unless defined $iso && $iso =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/;
	return eval { Time::Local::timegm( $6, $5, $4, $3, $2 - 1, $1 ) };
}

# What the HTTPS panel shows for a host: how long each phase took, the
# certificate it presented, what GET / answered, and whether the chain actually
# verifies.
#
# Two connections are made, deliberately. The first runs with verification off
# so the certificate can be read and reported even when it is expired,
# self-signed, or for the wrong name -- which are exactly the cases worth
# looking at. The second verifies properly against the Mozilla CA bundle and
# only records the verdict. Doing it in one pass would mean either refusing to
# show a bad certificate or never reporting whether it was good.
#
# Everything is bounded: one deadline covers the whole exchange, and the
# response body is capped, so a slow or endless server costs a fixed amount.
# timed_out and read_capped say which limit was hit, so the panel never
# presents a truncated body as a complete one.
#
# Certificate fields are best effort -- each is read under eval and dropped if
# unavailable, since certificates vary in what they carry.
#
# Blocking throughout, so it is only ever called inside a
# Mojo::IOLoop->subprocess. Plain function, not a method.
#
# Args:
#
#   - $domain :: the host to connect to, as a hostname. Also sent as SNI and as
#     the Host header, and verified against.
#   - $port :: the TCP port, normally 443.
#
# Returns: a hash ref, rendered to the browser as-is:
#
#     {
#       domain           => 'example.org',
#       port             => 443,
#       tcp_connect_ms   => 11.2,
#       tls_handshake_ms => 24.8,
#       response_ms      => 41.0,
#       total_ms         => 77.0,
#       timed_out        => 0,
#       read_capped      => 0,
#       http_status      => 301,
#       http_reason      => 'Moved Permanently',
#       redirect_to      => 'https://www.example.org/',   # 3xx only
#       expired          => 0,
#       valid            => 1,
#       cert             => { cn => 'example.org', issuer => '...', sans => [...],
#                             not_before => '...', not_after => '...',
#                             fp_sha256 => '...', key_bits omitted if unreadable },
#     }
#
# A connection that never got started returns early with only domain, port, and
# error set -- so a caller must check error before reading a timing.
#
#     my $info = _httpsinfo_gather( 'example.org', 443 );
#     # $info->{valid} is 1, $info->{cert}{cn} is 'example.org'
#
#     my $info = _httpsinfo_gather( 'nowhere.invalid', 443 );
#     # { domain => 'nowhere.invalid', port => 443,
#     #   error => 'TCP connect to nowhere.invalid:443 failed: ...' }
sub _httpsinfo_gather {
	my ( $domain, $port ) = @_;
	my %r = ( domain => $domain, port => $port + 0 );

	my $timeout  = 5;
	my $cap      = 512 * 1024;
	my $start    = Time::HiRes::time();
	my $deadline = $start + $timeout;

	my $tcp = IO::Socket::IP->new( PeerHost => $domain, PeerPort => $port, Proto => 'tcp', Timeout => $timeout );
	unless ($tcp) {
		$r{error} = "TCP connect to $domain:$port failed: $!";
		return \%r;
	}
	$r{tcp_connect_ms} = _ms_since($start);

	my $t1 = Time::HiRes::time();
	unless (
		IO::Socket::SSL->start_SSL(
			$tcp,
			SSL_verify_mode => SSL_VERIFY_NONE,
			SSL_hostname    => $domain,
			Timeout         => $timeout
		)
		)
	{
		$r{error} = 'TLS handshake failed: ' . ( $IO::Socket::SSL::SSL_ERROR // $! );
		return \%r;
	} ## end unless ( IO::Socket::SSL->start_SSL( $tcp, SSL_verify_mode...))
	$r{tls_handshake_ms} = _ms_since($t1);

	# certificate details, best effort — skip any field that is unavailable
	my $x = eval { $tcp->peer_certificate };
	if ($x) {
		my %c;
		$c{cn}      = eval { $tcp->peer_certificate('cn') };
		$c{subject} = eval { $tcp->peer_certificate('subject') };
		$c{issuer}  = eval { $tcp->peer_certificate('issuer') };
		my @sans = eval { $tcp->peer_certificate('subjectAltNames') };
		if (@sans) {
			my @v;
			for ( my $i = 1; $i < @sans; $i += 2 ) { push @v, $sans[$i] if defined $sans[$i]; }
			$c{sans} = \@v if @v;
		}
		$c{not_before} = eval { Net::SSLeay::P_ASN1_TIME_get_isotime( Net::SSLeay::X509_get_notBefore($x) ) };
		$c{not_after}  = eval { Net::SSLeay::P_ASN1_TIME_get_isotime( Net::SSLeay::X509_get_notAfter($x) ) };
		$c{serial}     = eval { Net::SSLeay::P_ASN1_INTEGER_get_hex( Net::SSLeay::X509_get_serialNumber($x) ) };
		$c{version}    = eval { Net::SSLeay::X509_get_version($x) + 1 };
		$c{sig_alg}    = eval { Net::SSLeay::OBJ_obj2txt( Net::SSLeay::P_X509_get_signature_alg($x) ) };
		$c{fp_sha1}    = eval { Net::SSLeay::X509_get_fingerprint( $x, 'sha1' ) };
		$c{fp_sha256}  = eval { Net::SSLeay::X509_get_fingerprint( $x, 'sha256' ) };

		for my $k ( keys %c ) {
			delete $c{$k} unless defined $c{$k} && ( ref $c{$k} || $c{$k} ne '' );
		}
		$r{cert} = \%c;

		my $ep = _isotime_to_epoch( $c{not_after} );
		$r{expired} = ( defined $ep && $ep < time() ) ? 1 : 0 if defined $ep;
	} ## end if ($x)

	# GET / with the overall deadline and a read cap
	my $t2          = Time::HiRes::time();
	my $timed_out   = 0;
	my $read_capped = 0;
	my $resp        = '';
	{
		local $SIG{PIPE} = 'IGNORE';
		print {$tcp} "GET / HTTP/1.1\r\nHost: $domain\r\nConnection: close\r\nUser-Agent: Lilith\r\n\r\n";
		my $sel = IO::Select->new($tcp);
		while (1) {
			my $rem = $deadline - Time::HiRes::time();
			if ( $rem <= 0 ) { $timed_out = 1; last; }
			if ( $sel->can_read($rem) ) {
				my $n = sysread( $tcp, my $buf, 65536 );
				last if !defined $n || $n == 0;
				$resp .= $buf;
				if ( length($resp) >= $cap ) { $read_capped = 1; last; }
			} else {
				$timed_out = 1;
				last;
			}
		} ## end while (1)
	}
	$r{response_ms} = _ms_since($t2);
	$r{total_ms}    = _ms_since($start);
	$r{timed_out}   = $timed_out;
	$r{read_capped} = $read_capped;
	close($tcp);

	if ( $resp =~ m{\AHTTP/\d(?:\.\d)?\s+(\d{3})([^\r\n]*)} ) {
		$r{http_status} = $1 + 0;
		( my $reason = $2 ) =~ s/^\s+//;
		$r{http_reason} = $reason if length $reason;
	}
	if ( defined $r{http_status} && $r{http_status} >= 300 && $r{http_status} < 400 ) {
		if ( $resp =~ /^Location:\s*([^\r\n]+)/mi ) {
			( $r{redirect_to} = $1 ) =~ s/\s+\z//;
		}
	}

	# validity — full chain + hostname against the Mozilla CA bundle
	my $v = IO::Socket::SSL->new(
		PeerHost            => $domain,
		PeerPort            => $port,
		Proto               => 'tcp',
		Timeout             => $timeout,
		SSL_verify_mode     => SSL_VERIFY_PEER,
		SSL_hostname        => $domain,
		SSL_verifycn_name   => $domain,
		SSL_verifycn_scheme => 'http',
		SSL_ca_file         => Mozilla::CA::SSL_ca_file(),
	);
	if ($v) {
		$r{valid} = 1;
		close($v);
	} else {
		$r{valid} = 0;
		( $r{valid_error} = ( $IO::Socket::SSL::SSL_ERROR // 'verification failed' ) ) =~ s/\s+\z//;
	}

	return \%r;
} ## end sub _httpsinfo_gather

=head2 mailinfo

Combined mail-authentication check for a domain: SPF (record + summary, plus an
evaluation when an IP is given), DMARC (record + policy, with the organizational
domain tree walk), and DKIM (the given selector, or a probe of common selectors).
Runs in a subprocess.

=cut

sub mailinfo {
	my $self     = shift;
	my $domain   = $self->param('domain');
	my $ip       = $self->param('ip');
	my $selector = $self->param('selector');

	unless ( defined $domain && $domain =~ /^[A-Za-z0-9._-]+$/ ) {
		return $self->render( json => { error => 'Invalid domain' }, status => 400 );
	}
	if ( defined $ip && $ip ne '' ) {
		return $self->render( json => { error => 'Invalid IP' }, status => 400 )
			unless $ip =~ /^[0-9a-fA-F:.]+$/;
	} else {
		$ip = undef;
	}
	if ( defined $selector && $selector ne '' ) {
		return $self->render( json => { error => 'Invalid selector' }, status => 400 )
			unless $selector =~ /^[A-Za-z0-9._-]+$/;
	} else {
		$selector = undef;
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return _mailinfo_gather( $domain, $ip, $selector ) },
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || ref $result ne 'HASH' ) {
				chomp( my $why = ( $err // 'lookup failed' ) );
				return $self->render(
					json   => { domain => $domain, error => 'mailinfo failed: ' . $why },
					status => 500
				);
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub mailinfo

# The whole mail authentication picture for a domain in one structure: where
# its mail goes, and its SPF, DMARC, and DKIM. Just the four gatherers under one
# key each, so the frontend makes one request instead of four and gets a
# consistent view rather than four snapshots taken at different moments.
#
# Each part handles its own failures, so a domain with SPF but no DMARC returns
# both keys with the second explaining itself. Nothing here dies.
#
# Blocking throughout, so it is only ever called inside a
# Mojo::IOLoop->subprocess. Plain function, not a method.
#
# Args:
#
#   - $domain :: the domain to check. Already validated by the caller against
#     /^[A-Za-z0-9._-]+$/.
#   - $ip :: a sending address to evaluate the SPF policy against, or undef for
#     the record and its summary without an evaluation.
#   - $selector :: a known DKIM selector to look up, or undef to probe the
#     common ones.
#
# Returns: a hash ref of the four gathers:
#
#     {
#       domain => 'example.org',
#       mx     => [ { preference => 10, exchange => 'mx1.example.org' } ],
#       spf    => { record => 'v=spf1 ...', summary => {...}, result => 'pass' },
#       dmarc  => { record => 'v=DMARC1; p=reject', p => 'reject', ... },
#       dkim   => { keys => [ ... ], probed => 1 },
#     }
#
#     my $info = _mailinfo_gather( 'example.org', '192.0.2.10', undef );
#     # $info->{spf}{result} is 'pass' when that address may send for the domain
sub _mailinfo_gather {
	my ( $domain, $ip, $selector ) = @_;
	return {
		domain => $domain,
		mx     => _mx_gather($domain),
		spf    => _spfinfo_gather( $domain, $ip ),
		dmarc  => _dmarc_gather($domain),
		dkim   => _dkim_gather( $domain, $selector ),
	};
} ## end sub _mailinfo_gather

# Where a domain's mail actually goes, as the mail panel lists it. Sorted by
# preference so the primary exchanger is first, which is the order a sender
# would try them in.
#
# Short resolver timeouts and a single retry: this is one part of a larger
# gather, and a domain with no MX at all is a normal answer worth returning
# quickly rather than waiting out the default retry schedule for.
#
# Plain function, not a method.
#
# Args:
#
#   - $domain :: the domain to look up.
#
# Returns: an array ref of { preference, exchange } hash refs sorted by
# preference ascending. preference is forced to a number so it encodes as a
# JSON number; exchange is the hostname as the record gave it.
#
# Empty when the domain has no MX records or the lookup failed -- the two are
# not distinguished, since neither gives the panel anything to show.
#
#     _mx_gather('example.org');
#     # [ { preference => 10, exchange => 'mx1.example.org' },
#     #   { preference => 20, exchange => 'mx2.example.org' } ]
sub _mx_gather {
	my ($domain) = @_;
	my @mx;
	eval {
		my $resolver = Net::DNS::Resolver->new( udp_timeout => 3, tcp_timeout => 3, retry => 1 );
		my $reply    = $resolver->query( $domain, 'MX' );
		if ($reply) {
			for my $rr ( $reply->answer ) {
				next unless $rr->type eq 'MX';
				push( @mx, { preference => $rr->preference + 0, exchange => $rr->exchange } );
			}
		}
	};
	@mx = sort { $a->{preference} <=> $b->{preference} } @mx;
	return \@mx;
} ## end sub _mx_gather

# The first TXT record at a name that looks like the kind of record being
# hunted. SPF, DMARC, and DKIM all live in TXT records, and a name may hold
# several unrelated ones, so a pattern rather than the first answer is what
# decides.
#
# Short timeouts and one retry matter here more than anywhere else: probing the
# common DKIM selectors means around thirty lookups, most of which are expected
# to find nothing. On the default retry schedule that alone would outlast the
# request.
#
# Plain function, not a method.
#
# Args:
#
#   - $name :: the exact name to query, already assembled -- e.g.
#     '_dmarc.example.org' or 'default._domainkey.example.org'.
#   - $re :: a qr// the record must match to count, e.g. qr/^v=DMARC1\b/i.
#     Multi-string TXT records are joined before matching, so a long key split
#     across strings still matches.
#
# Returns: the matching record as a single string, or undef when the name does
# not resolve, holds no TXT record, or holds none that matches. The caller
# treats undef as "not published".
#
#     _fetch_txt( '_dmarc.example.org', qr/^v=DMARC1\b/i );
#     # 'v=DMARC1; p=reject; rua=mailto:dmarc@example.org'
#
#     _fetch_txt( '_dmarc.example.org', qr/^v=DMARC1\b/i );
#     # undef when the domain publishes no DMARC record
sub _fetch_txt {
	my ( $name, $re ) = @_;
	my $rec;
	eval {
		my $resolver = Net::DNS::Resolver->new( udp_timeout => 3, tcp_timeout => 3, retry => 1 );
		my $reply    = $resolver->query( $name, 'TXT' );
		if ($reply) {
			for my $rr ( $reply->answer ) {
				next unless $rr->type eq 'TXT';
				my $txt = join( '', $rr->txtdata );
				if ( $txt =~ $re ) { $rec = $txt; last; }
			}
		}
	};
	return $rec;
} ## end sub _fetch_txt

# A domain's DMARC record and what its policy actually says.
#
# DMARC is inherited: a subdomain with no record of its own is covered by the
# organizational domain's. So the exact name is tried first and the
# organizational domain second, and found_at records which one answered --
# without it the panel could not tell a domain's own policy from an inherited
# one, which is the difference between a deliberate setting and a default.
#
# The record is parsed with Mail::DMARC::Policy so the panel can show the tags
# individually rather than leaving the reader to pick a raw record apart. That
# parse is best effort: an unparseable record still comes back verbatim.
#
# Plain function, not a method.
#
# Args:
#
#   - $domain :: the domain to check.
#
# Returns: a hash ref. With a record found:
#
#     {
#       record   => 'v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.org',
#       found_at => 'example.org',   # the name that held it
#       v => 'DMARC1', p => 'reject', pct => '100',
#       rua => 'mailto:dmarc@example.org',
#       # sp, ruf, adkim, aspf, fo, rf, ri when the record sets them
#     }
#
# With none, a single note key naming both places that were tried, so the panel
# can say what was looked for rather than only that nothing was found:
#
#     { note => 'no DMARC record found for mail.example.org or example.org' }
sub _dmarc_gather {
	my ($domain) = @_;
	my %d;

	my $org   = eval { Mail::DMARC::PurePerl->new->get_organizational_domain($domain) };
	my @cands = ($domain);
	push( @cands, $org ) if defined $org && $org ne $domain;

	my ( $record, $found_at );
	for my $cand (@cands) {
		my $rec = _fetch_txt( '_dmarc.' . $cand, qr/^v=DMARC1\b/i );
		if ($rec) { $record = $rec; $found_at = $cand; last; }
	}

	if ($record) {
		$d{record}   = $record;
		$d{found_at} = $found_at;
		my $policy = eval { Mail::DMARC::Policy->new($record) };
		if ($policy) {
			for my $f (qw( v p sp pct rua ruf adkim aspf fo rf ri )) {
				my $val = eval { $policy->$f };
				$d{$f} = "$val" if defined $val && $val ne '';
			}
		}
	} else {
		$d{note}
			= 'no DMARC record found for ' . $domain . ( ( defined $org && $org ne $domain ) ? ' or ' . $org : '' );
	}
	return \%d;
} ## end sub _dmarc_gather

# Common DKIM selectors to probe when none is supplied.
my @COMMON_DKIM_SELECTORS = qw(
	default google selector1 selector2 s1 s2 k1 k2 k3 mail dkim dkim1
	mandrill mxvault sig1 fm1 fm2 fm3 protonmail protonmail2 protonmail3
	zoho zmail smtp key1 pic scph mte1
);

# A domain's DKIM public keys, either at a selector that is known or by probing
# the ones in common use.
#
# DKIM has no way to ask a domain which selectors it publishes -- a key lives at
# a name derived from a selector, and the selector is only ever learned from a
# signed message. So without one the only option is to guess, and the probe walks
# @COMMON_DKIM_SELECTORS. That means a negative result proves nothing, which is
# why probed is reported and the note says so in as many words.
#
# Plain function, not a method.
#
# Args:
#
#   - $domain :: the domain to check.
#   - $selector :: the selector to look up, as taken from a signed message's
#     DKIM-Signature s= tag. undef or empty probes the common list instead.
#
# Returns: a hash ref:
#
#     {
#       selector => 'google',   # only when one was supplied
#       probed   => 1,          # only when the common list was walked
#       keys     => [ { selector => 'google', key_bits => 2048, ... } ],
#       note     => '...',      # only when keys is empty
#     }
#
# keys is always present, one entry per selector that answered, each as
# _dkim_parse_record built it. Empty with a note explaining which of the two
# searches came up short.
#
#     _dkim_gather( 'example.org', 'google' );
#     # { selector => 'google', keys => [ { selector => 'google', key_bits => 2048, ... } ] }
#
#     _dkim_gather( 'example.org', undef );
#     # { probed => 1, keys => [], note => 'no DKIM key found for the probed ...' }
sub _dkim_gather {
	my ( $domain, $selector ) = @_;
	my %d;
	my @selectors;
	if ( defined $selector && $selector ne '' ) {
		@selectors = ($selector);
		$d{selector} = $selector;
	} else {
		@selectors = @COMMON_DKIM_SELECTORS;
		$d{probed} = 1;
	}

	my @keys;
	for my $sel (@selectors) {
		my $txt = _fetch_txt( $sel . '._domainkey.' . $domain, qr/(?:^v=DKIM1|(?:^|;)\s*[kp]=)/i );
		push( @keys, _dkim_parse_record( $sel, $txt ) ) if defined $txt;
	}
	$d{keys} = \@keys;
	unless (@keys) {
		$d{note}
			= $d{probed}
			? 'no DKIM key found for the probed common selectors — supply the selector if known'
			: 'no DKIM key found for that selector';
	}
	return \%d;
} ## end sub _dkim_gather

# Pick a DKIM public key record apart into named fields, so the panel can show
# what the key is and what state it is in rather than a wall of tags.
#
# Two states are worth naming outright because both look like an ordinary
# record to anyone skimming it. An empty p= is a revoked key, not a malformed
# one -- that is how DKIM retires a selector. And t=y marks the domain as
# testing, meaning verifiers are asked to ignore failures, so a signature that
# appears to work may not be being enforced at all.
#
# Key size is worked out by handing the record to Mail::DKIM, since it is
# encoded in the key rather than stated. Best effort: a key that will not parse
# simply has no key_bits.
#
# Pure -- no DNS, no network. Plain function, not a method.
#
# Args:
#
#   - $selector :: the selector this record was found at, carried through so a
#     caller probing several can tell the results apart.
#   - $txt :: the record as published, e.g.
#     'v=DKIM1; k=rsa; p=MIIBIjANBgkq...'. Tags it does not carry are simply
#     absent from the result.
#
# Returns: a hash ref. selector, record, key_type, testing, and revoked are
# always present; the rest only when the record set them:
#
#     {
#       selector   => 'google',
#       record     => 'v=DKIM1; k=rsa; p=MIIBIjANBgkq...',
#       version    => 'DKIM1',
#       key_type   => 'rsa',        # 'rsa' when the record omits k=
#       key_bits   => 2048,         # absent when the key will not parse
#       public_key => 'MIIBIjANBgkq...',
#       testing    => 0,            # 1 when t=y
#       revoked    => 0,            # 1 when p= is empty
#     }
#
#     _dkim_parse_record( 'sel1', 'v=DKIM1; k=rsa; p=' );
#     # revoked => 1, no public_key, no key_bits
sub _dkim_parse_record {
	my ( $selector, $txt ) = @_;
	my %info = ( selector => $selector, record => $txt );

	my %tag;
	for my $t ( split /\s*;\s*/, $txt ) {
		if ( $t =~ /^\s*([a-z]+)\s*=\s*(.*)$/is ) { $tag{ lc $1 } = $2; }
	}
	$info{version}         = $tag{v} if defined $tag{v};
	$info{key_type}        = $tag{k} // 'rsa';
	$info{hash_algorithms} = $tag{h} if defined $tag{h};
	$info{service_types}   = $tag{s} if defined $tag{s};
	$info{granularity}     = $tag{g} if defined $tag{g};
	$info{notes}           = $tag{n} if defined $tag{n};
	$info{flags}           = $tag{t} if defined $tag{t};
	$info{testing}         = ( defined $tag{t} && $tag{t} =~ /(?:^|:)\s*y\s*(?::|$)/ ) ? 1 : 0;
	$info{revoked}         = ( !defined $tag{p} || $tag{p} eq '' )                     ? 1 : 0;
	$info{public_key}      = $tag{p} if defined $tag{p} && $tag{p} ne '';

	unless ( $info{revoked} ) {
		my $bits = eval { Mail::DKIM::PublicKey->parse($txt)->cork->size * 8 };
		$info{key_bits} = $bits if $bits;
	}
	return \%info;
} ## end sub _dkim_parse_record

# A domain's SPF record, what it means, and -- when an address is given -- what
# it says about that address.
#
# The two halves are separate on purpose. The record and its summary need only a
# TXT lookup and answer "what has this domain published". An evaluation needs a
# sending address and answers "may this host send for it", which is a different
# question and the one that matters when looking at a suspect message. Asking
# without an address gets the first half alone.
#
# The evaluation goes through Mail::SPF rather than reading the record here,
# because getting it right means following include and redirect and honouring
# the lookup limit -- and a hand rolled answer that disagrees with what a real
# receiver would decide is worse than none.
#
# Blocking, so it is only ever called inside a Mojo::IOLoop->subprocess. Plain
# function, not a method.
#
# Args:
#
#   - $domain :: the domain whose policy is being read.
#   - $ip :: the sending address to evaluate against, v4 or v6. undef or empty
#     skips the evaluation and returns the record and summary only.
#
# Returns: a hash ref. domain is always present; record and summary whenever
# the domain publishes SPF; the evaluation keys only when an address was given:
#
#     {
#       domain       => 'example.org',
#       record       => 'v=spf1 include:_spf.example.org -all',
#       summary      => { all => 'fail', mechanisms => [...], dns_lookups => 3 },
#       ip           => '192.0.2.10',
#       identity     => 'postmaster@example.org',   # what was evaluated as
#       result       => 'pass',   # or fail, softfail, neutral, none, permerror
#       explanation  => '...',
#       received_spf => 'Received-SPF: pass ...',
#       error        => '...',    # only when the evaluation itself failed
#     }
#
# A domain with no SPF record returns just domain, and ip when one was given --
# so a caller must check record before reading summary.
#
#     _spfinfo_gather( 'example.org', '192.0.2.10' );
#     # result => 'pass'
#
#     _spfinfo_gather( 'example.org', undef );
#     # the record and its summary, with no verdict
sub _spfinfo_gather {
	my ( $domain, $ip ) = @_;
	my %r = ( domain => $domain );
	$r{ip} = $ip if defined $ip;

	# The domain's v=spf1 TXT record, plus a static summary of it.
	eval {
		my $resolver = Net::DNS::Resolver->new;
		my $reply    = $resolver->query( $domain, 'TXT' );
		if ($reply) {
			for my $rr ( $reply->answer ) {
				next unless $rr->type eq 'TXT';
				my $txt = join( '', $rr->txtdata );
				if ( $txt =~ /^v=spf1\b/i ) { $r{record} = $txt; last; }
			}
		}
	};
	$r{summary} = _spf_summary( $r{record} ) if defined $r{record};

	# Evaluate the policy for a sending IP only when one was given.
	if ( defined $ip && $ip ne '' ) {
		my $identity = 'postmaster@' . $domain;
		$r{identity} = $identity;
		eval {
			my $server  = Mail::SPF::Server->new( query_timeout => 5 );
			my $request = Mail::SPF::Request->new(
				scope      => 'mfrom',
				identity   => $identity,
				ip_address => $ip,
			);
			my $result = $server->process($request);
			$r{result}       = $result->code;
			$r{explanation}  = eval { $result->local_explanation };
			$r{received_spf} = eval { $result->received_spf_header };
		};
		if ($@) {
			( my $why = $@ ) =~ s/\s+\z//;
			$r{error} = 'SPF evaluation failed: ' . $why;
		}
	} ## end if ( defined $ip && $ip ne '' )

	return \%r;
} ## end sub _spfinfo_gather

# Reduce an SPF record to the three things worth knowing at a glance: what it
# does with mail it does not recognise, what it is made of, and how close it is
# to the limit that would break it.
#
# That last one is the reason this exists. SPF allows ten DNS-consuming terms
# per evaluation, and a record over the limit is a permerror -- which receivers
# may treat as no SPF at all. The count here is for this record alone and does
# not follow include or redirect, so it is a floor rather than a total: a record
# counting four may still be over once its includes are expanded.
#
# The all policy is reported as the qualifier's name, since '-all' and '~all'
# are read at a glance as the same thing and mean quite different things to a
# receiver.
#
# Pure -- no DNS. Plain function, not a method.
#
# Args:
#
#   - $record :: the record as published, e.g. 'v=spf1 include:_spf.example.org
#     -all'. The v=spf1 prefix is optional. undef is allowed.
#
# Returns: a hash ref, or undef when given undef:
#
#     {
#       all         => 'fail',      # pass, fail, softfail, or neutral
#       mechanisms  => [ 'include:_spf.example.org', '-all' ],
#       modifiers   => [ 'redirect=_spf.example.org' ],
#       dns_lookups => 1,
#     }
#
# mechanisms, modifiers, and dns_lookups are always present. all is absent when
# the record has no all term, which leaves the default behaviour to whatever a
# redirect points at.
#
#     _spf_summary('v=spf1 a mx include:_spf.example.org ~all');
#     # all => 'softfail', dns_lookups => 3
sub _spf_summary {
	my ($record) = @_;
	return undef unless defined $record;

	my @terms = split /\s+/, $record;
	shift @terms if @terms && lc( $terms[0] ) eq 'v=spf1';

	my %qual = ( '+' => 'pass', '-' => 'fail', '~' => 'softfail', '?' => 'neutral' );
	my %s    = ( mechanisms => [], modifiers => [], dns_lookups => 0 );
	for my $term (@terms) {
		next if $term eq '';
		if ( $term =~ /^(redirect|exp)=/i ) {
			push @{ $s{modifiers} }, $term;
			$s{dns_lookups}++ if lc($1) eq 'redirect';
			next;
		}
		my ( $q, $mech ) = $term =~ /^([+\-~?]?)(.*)$/;
		my ($name) = ( lc( $mech // '' ) =~ /^([a-z]+)/ );
		$name //= '';
		if ( $name eq 'all' ) { $s{all} = $qual{ $q eq '' ? '+' : $q } // 'pass'; }
		push @{ $s{mechanisms} }, $term;
		$s{dns_lookups}++ if $name =~ /^(?:include|a|mx|ptr|exists)$/;
	} ## end for my $term (@terms)
	return \%s;
} ## end sub _spf_summary

1;
