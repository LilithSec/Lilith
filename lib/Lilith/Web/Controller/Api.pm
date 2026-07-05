package Lilith::Web::Controller::Api;

use Mojo::Base 'Mojolicious::Controller';
use Net::DNS     ();
use IO::Select   ();
use Mojo::IOLoop ();
use Mojo::JSON qw(decode_json);
use Time::Piece   ();
use Time::HiRes   ();
use Time::Local   ();
use IO::Socket::IP ();
use IO::Socket::SSL qw(SSL_VERIFY_PEER SSL_VERIFY_NONE);
use Net::SSLeay ();
use Mozilla::CA ();
use Mail::SPF            ();
use Mail::DMARC::PurePerl ();
use Mail::DMARC::Policy  ();
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
			}
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

=head2 _run_capture

Runs an external command (list form, no shell) and returns its stdout, giving
up after $timeout seconds. The read timeout is enforced with IO::Select rather
than alarm()/SIGALRM: under Mojo's EV reactor a SIGALRM can interrupt the read,
but the child process keeps running and the subsequent close()/waitpid then
blocks forever. Here the child is killed on timeout so cleanup never blocks.

    my $out = _run_capture( 10, 'whois', $domain );

=cut

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
	}

	# Kill a still-running child so close()'s waitpid cannot hang on it.
	if ($timed_out) {
		kill( 'TERM', $pid );
		kill( 'KILL', $pid );
	}
	close($fh);

	return $out;
} ## end sub _run_capture

=head2 ipinfo

Reverse DNS + whois + GeoIP for an IP, rendered as JSON. The blocking lookups
run in a subprocess so the web server's event loop stays responsive.

=cut

sub ipinfo {
	my $self = shift;
	my $ip   = $self->param('ip');

	# Strict validation — only digits, hex letters, dots, colons
	unless ( defined $ip && $ip =~ /^[0-9a-fA-F:.]+$/ ) {
		return $self->render( json => { error => 'Invalid IP' }, status => 400 );
	}

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return $self->_ipinfo_gather($ip); },
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || ref $result ne 'HASH' ) {
				return $self->render( json => { ip => $ip, error => 'lookup failed' }, status => 500 );
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub ipinfo

=head2 _ipinfo_gather

Performs the blocking reverse-DNS, whois, and GeoIP lookups for an IP and
returns the result hashref. Intended to be run inside a subprocess.

=cut

sub _ipinfo_gather {
	my ( $self, $ip ) = @_;

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

	return {
		ip         => $ip,
		ptr_name   => $ptr_name,
		rdns       => $rdns,
		rdns_error => $rdns_error,
		whois      => $whois,
		geo        => \%geo,
		geo_error  => $geo_error,
	};
} ## end sub _ipinfo_gather

=head2 _flatten_geo

Recursively flattens an MMDB record into C<$out> as dotted key => scalar pairs.
Localized C<names> hashes are collapsed onto their parent key, preferring the
English name, so C<< {country}{names}{en} >> becomes C<country>.

=cut

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
		}
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

=head2 _dns_records

Formats the answer records of one type from a Net::DNS reply into an arrayref
of display strings.

=cut

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
		elsif ( $type eq 'SOA' )   {
			push @recs, $rr->mname . ' ' . $rr->rname
				. ' serial=' . $rr->serial
				. ' refresh=' . $rr->refresh
				. ' retry=' . $rr->retry
				. ' expire=' . $rr->expire
				. ' min=' . $rr->minimum;
		}
		elsif ( $type eq 'CAA' ) { push @recs, $rr->flags . ' ' . $rr->tag . ' ' . $rr->value; }
		elsif ( $type eq 'SRV' ) {
			push @recs, $rr->priority . ' ' . $rr->weight . ' ' . $rr->port . ' ' . $rr->target;
		}
		else { push @recs, $rr->address; }
	}
	return \@recs;
} ## end sub _dns_records

=head2 _whois_domain

Reduces a hostname to the registrable/base domain used for the WHOIS query,
using Mozilla::PublicSuffix when available and a small known-two-level-TLD
heuristic as a fallback.

=cut

sub _whois_domain {
	my ($domain) = @_;
	my @labels = split /\./, $domain;
	return $domain unless @labels > 2;

	my $found = 0;
	my $whois_domain;
	eval {
		require Mozilla::PublicSuffix;
		my $suffix = Mozilla::PublicSuffix::public_suffix($domain);
		if ( defined $suffix && length $suffix ) {
			my $suffix_count = scalar( split /\./, $suffix );
			$whois_domain = join( '.', @labels[ -( $suffix_count + 1 ) .. -1 ] ) if @labels > $suffix_count;
			$found = 1;
		}
	};
	return $whois_domain // $domain if $found;

	# Fallback heuristic: known two-level TLDs get 3 labels, rest get 2.
	my $two_level = join( '.', @labels[ -2 .. -1 ] );
	my %tld2 = map { $_ => 1 } qw(
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

=head2 _domaininfo_gather

Performs the blocking DNS/whois/dnstracer gather for a domain and returns the
result hashref. Intended to be run inside a subprocess.

=cut

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
			my $fn = fileno($h);            # capture before any close() invalidates it
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
			}
		}

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
		}
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
				return $self->render( json => { domain => $domain, error => 'httpsinfo failed: ' . $why },
					status => 500 );
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub httpsinfo

=head2 _ms_since

Milliseconds elapsed since a Time::HiRes timestamp, to one decimal.

=cut

sub _ms_since { return sprintf( '%.1f', ( Time::HiRes::time() - $_[0] ) * 1000 ) + 0 }

=head2 _isotime_to_epoch

Parses an ISO8601 UTC time (as returned by Net::SSLeay) into an epoch, or undef.

=cut

sub _isotime_to_epoch {
	my ($iso) = @_;
	return undef unless defined $iso && $iso =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/;
	return eval { Time::Local::timegm( $6, $5, $4, $3, $2 - 1, $1 ) };
}

=head2 _httpsinfo_gather

Does the blocking TLS/HTTP work for httpsinfo and returns a result hashref.
Intended to be run inside a subprocess.

=cut

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
	unless ( IO::Socket::SSL->start_SSL( $tcp, SSL_verify_mode => SSL_VERIFY_NONE, SSL_hostname => $domain, Timeout => $timeout ) ) {
		$r{error} = 'TLS handshake failed: ' . ( $IO::Socket::SSL::SSL_ERROR // $! );
		return \%r;
	}
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
		}
	}
	$r{response_ms}  = _ms_since($t2);
	$r{total_ms}     = _ms_since($start);
	$r{timed_out}    = $timed_out;
	$r{read_capped}  = $read_capped;
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
	} else { $ip = undef; }
	if ( defined $selector && $selector ne '' ) {
		return $self->render( json => { error => 'Invalid selector' }, status => 400 )
			unless $selector =~ /^[A-Za-z0-9._-]+$/;
	} else { $selector = undef; }

	$self->render_later;
	Mojo::IOLoop->subprocess(
		sub { return _mailinfo_gather( $domain, $ip, $selector ) },
		sub {
			my ( $subprocess, $err, $result ) = @_;
			if ( $err || ref $result ne 'HASH' ) {
				chomp( my $why = ( $err // 'lookup failed' ) );
				return $self->render( json => { domain => $domain, error => 'mailinfo failed: ' . $why },
					status => 500 );
			}
			$self->render( json => $result );
		},
	);
	return;
} ## end sub mailinfo

=head2 _mailinfo_gather

Gathers SPF, DMARC, and DKIM for a domain. Intended to be run in a subprocess.

=cut

sub _mailinfo_gather {
	my ( $domain, $ip, $selector ) = @_;
	return {
		domain => $domain,
		mx     => _mx_gather($domain),
		spf    => _spfinfo_gather( $domain, $ip ),
		dmarc  => _dmarc_gather($domain),
		dkim   => _dkim_gather( $domain, $selector ),
	};
}

=head2 _mx_gather

Returns the domain's MX records as an arrayref of { preference, exchange },
sorted by preference.

=cut

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

=head2 _fetch_txt

Returns the first TXT record at $name matching $re, or undef. Uses a short
timeout so probing many names does not hang.

=cut

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
}

=head2 _dmarc_gather

DMARC record and parsed policy for a domain, walking up to the organizational
domain (via Mail::DMARC) when the exact domain has no record.

=cut

sub _dmarc_gather {
	my ($domain) = @_;
	my %d;

	my $org = eval { Mail::DMARC::PurePerl->new->get_organizational_domain($domain) };
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
		$d{note} = 'no DMARC record found for ' . $domain
			. ( ( defined $org && $org ne $domain ) ? ' or ' . $org : '' );
	}
	return \%d;
} ## end sub _dmarc_gather

# Common DKIM selectors to probe when none is supplied.
my @COMMON_DKIM_SELECTORS = qw(
	default google selector1 selector2 s1 s2 k1 k2 k3 mail dkim dkim1
	mandrill mxvault sig1 fm1 fm2 fm3 protonmail protonmail2 protonmail3
	zoho zmail smtp key1 pic scph mte1
);

=head2 _dkim_gather

DKIM public keys for a domain: the given selector, or a probe of common
selectors when none is supplied. Returns any found keys parsed for detail.

=cut

sub _dkim_gather {
	my ( $domain, $selector ) = @_;
	my %d;
	my @selectors;
	if ( defined $selector && $selector ne '' ) {
		@selectors    = ($selector);
		$d{selector}  = $selector;
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
		$d{note} = $d{probed}
			? 'no DKIM key found for the probed common selectors — supply the selector if known'
			: 'no DKIM key found for that selector';
	}
	return \%d;
} ## end sub _dkim_gather

=head2 _dkim_parse_record

Parses a DKIM public-key TXT record into a detail hashref (best effort). Pure,
no DNS. Key size is computed via Mail::DKIM when the key is present.

=cut

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
	$info{revoked}         = ( !defined $tag{p} || $tag{p} eq '' ) ? 1 : 0;
	$info{public_key}      = $tag{p} if defined $tag{p} && $tag{p} ne '';

	unless ( $info{revoked} ) {
		my $bits = eval { Mail::DKIM::PublicKey->parse($txt)->cork->size * 8 };
		$info{key_bits} = $bits if $bits;
	}
	return \%info;
} ## end sub _dkim_parse_record

=head2 _spfinfo_gather

Does the blocking SPF evaluation (and v=spf1 record lookup) for spfinfo and
returns a result hashref. Intended to be run inside a subprocess.

=cut

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
	}

	return \%r;
} ## end sub _spfinfo_gather

=head2 _spf_summary

Parses a v=spf1 record string into a summary: the default (all) policy, the
list of mechanisms and modifiers, and a count of the DNS-lookup-consuming terms
in this record.

=cut

sub _spf_summary {
	my ($record) = @_;
	return undef unless defined $record;

	my @terms = split /\s+/, $record;
	shift @terms if @terms && lc( $terms[0] ) eq 'v=spf1';

	my %qual = ( '+' => 'pass', '-' => 'fail', '~' => 'softfail', '?' => 'neutral' );
	my %s = ( mechanisms => [], modifiers => [], dns_lookups => 0 );
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
	}
	return \%s;
} ## end sub _spf_summary

1;
