package Lilith::Web::Controller::Api;

use Mojo::Base 'Mojolicious::Controller';
use Net::DNS   ();
use IO::Select ();

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

sub ipinfo {
	my $self = shift;
	my $ip   = $self->param('ip');

	# Strict validation — only digits, hex letters, dots, colons
	unless ( defined $ip && $ip =~ /^[0-9a-fA-F:.]+$/ ) {
		return $self->render( json => { error => 'Invalid IP' }, status => 400 );
	}

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

	$self->render(
		json => {
			ip         => $ip,
			ptr_name   => $ptr_name,
			rdns       => $rdns,
			rdns_error => $rdns_error,
			whois      => $whois,
			geo        => \%geo,
			geo_error  => $geo_error,
		}
	);
} ## end sub ipinfo

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

	my $result = {
		domain          => $domain,
		whois_domain    => $whois_domain,
		dns             => \%dns,
		dns_error       => $dns_error,
		whois           => $whois,
		dnstracer       => $dnstracer_out,
		dnstracer_error => '',
		cached          => 0,
	};

	if ( $cache_on && $ttl > 0 ) {
		my $cache = $self->domaininfo_cache;
		my $now   = time();
		for my $k ( keys %{$cache} ) {    # prune expired entries opportunistically
			delete $cache->{$k} if ( $now - $cache->{$k}{time} ) >= $ttl;
		}
		$cache->{$domain} = { time => $now, data => $result };
	}

	$self->render( json => $result );
} ## end sub domaininfo

1;
