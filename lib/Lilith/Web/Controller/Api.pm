package Lilith::Web::Controller::Api;

use Mojo::Base 'Mojolicious::Controller';
use Net::DNS   ();
use IO::Select ();

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

	# WHOIS — list-form open avoids shell injection
	my $whois = '';
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm(10);
		if ( open( my $fh, '-|', 'whois', $ip ) ) {
			local $/;
			$whois = <$fh>;
			close($fh);
		}
		alarm(0);
	};
	alarm(0);

	$self->render(
		json => {
			ip         => $ip,
			ptr_name   => $ptr_name,
			rdns       => $rdns,
			rdns_error => $rdns_error,
			whois      => $whois,
		}
	);
}

sub domaininfo {
	my $self   = shift;
	my $domain = $self->param('domain');

	# Basic domain validation
	unless ( defined $domain && $domain =~ /^[A-Za-z0-9._-]+$/ ) {
		return $self->render( json => { error => 'Invalid domain' }, status => 400 );
	}

	# DNS lookups
	my %dns;
	my $dns_error = '';
	eval {
		my $resolver     = Net::DNS::Resolver->new;
		my $sel          = IO::Select->new;
		my %sock_to_type;

		# Send all queries simultaneously
		for my $type (qw(A AAAA CNAME MX NS TXT SOA CAA SRV PTR)) {
			my $sock = $resolver->bgsend( $domain, $type );
			if ($sock) {
				$sel->add($sock);
				$sock_to_type{"$sock"} = $type;
			}
		}

		# Collect responses as they arrive, up to dns_bg_timeout seconds total
		my $deadline = time() + $self->dns_bg_timeout;
		while ( $sel->count && time() < $deadline ) {
			my @ready = $sel->can_read( $deadline - time() );
			for my $sock (@ready) {
				my $reply = $resolver->bgread($sock);
				$sel->remove($sock);
				next unless $reply;
				my $type = $sock_to_type{"$sock"};
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
					elsif ( $type eq 'CAA' ) { push @recs, $rr->flag . ' ' . $rr->tag . ' ' . $rr->value; }
					elsif ( $type eq 'SRV' ) {
						push @recs, $rr->priority . ' ' . $rr->weight . ' ' . $rr->port . ' ' . $rr->target;
					}
					else { push @recs, $rr->address; }
				}
				$dns{$type} = \@recs if @recs;
			}
		}
	};
	$dns_error = $@ if $@;

	# Determine the registrable/base domain for WHOIS
	my $whois_domain = $domain;
	{
		my @labels = split /\./, $domain;
		if ( @labels > 2 ) {
			my $found = 0;
			eval {
				require Mozilla::PublicSuffix;
				my $suffix = Mozilla::PublicSuffix::public_suffix($domain);
				if ( defined $suffix && length $suffix ) {
					my $suffix_count = scalar( split /\./, $suffix );
					if ( @labels > $suffix_count ) {
						$whois_domain = join( '.', @labels[ -( $suffix_count + 1 ) .. -1 ] );
					}
					$found = 1;
				}
			};
			unless ($found) {
				# Fallback heuristic: known two-level TLDs get 3 labels, rest get 2
				my $two_level = join( '.', @labels[ -2 .. -1 ] );
				my %tld2 = map { $_ => 1 } qw(
					co.uk co.au co.nz co.za co.in co.jp co.kr co.id co.il
					com.au com.br com.cn com.mx com.ar com.sg com.hk com.tw
					org.uk net.uk me.uk org.au net.au
				);
				if ( $tld2{$two_level} && @labels > 3 ) {
					$whois_domain = join( '.', @labels[ -3 .. -1 ] );
				} elsif ( !$tld2{$two_level} ) {
					$whois_domain = join( '.', @labels[ -2 .. -1 ] );
				}
			}
		}
	}

	# WHOIS
	my $whois = '';
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm(10);
		if ( open( my $fh, '-|', 'whois', $whois_domain ) ) {
			local $/;
			$whois = <$fh>;
			close($fh);
		}
		alarm(0);
	};
	alarm(0);

	# dnstracer
	my $dnstracer_out   = '';
	my $dnstracer_error = '';
	if ( $self->dnstracer_enable ) {
		my @dt_flags = @{ $self->dnstracer_flags };
		eval {
			local $SIG{ALRM} = sub { die "timeout\n" };
			alarm(30);
			if ( open( my $fh, '-|', 'dnstracer', @dt_flags, $domain ) ) {
				local $/;
				$dnstracer_out = <$fh>;
				close($fh);
			}
			alarm(0);
		};
		alarm(0);
		$dnstracer_error = $@ if $@;
	}

	$self->render(
		json => {
			domain          => $domain,
			whois_domain    => $whois_domain,
			dns             => \%dns,
			dns_error       => $dns_error,
			whois           => $whois,
			dnstracer       => $dnstracer_out,
			dnstracer_error => $dnstracer_error,
		}
	);
}

1;
