package Lilith::Web::Controller::Api;

use Mojo::Base 'Mojolicious::Controller';
use Net::DNS ();

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
		my $resolver = Net::DNS::Resolver->new;
		for my $type (qw(A AAAA CNAME MX NS TXT)) {
			my $reply = $resolver->query( $domain, $type );
			next unless $reply;
			my @recs;
			for my $rr ( $reply->answer ) {
				next unless $rr->type eq $type;
				if    ( $type eq 'MX' )  { push @recs, $rr->preference . ' ' . $rr->exchange; }
				elsif ( $type eq 'TXT' ) { push @recs, join( '', $rr->txtdata ); }
				elsif ( $type eq 'NS' )  { push @recs, $rr->nsdname; }
				elsif ( $type eq 'CNAME' ) { push @recs, $rr->cname; }
				else                     { push @recs, $rr->address; }
			}
			$dns{$type} = \@recs if @recs;
		}
	};
	$dns_error = $@ if $@;

	# WHOIS
	my $whois = '';
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm(10);
		if ( open( my $fh, '-|', 'whois', $domain ) ) {
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
	my @dt_flags        = @{ $self->dnstracer_flags };
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

	$self->render(
		json => {
			domain          => $domain,
			dns             => \%dns,
			dns_error       => $dns_error,
			whois           => $whois,
			dnstracer       => $dnstracer_out,
			dnstracer_error => $dnstracer_error,
		}
	);
}

1;
