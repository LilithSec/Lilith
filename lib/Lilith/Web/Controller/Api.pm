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

1;
