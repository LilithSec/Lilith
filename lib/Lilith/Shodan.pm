package Lilith::Shodan;

use strict;
use warnings;
use Mojo::UserAgent ();

=head1 NAME

Lilith::Shodan - what Shodan knows about an address, in the shape Lilith shows it.

=head1 SYNOPSIS

    use Lilith::Shodan ();

    next if Lilith::Shodan::is_private_ip($ip);

    my $source = Lilith::Shodan::source($api_key);
    my ( $info, $error, $raw ) = Lilith::Shodan::gather( $ip, $api_key, $source );

=head1 DESCRIPTION

The Shodan lookup, split from anything that calls it: the web UI's IP info
modal reaches it through L<Lilith::Web::Controller::Api>, and the
C<lilith shodan_cache> command through L<Lilith::CLI::Command::ShodanCache>.
Neither should have to go through the other.

Everything here is a plain function -- there is no object, and nothing is
exported. C<gather> is the whole lookup; C<fetch> and C<normalize> are its two
halves, separate so a response held in the C<shodan_cache> table can be turned
into the same result a fresh one would give, by the same code.

Nothing here touches the database or dies. Every function blocks on the
network, so the web frontend only ever calls them inside a subprocess.

=head1 FUNCTIONS

=cut

# Which tier a given key selects, as the name a cached row is stored under.
#
# Its own function because more than the fetch has to ask it: the cache has to
# know, before any fetch happens, whether a row it holds was written by the tier
# now configured -- a keyless summary must not stand in for a keyed lookup once
# a key exists.
#
# Args:
#
#   - $api_key :: the configured Shodan key, or '' / undef for none.
#
# Returns: 'api' when there is a key, 'internetdb' when there is not.
#
#     Lilith::Shodan::source('abc123');   # 'api'
#     Lilith::Shodan::source('');         # 'internetdb'
sub source {
	my $api_key = shift;

	return ( defined $api_key && $api_key ne '' ) ? 'api' : 'internetdb';
}
# Addresses that must never be handed to Shodan: the private, loopback,
# link-local, carrier-NAT, multicast, benchmarking, and documentation ranges.
#
# Two reasons, and either alone is enough. Shodan has nothing to say about an
# address that is not on the public internet, so the lookup is wasted; and most
# alerts name an internal address, so without this every analyst clicking "?"
# would be publishing a piece of the internal network map to a third party as a
# side effect.
#
# Plain function, not a method.
#
# Args:
#
#   - $ip :: the address to judge, v4 or v6. Anything this cannot parse as
#     either counts as private, since an address that cannot be understood is
#     not one to hand out.
#
# Returns: 1 when the address must not be looked up, 0 when it is public.
#
#     is_private_ip('10.0.0.5')      # 1
#     is_private_ip('fe80::1')       # 1
#     is_private_ip('198.51.100.7')  # 1 -- documentation range
#     is_private_ip('8.8.8.8')       # 0
sub is_private_ip {
	my $ip = shift;

	return 1 unless defined $ip && $ip ne '';

	if ( $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/ ) {
		my ( $first, $second, $third ) = ( $1 + 0, $2 + 0, $3 + 0 );
		return 1 if $first == 0;                                                         # this network
		return 1 if $first == 10;                                                        # RFC 1918
		return 1 if $first == 127;                                                       # loopback
		return 1 if $first >= 224;                                                       # multicast, reserved, broadcast
		return 1 if $first == 169 && $second == 254;                                     # link local
		return 1 if $first == 172 && $second >= 16 && $second <= 31;                     # RFC 1918
		return 1 if $first == 192 && $second == 168;                                     # RFC 1918
		return 1 if $first == 100 && $second >= 64 && $second <= 127;                    # carrier grade NAT
		return 1 if $first == 198 && ( $second == 18 || $second == 19 );                 # benchmarking
		return 1 if $first == 192 && $second == 0  && ( $third == 0 || $third == 2 );    # assignments, docs
		return 1 if $first == 198 && $second == 51 && $third == 100;                     # documentation
		return 1 if $first == 203 && $second == 0  && $third == 113;                     # documentation
		return 0;
	} ## end if ( $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/)

	if ( $ip =~ /:/ ) {
		my $lower = lc $ip;
		$lower =~ s/%.*\z//;                                                             # drop any scope id
		return 1 if $lower eq '::' || $lower eq '::1';                                   # unspecified, loopback
		return 1 if $lower =~ /^f[cd][0-9a-f]{2}:/;                                      # fc00::/7 unique local
		return 1 if $lower =~ /^fe[89ab][0-9a-f]:/;                                      # fe80::/10 link local
		return 1 if $lower =~ /^ff[0-9a-f]{2}:/;                                         # ff00::/8 multicast
		return 1 if $lower =~ /^2001:0*db8:/;                                            # documentation
		return 0;
	} ## end if ( $ip =~ /:/ )

	return 1;
} ## end sub is_private_ip

# A Shodan field that should hold a list, as one. Shodan omits a field it has
# nothing for rather than sending an empty list, so every read of one has to
# cope with undef; blanks are dropped so the modal never renders an empty chip.
#
# Plain function, not a method.
#
# Args:
#
#   - $value :: whatever the decoded response held at that key, commonly an
#     array ref but just as commonly undef.
#
# Returns: an array ref, empty when there was nothing usable.
#
#     _list( $raw->{tags} )   # [ 'cloud', 'cdn' ]
#     _list( undef )          # []
sub _list {
	my $value = shift;

	return [] unless ref $value eq 'ARRAY';
	return [ grep { defined && $_ ne '' } @{$value} ];
}

# A Shodan field that should hold a plain scalar, as one. Shodan omits fields
# it has nothing for, and a response is not trusted about shape either -- so
# every scalar read of one defaults through here, and a ref can never leak
# into the result.
#
# Plain function, not a method.
#
# Args:
#
#   - $hash :: the hash ref to read from. Anything that is not a hash ref
#     reads as holding nothing, so a possibly-absent parent can be passed
#     without checking it first.
#   - $key :: the field wanted.
#
# Returns: the value, or '' when it is absent or not a plain scalar.
#
#     _str( $http, 'title' )                  # 'Login' or ''
#     _str( $banner->{_shodan}, 'module' )    # parent may be absent
sub _str {
	my ( $hash, $key ) = @_;

	my $value = ref $hash eq 'HASH' ? $hash->{$key} : undef;
	return defined $value && !ref $value ? $value : '';
}

# One certificate name as the usual 'CN=..., O=...' one liner. Shodan sends a
# subject and an issuer as a hash of their DN components, which is not how
# anyone reads a certificate.
#
# CN leads because it is the part being looked at; the rest follow sorted, since
# a hash has no order to preserve and an arbitrary one would only look random.
#
# Plain function, not a method.
#
# Args:
#
#   - $dn :: the component hash, e.g. { CN => 'example.org', O => 'Example Inc',
#     C => 'US' }. Anything that is not a hash ref gives ''.
#
# Returns: the joined string, '' when there was nothing to join.
#
#     _dn( { CN => 'example.org', C => 'US' } )   # 'CN=example.org, C=US'
sub _dn {
	my $dn = shift;

	return '' unless ref $dn eq 'HASH';

	my @parts;
	for my $component ( 'CN', grep { $_ ne 'CN' } sort keys %{$dn} ) {
		my $value = $dn->{$component};
		next unless defined $value && !ref $value && $value ne '';
		push( @parts, $component . '=' . $value );
	}

	return join( ', ', @parts );
} ## end sub _dn

# One GET against a keyless *.shodan.io JSON endpoint, with a 404 taken as an
# empty answer rather than a failure -- both InternetDB and CVEDB answer a
# subject they have nothing on that way. Shared with Lilith::CVEDB, whose
# fetch is deliberately this fetch with a different URL; one copy keeps the
# two from drifting.
#
# Plain function, not a method. Blocking. Nothing here dies.
#
# Args:
#
#   - $url :: the full URL to GET.
#   - $error_label :: what to prefix an error with, naming the service --
#     'internetdb' or 'cvedb'.
#
# Returns: two values, the decoded response and an error string. A 404 or an
# undecodable body comes back as an empty hash ref with no error; a transport
# or HTTP failure as undef with the labelled reason.
#
#     my ( $raw, $error ) = get_json( 'https://internetdb.shodan.io/' . $ip, 'internetdb' );
sub get_json {
	my ( $url, $error_label ) = @_;

	my $transaction = eval {
		my $ua = Mojo::UserAgent->new;
		$ua->connect_timeout(5)->inactivity_timeout(10)->request_timeout(15);
		$ua->get($url);
	};
	if ( $@ || !$transaction ) {
		my $why = $@ || 'request failed';
		chomp($why);
		return ( undef, $error_label . ': ' . $why );
	}

	my $raw;
	if ( my $error = $transaction->error ) {
		my $why = $error->{message} // 'request failed';
		$why .= ' (' . $error->{code} . ')' if $error->{code};

		# a 404 is the service saying it has nothing on the subject
		return ( undef, $error_label . ': ' . $why ) unless ( $error->{code} // 0 ) == 404;
		$raw = {};
	} else {
		$raw = eval { $transaction->res->json };
	}

	return ( ref $raw eq 'HASH' ? $raw : {}, '' );
} ## end sub get_json

# Fold one Shodan 'vulns' value into a CVE => detail hash the caller owns.
#
# Written as a merge rather than a conversion because the same CVE turns up in
# more than one place in a single response -- once in the host's own list, which
# carries no detail, and again under each service it was found on, which does --
# and the modal wants one row per CVE with whatever detail was found anywhere.
#
# The two forms Shodan uses are both accepted: an array of bare CVE ids (the
# host level list, and everything InternetDB sends) and a hash of CVE => detail
# (a service's list). Detail already recorded is never overwritten with a blank,
# so the order the two are folded in does not matter.
#
# Plain function, not a method. Fills a hash the caller owns rather than
# returning one, for the merging above.
#
# Args:
#
#   - $value :: the 'vulns' value, an array ref or a hash ref. Anything else is
#     ignored.
#   - $out :: the hash ref to fill, keyed by CVE id. Each value is
#     { cve => 'CVE-2021-1234', cvss => 9.8, summary => '...', verified => 0 },
#     with '' for a score or summary that was never sent.
#
# Returns: nothing. The result is in $out.
#
#     my %vulns;
#     _add_vulns( $banner->{vulns}, \%vulns );
#     # $vulns{'CVE-2021-1234'}{cvss} is 9.8
sub _add_vulns {
	my ( $value, $out ) = @_;

	my @cves;
	my $detail = {};
	if ( ref $value eq 'ARRAY' ) {
		@cves = @{$value};
	} elsif ( ref $value eq 'HASH' ) {
		@cves   = keys %{$value};
		$detail = $value;
	} else {
		return;
	}

	for my $cve (@cves) {
		next unless defined $cve && !ref $cve && $cve ne '';
		my $entry = $out->{$cve} ||= { cve => $cve, cvss => '', summary => '', verified => 0 };

		my $found = $detail->{$cve};
		next unless ref $found eq 'HASH';
		$entry->{cvss}     = $found->{cvss} + 0 if defined $found->{cvss}    && $found->{cvss} =~ /^[\d.]+$/;
		$entry->{summary}  = $found->{summary}  if defined $found->{summary} && !ref $found->{summary};
		$entry->{verified} = 1                  if $found->{verified};
	} ## end for my $cve (@cves)

	return;
} ## end sub _add_vulns

# One service banner from a host API response, reduced to the fields the modal
# shows.
#
# Only the API tier ever produces these -- InternetDB answers with a summary and
# no banners at all -- so a modal with no service blocks means either the
# keyless tier or a host Shodan has only seen the ports of.
#
# Plain function, not a method.
#
# Args:
#
#   - $banner :: one element of the response's 'data' array.
#
# Returns: a hash ref. The three protocol sections are always present as hashes,
# empty when the banner carried nothing of that kind, so the front end can read
# through them without checking first:
#
#     {
#       port      => 443,
#       transport => 'tcp',
#       module    => 'https',            # the Shodan crawler module that found it
#       product   => 'nginx',
#       version   => '1.18.0',
#       label     => 'nginx 1.18.0',     # what to call it; see below
#       cpes      => [ 'cpe:2.3:a:nginx:nginx:1.18.0:...' ],
#       timestamp => '2026-06-14T02:11:33.123456',
#       hash      => -1524570663,          # Shodan's banner hash, a pivot facet
#       banner    => "HTTP/1.1 200 OK\r\n...",   # capped at 4000 characters
#       vulns     => [ 'CVE-2021-23017' ],
#       http      => { title => '...', server => 'nginx', host => 'example.org',
#                      waf => '', status => 200, components => 'jQuery, Bootstrap',
#                      favicon_hash => -1234567890, html_hash => 12345678,
#                      securitytxt => 0, robots => 1, redirects => 2 },
#       ssl       => { versions => 'TLSv1.2, TLSv1.3', cipher => 'TLS_AES_256_GCM_SHA384 (256 bit)',
#                      jarm => '...', ja3s => '...', cert_subject => 'CN=example.org',
#                      cert_issuer => 'CN=R3, O=Let\'s Encrypt', self_signed => 0,
#                      cert_serial => '...', cert_issued => '20260601000000Z',
#                      cert_expires => '20260901000000Z', cert_expired => 0,
#                      cert_sig_alg => 'sha256WithRSAEncryption', cert_pubkey => 'RSA 2048-bit',
#                      chain_len => 2, dh_bits => '', cert_fingerprint => '...' },
#       ssh       => { type => 'ssh-rsa', fingerprint => '...', hassh => '...',
#                      cipher => 'aes128-ctr', mac => 'hmac-sha2-256' },
#     }
#
# securitytxt and robots are 1/0 presence flags, not the files themselves; html
# and favicon hashes, like the banner hash, are search facets. self_signed is
# derived (subject == issuer). dh_bits is '' rather than 0 on the ECDHE
# handshakes that never negotiate a DH group.
#
# The banner is capped because Shodan stores whatever the service sent, which
# for some HTTP servers is the whole page -- and this one lives in a modal
# beside three other sections.
#
# label is the one display name every renderer of a service block should use --
# the identified product first, then the crawler module that answered, then the
# HTTP server header, empty when none of those are known. Derived here rather
# than by each renderer so the modal's headings and the event view's strip
# cannot drift.
#
#     my $service = _service( $raw->{data}[0] );
#     # $service->{port} is 443, $service->{ssl}{jarm} is the JARM fingerprint
sub _service {
	my $banner = shift;

	my $text = _str( $banner, 'data' );
	if ( length($text) > 4000 ) {
		$text = substr( $text, 0, 4000 ) . "\n... (truncated)";
	}

	my $cpes = _list( $banner->{cpe23} );
	$cpes = _list( $banner->{cpe} ) unless @{$cpes};

	my %service = (
		port      => ( defined $banner->{port} ? $banner->{port} + 0 : 0 ),
		transport => _str( $banner,            'transport' ),
		module    => _str( $banner->{_shodan}, 'module' ),
		product   => _str( $banner,            'product' ),
		version   => _str( $banner,            'version' ),
		timestamp => _str( $banner,            'timestamp' ),

		# Shodan's banner hash: identical services (a cloned panel, a reused
		# stack) share it, so it is a search facet the modal pivots on.
		hash => _str( $banner, 'hash' ),

		cpes   => $cpes,
		banner => $text,
		vulns  => [],
		http   => {},
		ssl    => {},
		ssh    => {},
	);

	# The CVEs this particular service is answerable for, as bare ids -- their
	# scores and summaries are shown once in the host's own vulnerability table
	# rather than repeated under every service.
	if ( ref $banner->{vulns} eq 'HASH' ) {
		$service{vulns} = [ sort keys %{ $banner->{vulns} } ];
	} elsif ( ref $banner->{vulns} eq 'ARRAY' ) {
		$service{vulns} = _list( $banner->{vulns} );
	}

	if ( ref $banner->{http} eq 'HASH' ) {
		my $http = $banner->{http};
		$service{http} = {
			title      => _str( $http, 'title' ),
			server     => _str( $http, 'server' ),
			host       => _str( $http, 'host' ),
			waf        => _str( $http, 'waf' ),
			status     => _str( $http, 'status' ),
			components =>
				( ref $http->{components} eq 'HASH' ? join( ', ', sort keys %{ $http->{components} } ) : '' ),
			favicon_hash => _str( $http->{favicon}, 'hash' ),

			# another pivot facet, like the favicon hash: the whole page's hash,
			# which clones of one deployment share.
			html_hash => _str( $http, 'html_hash' ),

			# presence, not content: both are pages in their own right and the
			# modal only reports that the server serves one.
			securitytxt => ( _str( $http, 'securitytxt' ) ne '' ? 1 : 0 ),
			robots      => ( _str( $http, 'robots' ) ne ''      ? 1 : 0 ),

			# how many hops the crawler was bounced through before the banner --
			# a login page that redirects elsewhere is worth seeing at a glance.
			redirects => ( ref $http->{redirects} eq 'ARRAY' ? scalar @{ $http->{redirects} } : 0 ),
		};
	} ## end if ( ref $banner->{http} eq 'HASH' )

	if ( ref $banner->{ssl} eq 'HASH' ) {
		my $ssl    = $banner->{ssl};
		my $cert   = ref $ssl->{cert} eq 'HASH'   ? $ssl->{cert}   : {};
		my $cipher = ref $ssl->{cipher} eq 'HASH' ? $ssl->{cipher} : {};

		# Shodan lists the versions it probed, prefixing the ones the service
		# refused with a '-'. Only the supported ones are worth showing.
		my @versions = grep { $_ !~ /^-/ } @{ _list( $ssl->{versions} ) };

		my $cert_subject = _dn( $cert->{subject} );
		my $cert_issuer  = _dn( $cert->{issuer} );

		# The public key as 'RSA 2048-bit', from Shodan's { type, bits }. Weak
		# keys (1024-bit RSA) read at a glance where the raw pair would not.
		my $pubkey      = ref $cert->{pubkey} eq 'HASH' ? $cert->{pubkey} : {};
		my $pubkey_type = _str( $pubkey, 'type' );
		my $pubkey_bits = _str( $pubkey, 'bits' );

		$service{ssl} = {
			versions => join( ', ', @versions ),
			cipher   => (
				defined $cipher->{name}
				? $cipher->{name} . ( defined $cipher->{bits} ? ' (' . $cipher->{bits} . ' bit)' : '' )
				: ''
			),
			jarm         => _str( $ssl, 'jarm' ),
			ja3s         => _str( $ssl, 'ja3s' ),
			cert_subject => $cert_subject,
			cert_issuer  => $cert_issuer,

			# subject == issuer is a self-signed certificate: no CA vouches for
			# it, which for anything public-facing is worth a flag of its own.
			self_signed  => ( $cert_subject ne '' && $cert_subject eq $cert_issuer ) ? 1 : 0,
			cert_serial  => _str( $cert, 'serial' ),
			cert_issued  => _str( $cert, 'issued' ),
			cert_expires => _str( $cert, 'expires' ),
			cert_expired => ( $cert->{expired} ? 1 : 0 ),
			cert_sig_alg => _str( $cert, 'sig_alg' ),
			cert_pubkey  => (
				$pubkey_type ne ''
				? uc($pubkey_type) . ( $pubkey_bits ne '' ? ' ' . $pubkey_bits . '-bit' : '' )
				: ''
			),
			cert_fingerprint => _str( $cert->{fingerprint}, 'sha256' ),

			# how many certificates the server presented: a chain of one means no
			# intermediate was sent, which corroborates a self-signed leaf.
			chain_len => scalar @{ _list( $ssl->{chain} ) },

			# Diffie-Hellman parameter size, present only when the handshake used
			# it; under 2048 bits is weak. Absent on the ECDHE handshakes that
			# are now the common case, hence '' rather than 0.
			dh_bits => _str( $ssl->{dhparams}, 'bits' ),
		};
	} ## end if ( ref $banner->{ssl} eq 'HASH' )

	if ( ref $banner->{ssh} eq 'HASH' ) {
		my $ssh = $banner->{ssh};
		$service{ssh} = {
			type        => _str( $ssh, 'type' ),
			fingerprint => _str( $ssh, 'fingerprint' ),
			hassh       => _str( $ssh, 'hassh' ),

			# the negotiated symmetric cipher and MAC, both plain strings (the
			# kex field beside them is the whole algorithm list, not one value);
			# a weak choice here dates an old or misconfigured daemon.
			cipher => _str( $ssh, 'cipher' ),
			mac    => _str( $ssh, 'mac' ),
		};
	} ## end if ( ref $banner->{ssh} eq 'HASH' )

	$service{label}
		= $service{product} ne '' ? $service{product} . ( $service{version} ne '' ? ' ' . $service{version} : '' )
		: $service{module} ne ''  ? $service{module}
		: ( defined $service{http}{server} && $service{http}{server} ne '' ) ? $service{http}{server}
		:                                                                      '';

	return \%service;
} ## end sub _service

# Shodan's view of an address for the IP info modal: what is listening, what it
# is running, and what is known to be wrong with it. None of which the other
# three sections can say -- reverse DNS, whois, and GeoIP between them describe
# who an address belongs to and where it is, not what it does.
#
# Two tiers behind one return shape, chosen by whether a key was configured:
#
#   - with a key :: /shodan/host/{ip} through WWW::Shodan::API, which carries
#     the per-service banners -- product and version per port, TLS certificates
#     with their JARM and JA3S fingerprints, HTTP titles and detected
#     components, and CVEs attributed to the service they were found on. The
#     lookup costs no query credits as long as no search filters are passed,
#     and none are.
#   - without a key :: InternetDB, which needs no account but answers with a
#     summary only: ports, CPEs, hostnames, tags, and bare CVE ids.
#
# The tiers differ in depth, not in shape, so the modal renders whichever it
# got without knowing which it got: the keyless one simply leaves services empty
# and the CVEs without their scores. WWW::Shodan::API is required lazily, so an
# install without it still has the keyless tier.
#
# Blocking HTTP, so it is only ever called inside a Mojo::IOLoop->subprocess.
# Nothing here dies.
#
# Args:
#
#   - $ip :: the address to look up, v4 or v6. Private, reserved, and
#     unparseable addresses are never sent anywhere; see is_private_ip.
#   - $api_key :: the configured Shodan key, or '' for the keyless tier.
#   - $source :: the name of the tier that key selects, from the shodan_source
#     helper. Passed in rather than worked out again here, so the name a cached
#     row is written under and the name it is read back by cannot drift.
#   - $history :: passed through to fetch: ask the host API for every banner
#     it has ever crawled rather than only the current ones, which is what
#     puts a first_seen on the services. Needs a membership plan; see fetch.
#
# Returns: three values -- the result, an error string, and the response the
# result was built from:
#
#     (
#       {
#         source      => 'api',       # or 'internetdb'
#         url         => 'https://www.shodan.io/host/192.0.2.10',
#         last_update => '2026-06-14T02:11:33.123456',   # API tier only
#         os          => 'Linux 3.x',
#         org         => 'Example Hosting LLC',          # API tier only, as
#         isp         => 'Example Carrier Inc',          # are isp and asn
#         asn         => 'AS64496',
#         ports       => [ 22, 80, 443 ],
#         hostnames   => [ 'gate1.example.org' ],
#         domains     => [ 'example.org' ],              # API tier only
#         tags        => [ 'cloud', 'eol-product' ],
#         cpes        => [ 'cpe:2.3:a:nginx:nginx:...' ],
#         vulns       => [ { cve => 'CVE-2021-23017', cvss => 9.8, ... } ],
#         services    => [ { port => 443, ... } ],       # see _service
#         callouts    => [ { text => 'exposed RDP', level => 'danger', key => 'exposed-rdp' } ],  # see _callouts
#         html_hashes       => [ 12345678 ],             # the fingerprint projection
#         cert_fingerprints => [ 'aabbcc...' ],          # deduped across services,
#         banner_hashes     => [ -1524570663 ],          # stored and matched locally
#         products          => [ 'nginx' ],              # distinct product names, no versions
#         port_products     => [ '443 nginx 1.18.0' ],   # the port-to-product pairing, current
#                                                        # ports only; see port_product_map
#       },
#       '',                                              # the error string
#       { ... },                                         # Shodan's own response
#     )
#
# The third is for the cache, which stores what arrived rather than what was
# made of it, so that changing the normalizer does not strand every cached row
# on the old shape. It is undef for a lookup that never happened or failed --
# which is also how the caller knows there is nothing worth caching.
#
# The three ways there is nothing to show are kept apart, because they mean
# different things to whoever is reading the modal. An address Shodan has never
# seen gives the shape above with everything in it empty -- an answer, and a
# useful one. An address that was never asked about gives { skipped => 'why' }
# instead. Only a lookup that actually failed fills the error string, and then
# the result is empty.
#
#     my ( $shodan, $error, $raw ) = gather( '192.0.2.10', $key, 'api' );
#     # $shodan->{ports} is [ 22, 80, 443 ]
#     # $shodan->{services}[2]{ssl}{jarm} is the JARM fingerprint of the 443 service
sub gather {
	my ( $ip, $api_key, $source, $history ) = @_;

	return ( { skipped => 'private or reserved address' }, '' ) if is_private_ip($ip);

	my ( $raw, $error ) = fetch( $ip, $api_key, $history );
	return ( {}, $error ) if $error ne '';

	return ( normalize( $raw, $source, $ip ), '', $raw );
} ## end sub gather

# Ask Shodan about an address, by whichever tier the key selects.
#
# Split from the normalizing half so the cache has something to store: what
# arrives here is what goes in the table, and the normalizer runs over it again
# on the way back out.
#
# Blocking HTTP, so it is only ever called inside a Mojo::IOLoop->subprocess.
# Nothing here dies.
#
# Args:
#
#   - $ip :: the address to look up. Already checked by the caller against
#     is_private_ip, so it is one that may be sent.
#   - $api_key :: the configured Shodan key, or '' for the keyless tier.
#   - $history :: when true, ask the host API for every banner it has ever
#     crawled for the address rather than only the current ones -- what dates
#     when a port first appeared (see normalize's first_seen). Needs a Shodan
#     membership plan, which is why it is its own config switch
#     (shodan_history) rather than implied by the key. History responses are
#     much larger, and are cached whole like everything else. Ignored on the
#     keyless tier, which keeps no history.
#
# Returns: two values, the decoded response and an error string. An address
# Shodan has never crawled is a 404 on both tiers and comes back as an empty
# hash ref with no error, since that is an answer rather than a failure. A
# response that could not be decoded comes back the same way -- there is nothing
# to show either way, and nothing is gained by telling them apart.
#
#     my ( $raw, $error ) = fetch( '192.0.2.10', $key );
sub fetch {
	my ( $ip, $api_key, $history ) = @_;

	my $raw;

	if ( defined $api_key && $api_key ne q{} ) {
		eval {
			require WWW::Shodan::API;
			my $shodan = WWW::Shodan::API->new($api_key);

			# The module builds a plain LWP::UserAgent with LWP's default three
			# minute timeout, which is no timeout at all for something the modal
			# is waiting on.
			$shodan->_ua->timeout(15);

			$raw = $shodan->host_ip( { IP => $ip, ( $history ? ( HISTORY => 1 ) : () ) } );
		};
		if ($@) {
			my $why = $@;
			chomp($why);

			# Shodan answers an address it has never crawled with a 404, which is
			# an answer -- an empty one -- rather than a failure.
			return ( undef, $why ) unless $why =~ /no information available/i;
			$raw = {};
		}
	} else {
		my $error;
		( $raw, $error ) = get_json( 'https://internetdb.shodan.io/' . $ip, 'internetdb' );
		return ( undef, $error ) if !defined $raw;
	}

	return ( ref $raw eq 'HASH' ? $raw : {}, '' );
} ## end sub fetch

# Ports that are a finding in themselves when they answer on the public
# internet: remote access, unauthenticated-by-default datastores, and container
# orchestration control planes. Kept deliberately short -- a port common enough
# to be background noise (FTP, SMTP) would drown the real signal -- so every
# entry here is one an analyst would want called out by name.
#
# Keyed by port, valued by what to call it in the callout.
my %EXPOSED_PORT = (
	23    => 'Telnet',
	445   => 'SMB',
	1433  => 'MSSQL',
	2375  => 'Docker API',
	2379  => 'etcd',
	3306  => 'MySQL',
	3389  => 'RDP',
	5432  => 'PostgreSQL',
	5900  => 'VNC',
	5984  => 'CouchDB',
	6379  => 'Redis',
	9200  => 'Elasticsearch',
	10250 => 'Kubelet',
	11211 => 'Memcached',
	27017 => 'MongoDB',
);

# The plain-language findings drawn out of an already-normalized result: the
# things an analyst wants at the top of the modal rather than reconstructed from
# a port list and a row of certificate fields. Descriptive, not exhaustive --
# what is wrong with the host, in the words for it.
#
# Pure, and derived entirely from what normalize has already built, so it stays
# in step with the modal without a second read of the raw. Nothing here needs
# the clock; the one time-relative finding (a certificate not yet expired but
# nearly) is added by the controller, which has the clock and the freshness
# rules, so this function can stay pure and testable.
#
# Plain function, not a method.
#
# Args:
#
#   - $info :: the result hash normalize is building, read after its ports,
#     services, and tags are set. Its services carry the ssl fields _service
#     produced (self_signed, cert_expired, versions); its tags are Shodan's own.
#
# Returns: an array ref of findings, each { text => 'exposed RDP', level =>
# 'danger' | 'warning', key => 'exposed-rdp' }, danger first so the exposed
# services lead. Empty when nothing stood out. text is what the modal shows;
# key is the stable token the /shodan browser filters on and shodan_cache_put
# stores, so the display wording can change without stranding a filter.
#
#     my $callouts = _callouts( \%info );
#     # $callouts->[0] is { text => 'exposed MongoDB', level => 'danger', key => 'exposed-mongodb' }
sub _callouts {
	my $info = shift;

	my @danger;
	for my $port ( @{ $info->{ports} } ) {
		next unless $EXPOSED_PORT{$port};

		# a stable filter token for the /shodan browser: 'Docker API' -> 'exposed-docker-api'
		( my $slug = lc $EXPOSED_PORT{$port} ) =~ s/[^a-z0-9]+/-/g;
		$slug =~ s/^-+|-+$//g;
		push( @danger, { text => 'exposed ' . $EXPOSED_PORT{$port}, level => 'danger', key => 'exposed-' . $slug } );
	}

	# The certificate and TLS weaknesses are gathered across every service and
	# each reported once, rather than once per port that shares the fault.
	my %weak_tls;
	my $self_signed = 0;
	my $expired     = 0;
	for my $service ( @{ $info->{services} } ) {
		my $ssl = $service->{ssl};
		next unless ref $ssl eq 'HASH';
		$self_signed = 1 if $ssl->{self_signed};
		$expired     = 1 if $ssl->{cert_expired};

		# SSLv2/3 and TLS 1.0/1.1 are the deprecated ones; the versions string is
		# what _service already dropped the refused protocols from.
		my $versions = defined $ssl->{versions} ? $ssl->{versions} : '';
		while ( $versions =~ /(SSLv[23]|TLSv1\.[01])\b/g ) { $weak_tls{$1} = 1; }
	} ## end for my $service ( @{ $info->{services} } )

	my @warning;
	push( @warning,
		{ text => 'weak TLS (' . join( ', ', sort keys %weak_tls ) . ')', level => 'warning', key => 'weak-tls' } )
		if %weak_tls;
	push( @warning, { text => 'self-signed certificate', level => 'warning', key => 'self-signed' } )  if $self_signed;
	push( @warning, { text => 'expired certificate',     level => 'warning', key => 'expired-cert' } ) if $expired;

	# End-of-life software, from the tags Shodan already sets -- promoted out of
	# the grey tag row into a finding, since "runs software past its support" is
	# exactly what the callouts are for.
	my %tag = map { $_ => 1 } @{ $info->{tags} };
	push( @warning, { text => 'end-of-life OS',      level => 'warning', key => 'eol-os' } ) if $tag{'eol-os'};
	push( @warning, { text => 'end-of-life product', level => 'warning', key => 'eol-product' } )
		if $tag{'eol-product'};

	return [ @danger, @warning ];
} ## end sub _callouts

# One Shodan response, reduced to what the IP info modal shows.
#
# Separate from the fetch so that a cached response goes through exactly the
# same reduction a fresh one does -- which is the whole reason the cache stores
# what arrived rather than what was made of it. A change here takes effect on
# every cached row at once instead of only on rows written afterwards.
#
# Pure -- no network, no database. Plain function, not a method.
#
# Args:
#
#   - $raw :: the decoded response, as fetch returns it. An empty hash
#     ref gives the full result shape with nothing in it, which is what an
#     address Shodan has never crawled comes to.
#   - $source :: which tier answered, 'api' or 'internetdb'. Recorded as-is so
#     the modal can say how deep an answer it is looking at.
#   - $ip :: the address, for building the shodan.io link.
#
# Returns: a hash ref of the shape documented on gather.
#
# Vulnerabilities are sorted worst first, by CVSS and then by id, so the CVE
# worth reading is the one at the top rather than whichever sorts first
# alphabetically. Services are sorted by port.
#
#     my $info = normalize( $raw, 'api', '192.0.2.10' );
#     # $info->{vulns}[0] is the highest scored CVE on the host
sub normalize {
	my ( $raw, $source, $ip ) = @_;

	$raw = {} unless ref $raw eq 'HASH';

	my %info = (
		source      => $source,
		url         => 'https://www.shodan.io/host/' . $ip,
		os          => _str( $raw, 'os' ),
		last_update => _str( $raw, 'last_update' ),

		# who the address belongs to, per Shodan itself: often more specific
		# than whois or the GeoIP ASN database (the customer rather than the
		# carrier), and unlike either of those it can be cached into columns
		# and grouped by. API tier only; the keyless summary carries none.
		org => _str( $raw, 'org' ),
		isp => _str( $raw, 'isp' ),
		asn => _str( $raw, 'asn' ),

		hostnames => _list( $raw->{hostnames} ),
		domains   => _list( $raw->{domains} ),
		tags      => _list( $raw->{tags} ),
		ports     => [ sort { $a <=> $b } @{ _list( $raw->{ports} ) } ],
	);

	my %vulns;
	_add_vulns( $raw->{vulns}, \%vulns );

	# CPEs come from the host level on the keyless tier and from the individual
	# banners on the API one, so both are collected and merged.
	my %cpes = map { $_ => 1 } @{ _list( $raw->{cpes} ) };

	# One service per port/transport/module, the newest banner standing for the
	# group. On an ordinary response that is every banner exactly as it
	# arrived; a history response (see fetch) carries the same service once per
	# crawl, and collapsing to the newest keeps the modal describing it as it
	# stands -- while the group's oldest sighting rides along as first_seen,
	# which is what dates when a port first appeared.
	my %service_group;
	for my $banner ( @{ _list( $raw->{data} ) } ) {
		next unless ref $banner eq 'HASH';
		my $stamp = _str( $banner, 'timestamp' );
		my $key   = join( '|',
			( _str( $banner, 'port' ) || 0 ),
			_str( $banner,            'transport' ),
			_str( $banner->{_shodan}, 'module' ) );

		my $slot = $service_group{$key} ||= { banner => $banner, stamp => $stamp, first_seen => $stamp };

		# the stamps are ISO, so they compare lexically
		if ( $stamp gt $slot->{stamp} ) {
			@{$slot}{qw( banner stamp )} = ( $banner, $stamp );
		}
		$slot->{first_seen} = $stamp if $stamp ne '' && ( $slot->{first_seen} eq '' || $stamp lt $slot->{first_seen} );
	} ## end for my $banner ( @{ _list( $raw->{data} ) })

	my @services;
	my %current_port = map { $_ => 1 } @{ $info{ports} };
	for my $slot ( values %service_group ) {
		my $service = _service( $slot->{banner} );
		$service->{first_seen} = $slot->{first_seen};
		push( @services, $service );

		# The host-level lists describe the host as it stands, so only the
		# services on its current ports feed them: a history response also
		# carries banners for ports since closed, whose old CVEs and CPEs must
		# not resurface as the host's. With no host-level port list there is
		# no "current" to hold to, and every banner counts, as before.
		next if %current_port && !$current_port{ $service->{port} };
		_add_vulns( $slot->{banner}{vulns}, \%vulns );
		$cpes{$_} = 1 for @{ $service->{cpes} };
	} ## end for my $slot ( values %service_group )
	$info{services}
		= [ sort { $a->{port} <=> $b->{port} || $a->{transport} cmp $b->{transport} || $a->{module} cmp $b->{module} }
			@services ];

	# A response can carry banners without a host level port list; deriving the
	# ports from them keeps the chips from being the one thing missing.
	unless ( @{ $info{ports} } ) {
		my %ports = map { $_->{port} => 1 } grep { $_->{port} } @services;
		$info{ports} = [ sort { $a <=> $b } keys %ports ];
	}

	$info{cpes}  = [ sort keys %cpes ];
	$info{vulns} = [
		sort {
			( $b->{cvss} eq '' ? -1 : $b->{cvss} ) <=> ( $a->{cvss} eq '' ? -1 : $a->{cvss} )
				|| $a->{cve} cmp $b->{cve}
		} values %vulns
	];

	# The service fingerprints, deduplicated across services, as the queryable
	# projection shodan_cache_put stores and the neighborhood panel matches on:
	# a host commonly presents one panel or certificate on several ports, and
	# that is one fingerprint, not one per port.
	my ( %html_hash, %cert_fp, %banner_hash, %product, %port_product );
	my %open_port = map { $_ => 1 } @{ $info{ports} };
	for my $service ( @{ $info{services} } ) {
		my $html = $service->{http}{html_hash};
		$html_hash{$html} = 1 if defined $html && $html ne '' && $html ne '0';
		my $cert = $service->{ssl}{cert_fingerprint};
		$cert_fp{$cert} = 1 if defined $cert && $cert ne '';
		my $banner = $service->{hash};
		$banner_hash{$banner} = 1 if defined $banner && $banner ne '' && $banner ne '0';

		# the product name only; the version rides along per-service and is not
		# what a "which hosts run nginx" facet groups by.
		my $name = $service->{product};
		next unless defined $name && $name ne '';
		$product{$name} = 1;

		# the pairing too, since the flat list cannot say which port runs what.
		# 'PORT product version', one per distinct pair (both transports of a
		# port commonly carry the same banner, and that is one pairing). Current
		# ports only, so a history response's since-closed services do not
		# annotate a port list they are no longer on.
		next unless $open_port{ $service->{port} };
		my $pairing = $service->{port} . ' ' . $name . ( $service->{version} ne '' ? ' ' . $service->{version} : '' );
		$port_product{$pairing} = $service->{port};
	} ## end for my $service ( @{ $info{services} } )
	$info{html_hashes}       = [ sort { $a <=> $b } keys %html_hash ];
	$info{cert_fingerprints} = [ sort keys %cert_fp ];
	$info{banner_hashes}     = [ sort { $a <=> $b } keys %banner_hash ];
	$info{products}          = [ sort keys %product ];
	$info{port_products}
		= [ sort { $port_product{$a} <=> $port_product{$b} || $a cmp $b } keys %port_product ];

	# The plain-language findings, drawn from everything just built. Last, so it
	# reads ports, services, and tags in their final form.
	$info{callouts} = _callouts( \%info );

	return \%info;
} ## end sub normalize

# The port_products list back as a per-port lookup, for annotating a port list
# with what runs on each. The one reader of the format normalize writes (and
# shodan_cache stores), so the two cannot drift apart in separate template
# copies.
#
# Plain function, not a method.
#
# Args:
#
#   - $port_products :: an array ref of 'PORT product version' strings, as
#     normalize's port_products or the shodan_cache column. Anything else
#     (undef, a non-ref, a malformed entry) is ignored rather than died on,
#     since a row from before schema 20 hands in undef.
#
# Returns: a hash ref keyed by port number. Each value is the product (with
# its version when one was identified), several on one port joined with ' / '.
# A port nothing was identified on is simply absent. Empty hash ref when there
# is nothing to correlate.
#
#     my $products_by_port = port_product_map( [ '443 nginx 1.18.0' ] );
#     # $products_by_port->{443} is 'nginx 1.18.0'
sub port_product_map {
	my $port_products = shift;

	my %map;
	return \%map unless ref $port_products eq 'ARRAY';

	for my $pairing ( @{$port_products} ) {
		next unless defined $pairing && !ref $pairing;
		my ( $port, $label ) = $pairing =~ /^([0-9]+) (.+)$/;
		next unless defined $label;
		$map{$port} = defined $map{$port} ? $map{$port} . ' / ' . $label : $label;
	}

	return \%map;
} ## end sub port_product_map

# A count facet, as the [ { value, count } ] list the modal renders, sorted the
# way Shodan already returns it (most common first). Shodan sends each facet as
# an array of { count, value }, but omits a facet it has nothing for -- so every
# read of one has to cope with the key being absent.
#
# Plain function, not a method.
#
# Args:
#
#   - $facets :: the response's 'facets' value, a hash ref keyed by facet name.
#     Anything that is not a hash ref reads as holding nothing.
#   - $key :: the facet wanted, e.g. 'port'.
#
# Returns: an array ref of { value => ..., count => ... }, empty when the facet
# was absent or malformed. Values are left as Shodan typed them (a port is a
# number, a product a string); counts are forced numeric.
#
#     _facet( $raw->{facets}, 'port' )   # [ { value => 443, count => 1200 }, ... ]
sub _facet {
	my ( $facets, $key ) = @_;

	my $list = ref $facets eq 'HASH' ? $facets->{$key} : undef;
	return [] unless ref $list eq 'ARRAY';

	my @out;
	for my $entry ( @{$list} ) {
		next unless ref $entry eq 'HASH' && defined $entry->{value};
		push( @out, { value => $entry->{value}, count => ( ( $entry->{count} // 0 ) + 0 ) } );
	}

	return \@out;
} ## end sub _facet

# A value safe to splice into a Shodan search query, or '' when there is none.
# The count queries are built from Shodan's own data about the host -- an org
# name, a hash, a certificate serial -- none of which is trusted for shape, and
# all of which is about to become part of a query string. A stray quote or space
# would at best break the query and at worst change what it matches, so anything
# outside a conservative set is dropped rather than escaped.
#
# Plain function, not a method.
#
# Args:
#
#   - $value :: the raw value.
#   - $quote :: when true, the cleaned value is wrapped in double quotes for a
#     phrase match (what an org name with spaces needs); when false it is left
#     bare (what a single-token hash or serial needs).
#
# Returns: the query-safe fragment, or '' when nothing usable was left.
#
#     _query_value( 'Example Hosting LLC', 1 )   # '"Example Hosting LLC"'
#     _query_value( -1524570663, 0 )             # '-1524570663'
sub _query_value {
	my ( $value, $quote ) = @_;

	return '' unless defined $value && !ref $value;

	if ($quote) {

		# a phrase: keep spaces, drop only what would break out of the quotes
		( my $clean = $value ) =~ s/["\\\r\n]//g;
		$clean =~ s/^\s+|\s+$//g;
		return $clean eq '' ? '' : '"' . $clean . '"';
	}

	# a single token: only the characters a hash, serial, or fingerprint uses
	return $value =~ /^-?[\w:.-]+$/ ? $value : '';
} ## end sub _query_value

# How many hosts Shodan sees matching the neighborhood of an address: the org it
# belongs to, and the fingerprints its services carry. The count endpoint costs
# no query credits and returns no host detail, only totals and facets -- which
# is all the modal's neighborhood panel wants, and is why this is separate from
# the per-host gather.
#
# Two kinds of question, both answered by /shodan/host/count:
#
#   - the org :: one count of org:"..." faceted by port, product, and vuln --
#     what the rest of this owner's internet-facing fleet is running. Only as
#     useful as the org is specific; a hosting provider's org is every kind of
#     host at once, which the caller is left to judge from the total.
#   - each fingerprint :: one bare count per html hash, certificate, or banner
#     hash the host presents -- how much else on the internet shares that exact
#     panel or TLS stack, which clusters reused infrastructure the org never
#     could.
#
# API tier only: the count endpoint needs a key, and the tag facet it would most
# want is plan-gated, so this asks only for the facets a Freelancer key answers.
# Blocking HTTP throughout -- one request per count, paced a second apart for the
# rate limit, so it is only ever called inside a subprocess. Nothing here dies.
#
# Args:
#
#   - $org :: the host's org string, or '' to skip the org count.
#   - $fingerprints :: an array ref of { label, filter, value } to count one
#     apiece, e.g. { label => 'HTML hash', filter => 'http.html_hash',
#     value => 12345678 }. filter is the Shodan search filter; value is spliced
#     through _query_value, so an unusable one is simply skipped.
#   - $api_key :: the configured key. Required; '' returns an error.
#   - $limit :: the most fingerprint counts to actually run, since each is a
#     paced request. Default 6. Any past it are reported as skipped rather than
#     run, so a host with many services does not stall the panel.
#
# Returns: three values -- the result, an error string, and the number of
# fingerprints skipped for the limit:
#
#     (
#       {
#         org => {                                   # undef when org was ''
#           query    => 'Example Hosting LLC',
#           total    => 1240,
#           ports    => [ { value => 443, count => 900 }, ... ],
#           products => [ { value => 'nginx', count => 410 }, ... ],
#           vulns    => [ { value => 'CVE-2021-23017', count => 88 }, ... ],
#         },
#         fingerprints => [
#           { label => 'HTML hash', filter => 'http.html_hash',
#             value => 12345678, total => 37 },
#         ],
#       },
#       '',     # error string, set only on a transport/HTTP failure
#       0,      # fingerprints skipped for the limit
#     )
#
# A count that fails stops the run and fills the error; the partial result so
# far still rides back, so one bad fingerprint does not lose the org count.
#
#     my ( $near, $error ) = neighborhood_count( 'Example Hosting LLC', \@fp, $key );
#     # $near->{org}{total} is how many hosts Shodan sees in that org
sub neighborhood_count {
	my ( $org, $fingerprints, $api_key, $limit ) = @_;

	return ( {}, 'neighborhood count needs a Shodan API key', 0 )
		unless defined $api_key && $api_key ne '';

	$limit        = 6  unless defined $limit && $limit =~ /^[0-9]+$/;
	$fingerprints = [] unless ref $fingerprints eq 'ARRAY';

	my $shodan = eval {
		require WWW::Shodan::API;
		my $client = WWW::Shodan::API->new($api_key);
		$client->_ua->timeout(15);
		$client;
	};
	return ( {}, 'WWW::Shodan::API: ' . _trim($@), 0 ) if $@ || !$shodan;

	my %result = ( org => undef, fingerprints => [] );
	my $first  = 1;

	# The org count, faceted. _query_value quotes it, since an org name is a
	# phrase; an org that cleans away to nothing simply skips the count.
	my $org_query = _query_value( $org, 1 );
	if ( $org_query ne '' ) {
		my $raw
			= eval { $shodan->count( { org => $org_query }, [ { port => 10 }, { product => 10 }, { vuln => 10 } ] ); };
		return ( \%result, 'org count: ' . _trim($@), 0 ) if $@;
		$first = 0;

		$result{org} = {
			query    => $org,
			total    => ( ref $raw eq 'HASH' && defined $raw->{total} ? $raw->{total} + 0 : 0 ),
			ports    => _facet( ref $raw eq 'HASH' ? $raw->{facets} : undef, 'port' ),
			products => _facet( ref $raw eq 'HASH' ? $raw->{facets} : undef, 'product' ),
			vulns    => _facet( ref $raw eq 'HASH' ? $raw->{facets} : undef, 'vuln' ),
		};
	} ## end if ( $org_query ne '' )

	# The fingerprint counts, one bare total apiece, capped at the limit.
	my $run     = 0;
	my $skipped = 0;
	for my $fp ( @{$fingerprints} ) {
		next unless ref $fp eq 'HASH';
		my $value = _query_value( $fp->{value}, 0 );
		next if $value eq '' || !defined $fp->{filter} || $fp->{filter} eq '';

		if ( $run >= $limit ) {
			$skipped++;
			next;
		}

		# the rate limit is about a request a second; pace all but the first
		sleep(1) unless $first;
		$first = 0;
		$run++;

		my $raw = eval { $shodan->count( { $fp->{filter} => $value }, [] ); };
		return ( \%result, 'fingerprint count (' . $fp->{filter} . '): ' . _trim($@), $skipped ) if $@;

		push(
			@{ $result{fingerprints} },
			{
				label  => ( defined $fp->{label} ? $fp->{label} : $fp->{filter} ),
				filter => $fp->{filter},
				value  => $fp->{value},
				total  => ( ref $raw eq 'HASH' && defined $raw->{total} ? $raw->{total} + 0 : 0 ),
			}
		);
	} ## end for my $fp ( @{$fingerprints} )

	return ( \%result, '', $skipped );
} ## end sub neighborhood_count

# An error string with its trailing whitespace stripped, or a stand-in when it
# was empty -- so a failure never comes back as a blank the caller reads as
# success. Plain function, not a method.
#
# Args:
#
#   - $error :: the caught $@, or anything stringifiable.
#
# Returns: the trimmed string, or 'request failed' when there was nothing.
#
#     _trim("boom\n")   # 'boom'
sub _trim {
	my $error = shift;
	my $why   = defined $error ? "$error" : '';
	$why =~ s/\s+\z//;
	return $why eq '' ? 'request failed' : $why;
}

=head1 SEE ALSO

L<Lilith>, L<Lilith::CLI::Command::ShodanCache>, L<WWW::Shodan::API>

=cut

1;
