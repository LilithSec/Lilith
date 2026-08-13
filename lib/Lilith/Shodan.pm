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
#       banner    => "HTTP/1.1 200 OK\r\n...",   # capped at 4000 characters
#       vulns     => [ 'CVE-2021-23017' ],
#       http      => { title => '...', server => 'nginx', waf => '',
#                      status => 200, components => 'jQuery, Bootstrap',
#                      favicon_hash => -1234567890 },
#       ssl       => { versions => 'TLSv1.2, TLSv1.3', cipher => 'TLS_AES_256_GCM_SHA384 (256 bit)',
#                      jarm => '...', ja3s => '...', cert_subject => 'CN=example.org',
#                      cert_issuer => 'CN=R3, O=Let\'s Encrypt', cert_serial => '...',
#                      cert_expires => '20260901000000Z', cert_expired => 0,
#                      cert_fingerprint => '...' },
#       ssh       => { type => 'ssh-rsa', fingerprint => '...', hassh => '...' },
#     }
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

	my $text = defined $banner->{data} && !ref $banner->{data} ? $banner->{data} : '';
	if ( length($text) > 4000 ) {
		$text = substr( $text, 0, 4000 ) . "\n... (truncated)";
	}

	my $cpes = _list( $banner->{cpe23} );
	$cpes = _list( $banner->{cpe} ) unless @{$cpes};

	my %service = (
		port      => ( defined $banner->{port}      ? $banner->{port} + 0  : 0 ),
		transport => ( defined $banner->{transport} ? $banner->{transport} : '' ),
		module    => ( ref $banner->{_shodan} eq 'HASH' && defined $banner->{_shodan}{module} )
		? $banner->{_shodan}{module}
		: '',
		product   => ( defined $banner->{product}   ? $banner->{product}   : '' ),
		version   => ( defined $banner->{version}   ? $banner->{version}   : '' ),
		timestamp => ( defined $banner->{timestamp} ? $banner->{timestamp} : '' ),
		cpes      => $cpes,
		banner    => $text,
		vulns     => [],
		http      => {},
		ssl       => {},
		ssh       => {},
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
			title      => ( defined $http->{title}  && !ref $http->{title}  ? $http->{title}  : '' ),
			server     => ( defined $http->{server} && !ref $http->{server} ? $http->{server} : '' ),
			waf        => ( defined $http->{waf}    && !ref $http->{waf}    ? $http->{waf}    : '' ),
			status     => ( defined $http->{status} && !ref $http->{status} ? $http->{status} : '' ),
			components =>
				( ref $http->{components} eq 'HASH' ? join( ', ', sort keys %{ $http->{components} } ) : '' ),
			favicon_hash =>
				( ref $http->{favicon} eq 'HASH' && defined $http->{favicon}{hash} ? $http->{favicon}{hash} : '' ),
		};
	} ## end if ( ref $banner->{http} eq 'HASH' )

	if ( ref $banner->{ssl} eq 'HASH' ) {
		my $ssl    = $banner->{ssl};
		my $cert   = ref $ssl->{cert} eq 'HASH'   ? $ssl->{cert}   : {};
		my $cipher = ref $ssl->{cipher} eq 'HASH' ? $ssl->{cipher} : {};

		# Shodan lists the versions it probed, prefixing the ones the service
		# refused with a '-'. Only the supported ones are worth showing.
		my @versions = grep { $_ !~ /^-/ } @{ _list( $ssl->{versions} ) };

		$service{ssl} = {
			versions => join( ', ', @versions ),
			cipher   => (
				defined $cipher->{name}
				? $cipher->{name} . ( defined $cipher->{bits} ? ' (' . $cipher->{bits} . ' bit)' : '' )
				: ''
			),
			jarm             => ( defined $ssl->{jarm} && !ref $ssl->{jarm} ? $ssl->{jarm} : '' ),
			ja3s             => ( defined $ssl->{ja3s} && !ref $ssl->{ja3s} ? $ssl->{ja3s} : '' ),
			cert_subject     => _dn( $cert->{subject} ),
			cert_issuer      => _dn( $cert->{issuer} ),
			cert_serial      => ( defined $cert->{serial}  && !ref $cert->{serial}  ? $cert->{serial}  : '' ),
			cert_expires     => ( defined $cert->{expires} && !ref $cert->{expires} ? $cert->{expires} : '' ),
			cert_expired     => ( $cert->{expired} ? 1 : 0 ),
			cert_fingerprint => (
				ref $cert->{fingerprint} eq 'HASH' && defined $cert->{fingerprint}{sha256}
				? $cert->{fingerprint}{sha256}
				: ''
			),
		};
	} ## end if ( ref $banner->{ssl} eq 'HASH' )

	if ( ref $banner->{ssh} eq 'HASH' ) {
		my $ssh = $banner->{ssh};
		$service{ssh} = {
			type        => ( defined $ssh->{type}        && !ref $ssh->{type}        ? $ssh->{type}        : '' ),
			fingerprint => ( defined $ssh->{fingerprint} && !ref $ssh->{fingerprint} ? $ssh->{fingerprint} : '' ),
			hassh       => ( defined $ssh->{hassh}       && !ref $ssh->{hassh}       ? $ssh->{hassh}       : '' ),
		};
	}

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
		my $transaction = eval {
			my $ua = Mojo::UserAgent->new;
			$ua->connect_timeout(5)->inactivity_timeout(10)->request_timeout(15);
			$ua->get( 'https://internetdb.shodan.io/' . $ip );
		};
		if ( $@ || !$transaction ) {
			my $why = $@ || 'request failed';
			chomp($why);
			return ( undef, 'internetdb: ' . $why );
		}

		if ( my $error = $transaction->error ) {
			my $why = $error->{message} // 'request failed';
			$why .= ' (' . $error->{code} . ')' if $error->{code};

			# As above, a 404 is InternetDB saying it has nothing on the address.
			return ( undef, 'internetdb: ' . $why ) unless ( $error->{code} // 0 ) == 404;
			$raw = {};
		} else {
			$raw = eval { $transaction->res->json };
		}
	} ## end else [ if ( defined $api_key && $api_key ne q{} )]

	return ( ref $raw eq 'HASH' ? $raw : {}, '' );
} ## end sub fetch

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
		os          => ( defined $raw->{os}          && !ref $raw->{os}          ? $raw->{os}          : '' ),
		last_update => ( defined $raw->{last_update} && !ref $raw->{last_update} ? $raw->{last_update} : '' ),

		# who the address belongs to, per Shodan itself: often more specific
		# than whois or the GeoIP ASN database (the customer rather than the
		# carrier), and unlike either of those it can be cached into columns
		# and grouped by. API tier only; the keyless summary carries none.
		org => ( defined $raw->{org} && !ref $raw->{org} ? $raw->{org} : '' ),
		isp => ( defined $raw->{isp} && !ref $raw->{isp} ? $raw->{isp} : '' ),
		asn => ( defined $raw->{asn} && !ref $raw->{asn} ? $raw->{asn} : '' ),

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
		my $stamp = defined $banner->{timestamp} && !ref $banner->{timestamp} ? $banner->{timestamp} : '';
		my $key   = join(
			'|',
			( defined $banner->{port}      && !ref $banner->{port}      ? $banner->{port}      : 0 ),
			( defined $banner->{transport} && !ref $banner->{transport} ? $banner->{transport} : '' ),
			(
				ref $banner->{_shodan} eq 'HASH'
					&& defined $banner->{_shodan}{module} ? $banner->{_shodan}{module} : ''
			)
		);

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

	return \%info;
} ## end sub normalize

=head1 SEE ALSO

L<Lilith>, L<Lilith::CLI::Command::ShodanCache>, L<WWW::Shodan::API>

=cut

1;
