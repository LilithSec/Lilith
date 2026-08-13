package Lilith::CVEDB;

use strict;
use warnings;
use Lilith::Shodan ();

=head1 NAME

Lilith::CVEDB - what CVEDB knows about a CVE, in the shape Lilith shows it.

=head1 SYNOPSIS

    use Lilith::CVEDB ();

    next unless Lilith::CVEDB::is_cve_id($id);

    my ( $info, $error, $raw ) = Lilith::CVEDB::gather($id);

=head1 DESCRIPTION

The CVEDB lookup, split from anything that calls it, the same way
L<Lilith::Shodan> is: the C<lilith cvedb_cache> command reaches it through
L<Lilith::CLI::Command::CvedbCache>, and nothing else asks the network at all
-- the web UI reads only the C<cvedb_cache> table.

CVEDB (L<https://cvedb.shodan.io>) is Shodan's free CVE database and needs no
key or account. Per CVE it carries the parts of a vulnerability's record that
change what it means in triage: the CVSS score, the EPSS exploitation
probability, whether it is on the CISA KEV list, and whether it is known to be
used in ransomware campaigns.

Everything here is a plain function -- there is no object, and nothing is
exported. C<gather> is the whole lookup; C<fetch> and C<normalize> are its two
halves, separate so a response held in the C<cvedb_cache> table can be turned
into the same result a fresh one would give, by the same code.

Nothing here touches the database or dies. C<fetch> blocks on the network.

=head1 FUNCTIONS

=cut

# Whether a string is a CVE id in its canonical form, and so one worth asking
# CVEDB about. The gate every id passes before it goes anywhere near the
# network: the ids come out of Shodan responses and ruleset metadata, which is
# to say out of other people's data, and an id that is not understood is not
# one to send anywhere -- the same reasoning as Lilith::Shodan::is_private_ip.
#
# Plain function, not a method.
#
# Args:
#
#   - $id :: the string to judge, e.g. 'CVE-2021-44228'. The canonical
#     uppercase form only, which is the form Shodan and CVEDB themselves use.
#
# Returns: 1 when it is a CVE id, 0 when it is not.
#
#     is_cve_id('CVE-2021-44228')   # 1
#     is_cve_id('cve-2021-44228')   # 0 -- not the canonical form
#     is_cve_id('GHSA-jfh8-c2jp')   # 0
sub is_cve_id {
	my $id = shift;

	return 0 unless defined $id && !ref $id;
	return $id =~ /^CVE-[0-9]{4}-[0-9]{4,}$/ ? 1 : 0;
}

# The CVE ids a rule names, in canonical form, from a decoded EVE record.
#
# Rulesets write them into alert.metadata.cve in several shapes --
# 'CVE_2021_44228', 'cve-2021-44228', a bare '2021-44228' -- and often only
# into the signature text, so both are read and everything is normalized to
# 'CVE-YYYY-NNNN'. Anything that does not normalize to an id is dropped rather
# than guessed at.
#
# This is the same extraction as the suricata_alert_cves SQL function, which
# fills the suricata_alerts.cves generated column for the code paths that must
# match in SQL; this one is for code already holding a decoded row. Change one
# and change the other.
#
# Pure -- no network, no database. Plain function, not a method.
#
# Args:
#
#   - $raw :: the decoded EVE record as a hash ref, as the event view holds it
#     or as decoding a search row's raw column gives it. Only
#     alert.metadata.cve (array or single string) and alert.signature are
#     read. Anything unusable -- undef, a non-hash, a record with no alert --
#     yields an empty list rather than an error.
#
# Returns: an array ref of the ids, deduplicated and sorted. Empty when the
# rule names none.
#
#     my $cves = rule_cves($raw);
#     # [ 'CVE-2021-44228', 'CVE-2021-45046' ]
sub rule_cves {
	my $raw = shift;

	return [] unless ref $raw eq 'HASH' && ref $raw->{alert} eq 'HASH';
	my $alert = $raw->{alert};

	my @candidates;

	my $metadata_cve = ref $alert->{metadata} eq 'HASH' ? $alert->{metadata}{cve} : undef;
	if ( ref $metadata_cve eq 'ARRAY' ) {
		push( @candidates, grep { defined && !ref } @{$metadata_cve} );
	} elsif ( defined $metadata_cve && !ref $metadata_cve ) {
		push( @candidates, $metadata_cve );
	}

	my %found;
	foreach my $candidate (@candidates) {
		$candidate = uc($candidate);
		$candidate =~ tr/_/-/;
		if ( $candidate =~ /^(?:CVE-)?([0-9]{4}-[0-9]{4,})$/ ) {
			$found{ 'CVE-' . $1 } = 1;
		}
	}

	my $signature = defined $alert->{signature} && !ref $alert->{signature} ? uc( $alert->{signature} ) : '';
	while ( $signature =~ /CVE[-_ ]?([0-9]{4})[-_]([0-9]{4,})/g ) {
		$found{ 'CVE-' . $1 . '-' . $2 } = 1;
	}

	return [ sort keys %found ];
} ## end sub rule_cves

# Ask CVEDB about a CVE.
#
# Split from the normalizing half so the cache has something to store: what
# arrives here is what goes in the table, and the normalizer runs over it
# again on the way back out.
#
# The one thing removed before the response is handed back is its 'cpes' list.
# Nothing in Lilith displays it, and for a widely deployed product's CVE it is
# most of the payload -- Log4Shell's runs to thousands of entries. Dropping it
# here rather than at store time keeps "what fetch returns" and "what the
# cache holds" the same thing.
#
# Blocking HTTP. Nothing here dies.
#
# Args:
#
#   - $cve :: the id to look up. Already checked by the caller against
#     is_cve_id, so it is one that may be sent.
#
# Returns: two values, the decoded response and an error string. An id CVEDB
# has nothing on is a 404 and comes back as an empty hash ref with no error,
# since that is an answer rather than a failure. A response that could not be
# decoded comes back the same way.
#
#     my ( $raw, $error ) = fetch('CVE-2021-44228');
sub fetch {
	my $cve = shift;

	# the GET itself, with its 404-is-an-answer handling, is shared with the
	# InternetDB fetch in Lilith::Shodan -- the two endpoints behave the same
	my ( $raw, $error ) = Lilith::Shodan::get_json( 'https://cvedb.shodan.io/cve/' . $cve, 'cvedb' );
	return ( undef, $error ) if !defined $raw;

	delete $raw->{cpes};

	return ( $raw, '' );
} ## end sub fetch

# One CVEDB response, reduced to what Lilith shows and stores beside it.
#
# Separate from the fetch so that a cached response goes through exactly the
# same reduction a fresh one does. Pure -- no network, no database. Plain
# function, not a method.
#
# Args:
#
#   - $raw :: the decoded response, as fetch returns it. An empty hash ref
#     gives the full result shape with nothing in it, which is what an id
#     CVEDB has nothing on comes to.
#
# Returns: a hash ref:
#
#     {
#       cvss       => 9.8,        # '' when never scored
#       epss       => 0.94321,    # exploitation probability, '' when absent
#       kev        => 1,          # on the CISA Known Exploited Vulns list
#       ransomware => 1,          # known use in ransomware campaigns
#       summary    => '...',
#       published  => '2021-12-10T10:15:09',
#     }
#
# CVEDB reports up to three CVSS versions plus its own preferred 'cvss'
# field; that field is taken first, then v3, then v2, so the score shown is
# the best one the record carries rather than whichever version happened to
# be filled in.
#
#     my $info = normalize($raw);
#     # $info->{kev} is 1 for anything CISA has seen exploited
sub normalize {
	my $raw = shift;

	$raw = {} unless ref $raw eq 'HASH';

	my $cvss = '';
	for my $field (qw( cvss cvss_v3 cvss_v2 )) {
		next unless defined $raw->{$field} && !ref $raw->{$field} && $raw->{$field} =~ /^[0-9.]+$/;
		$cvss = $raw->{$field} + 0;
		last;
	}

	my $epss
		= ( defined $raw->{epss} && !ref $raw->{epss} && $raw->{epss} =~ /^[0-9.]+$/ )
		? $raw->{epss} + 0
		: '';

	# ransomware_campaign is a string ('Known') rather than a flag, and absent
	# when there is nothing to say.
	my $ransomware
		= (    defined $raw->{ransomware_campaign}
			&& !ref $raw->{ransomware_campaign}
			&& $raw->{ransomware_campaign} ne '' )
		? 1
		: 0;

	return {
		cvss       => $cvss,
		epss       => $epss,
		kev        => ( $raw->{kev} ? 1 : 0 ),
		ransomware => $ransomware,
		summary    => ( defined $raw->{summary} && !ref $raw->{summary} ? $raw->{summary} : '' ),
		published  =>
			( defined $raw->{published_time} && !ref $raw->{published_time} ? $raw->{published_time} : '' ),
	};
} ## end sub normalize

# CVEDB's record for one CVE: the whole lookup, as the cvedb_cache command
# uses it.
#
# Blocking HTTP by way of fetch. Nothing here dies.
#
# Args:
#
#   - $cve :: the id to look up. Anything is_cve_id rejects is never sent
#     anywhere.
#
# Returns: three values -- the result, an error string, and the response the
# result was built from:
#
#     (
#       { cvss => 9.8, epss => 0.94, kev => 1, ... },   # see normalize
#       '',                                             # the error string
#       { ... },                                        # CVEDB's own response
#     )
#
# The third is for the cache, which stores what arrived rather than what was
# made of it, so that changing the normalizer does not strand every cached row
# on the old shape. It is undef for a lookup that never happened or failed --
# which is also how the caller knows there is nothing worth caching.
#
# The three ways there is nothing to show are kept apart, the same as in
# Lilith::Shodan::gather: an id CVEDB has nothing on gives the shape above
# with everything in it empty -- an answer worth caching. An id that was never
# asked about gives { skipped => 'why' } instead. Only a lookup that actually
# failed fills the error string, and then the result is empty.
#
#     my ( $info, $error, $raw ) = gather('CVE-2021-44228');
#     # $info->{kev} is 1
sub gather {
	my $cve = shift;

	return ( { skipped => 'not a CVE id' }, '' ) unless is_cve_id($cve);

	my ( $raw, $error ) = fetch($cve);
	return ( {}, $error ) if $error ne '';

	return ( normalize($raw), '', $raw );
} ## end sub gather

=head1 SEE ALSO

L<Lilith>, L<Lilith::CLI::Command::CvedbCache>, L<Lilith::Shodan>

=cut

1;
