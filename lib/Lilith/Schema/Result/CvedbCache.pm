use utf8;

package Lilith::Schema::Result::CvedbCache;

=head1 NAME

Lilith::Schema::Result::CvedbCache

=head1 DESCRIPTION

What Shodan's free CVEDB last said about a CVE, so the ids C<shodan_cache> and
the rulesets name can be annotated -- CVSS, EPSS, the CISA KEV flag, known
ransomware use -- without asking per render. One row per CVE, keyed on C<cve>.

C<raw> is the CVEDB response as it arrived, minus its C<cpes> list -- the one
field nothing displays, and for a CVE like Log4Shell most of the payload. The
columns beside it are the parts worth querying without opening the JSON.
C<found> is false for an id CVEDB has nothing on, cached deliberately so it is
not re-asked every run.

Unlike C<shodan_cache> there is no freshness gate on reads: CVE detail only
firms up, so the web serves whatever row exists however old, and C<fetched> is
read only by C<lilith cvedb_cache> to pick what to refresh.

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<cvedb_cache>

=cut

__PACKAGE__->table("cvedb_cache");

=head1 ACCESSORS

=head2 cve

  data_type: 'varchar'
  is_nullable: 0
  size: 32

=head2 found

  data_type: 'boolean'
  is_nullable: 0

=head2 fetched

  data_type: 'timestamp with time zone'
  is_nullable: 0

=head2 cvss

  data_type: 'numeric'
  is_nullable: 1
  size: [3,1]

=head2 epss

  data_type: 'numeric'
  is_nullable: 1
  size: [6,5]

=head2 kev

  data_type: 'boolean'
  is_nullable: 1

=head2 ransomware

  data_type: 'boolean'
  is_nullable: 1

=head2 raw

  data_type: 'jsonb'
  is_nullable: 1

=cut

__PACKAGE__->add_columns(
	"cve",        { data_type => "varchar",                  is_nullable => 0, size => 32 },
	"found",      { data_type => "boolean",                  is_nullable => 0 },
	"fetched",    { data_type => "timestamp with time zone", is_nullable => 0 },
	"cvss",       { data_type => "numeric",                  is_nullable => 1, size => [ 3, 1 ] },
	"epss",       { data_type => "numeric",                  is_nullable => 1, size => [ 6, 5 ] },
	"kev",        { data_type => "boolean",                  is_nullable => 1 },
	"ransomware", { data_type => "boolean",                  is_nullable => 1 },
	"raw",        { data_type => "jsonb",                    is_nullable => 1 },
);

=head1 PRIMARY KEY

=over 4

=item * L</cve>

=back

=cut

__PACKAGE__->set_primary_key("cve");

1;
