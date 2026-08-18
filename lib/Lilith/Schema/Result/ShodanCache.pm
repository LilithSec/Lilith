use utf8;

package Lilith::Schema::Result::ShodanCache;

=head1 NAME

Lilith::Schema::Result::ShodanCache

=head1 DESCRIPTION

What Shodan last said about an address, so the IP info modal does not repeat a
lookup every time someone opens it. One row per address, keyed on C<ip>.

C<raw> is Shodan's response as it arrived and is what the modal is rendered
from; the columns beside it are the parts worth querying without opening the
JSON. C<source> names which tier answered (C<api> or C<internetdb>) -- the two
differ in depth, so a row from the keyless tier reads as a miss once a key is
configured. C<found> is false for an address Shodan has never crawled, cached
deliberately since it is the lookup that would otherwise be repeated most.

C<fetched> is when Lilith asked, and is what freshness is measured against;
C<last_update> is when Shodan itself last crawled, and is NULL on the keyless
tier, which does not report it.

C<callouts>, the three fingerprint arrays (C<html_hashes>,
C<cert_fingerprints>, C<banner_hashes>), and C<products> are the interpretive
projection of C<raw>: the callout keys the modal shows, the service
fingerprints it pivots on, and the product names its banners identify, as
columns so the C</shodan> browser can filter on them and the neighborhood panel
can find other cached hosts sharing them. C<port_products> keeps the
port-to-product pairing those flatten away, as C<'PORT product version'>
strings, so the port lists rendered from columns can name what runs on each
port without opening C<raw>.

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<shodan_cache>

=cut

__PACKAGE__->table("shodan_cache");

=head1 ACCESSORS

=head2 ip

  data_type: 'inet'
  is_nullable: 0

=head2 source

  data_type: 'varchar'
  is_nullable: 0
  size: 16

=head2 found

  data_type: 'boolean'
  is_nullable: 0

=head2 fetched

  data_type: 'timestamp with time zone'
  is_nullable: 0

=head2 last_update

  data_type: 'timestamp with time zone'
  is_nullable: 1

=head2 ports

  data_type: 'integer[]'
  is_nullable: 1

=head2 tags

  data_type: 'varchar[]'
  is_nullable: 1

=head2 cpes

  data_type: 'varchar[]'
  is_nullable: 1

=head2 vulns

  data_type: 'varchar[]'
  is_nullable: 1

=head2 max_cvss

  data_type: 'numeric'
  is_nullable: 1
  size: [3,1]

=head2 hostnames

  data_type: 'varchar[]'
  is_nullable: 1

=head2 callouts

  data_type: 'varchar[]'
  is_nullable: 1

=head2 html_hashes

  data_type: 'bigint[]'
  is_nullable: 1

=head2 cert_fingerprints

  data_type: 'varchar[]'
  is_nullable: 1

=head2 banner_hashes

  data_type: 'bigint[]'
  is_nullable: 1

=head2 products

  data_type: 'varchar[]'
  is_nullable: 1

=head2 port_products

  data_type: 'varchar[]'
  is_nullable: 1

=head2 raw

  data_type: 'jsonb'
  is_nullable: 1

=cut

__PACKAGE__->add_columns(
	"ip",                { data_type => "inet",                     is_nullable => 0 },
	"source",            { data_type => "varchar",                  is_nullable => 0, size => 16 },
	"found",             { data_type => "boolean",                  is_nullable => 0 },
	"fetched",           { data_type => "timestamp with time zone", is_nullable => 0 },
	"last_update",       { data_type => "timestamp with time zone", is_nullable => 1 },
	"ports",             { data_type => "integer[]",                is_nullable => 1 },
	"tags",              { data_type => "varchar[]",                is_nullable => 1 },
	"cpes",              { data_type => "varchar[]",                is_nullable => 1 },
	"vulns",             { data_type => "varchar[]",                is_nullable => 1 },
	"max_cvss",          { data_type => "numeric",                  is_nullable => 1, size => [ 3, 1 ] },
	"hostnames",         { data_type => "varchar[]",                is_nullable => 1 },
	"os",                { data_type => "varchar",                  is_nullable => 1, size => 255 },
	"org",               { data_type => "varchar",                  is_nullable => 1, size => 255 },
	"isp",               { data_type => "varchar",                  is_nullable => 1, size => 255 },
	"asn",               { data_type => "varchar",                  is_nullable => 1, size => 32 },
	"callouts",          { data_type => "varchar[]",                is_nullable => 1 },
	"html_hashes",       { data_type => "bigint[]",                 is_nullable => 1 },
	"cert_fingerprints", { data_type => "varchar[]",                is_nullable => 1 },
	"banner_hashes",     { data_type => "bigint[]",                 is_nullable => 1 },
	"products",          { data_type => "varchar[]",                is_nullable => 1 },
	"port_products",     { data_type => "varchar[]",                is_nullable => 1 },
	"raw",               { data_type => "jsonb",                    is_nullable => 1 },
);

=head1 PRIMARY KEY

=over 4

=item * L</ip>

=back

=cut

__PACKAGE__->set_primary_key("ip");

1;
