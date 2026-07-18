use utf8;
package Lilith::Schema::Result::BaphometAlert;

# Created by DBIx::Class::Schema::Loader
# DO NOT MODIFY THE FIRST PART OF THIS FILE

=head1 NAME

Lilith::Schema::Result::BaphometAlert

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<baphomet_alerts>

=cut

__PACKAGE__->table("baphomet_alerts");

=head1 ACCESSORS

=head2 id

  data_type: 'bigint'
  is_auto_increment: 1
  is_nullable: 0
  sequence: 'baphomet_alerts_id_seq'

=head2 instance

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 host

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 timestamp

  data_type: 'timestamp with time zone'
  is_nullable: 0

=head2 event_id

  data_type: 'varchar'
  is_nullable: 0
  size: 64

=head2 event_type

  data_type: 'varchar'
  is_nullable: 0
  size: 32

=head2 kur

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 path

  data_type: 'varchar'
  is_nullable: 1
  size: 1024

=head2 score

  data_type: 'double precision'
  is_nullable: 1

=head2 signature

  data_type: 'varchar'
  is_nullable: 1
  size: 2048

=head2 severity

  data_type: 'varchar'
  is_nullable: 1
  size: 32

=head2 classification

  data_type: 'varchar'
  is_nullable: 1
  size: 1024

=head2 src_ip

  data_type: 'inet'
  is_nullable: 1

=head2 dest_ip

  data_type: 'inet'
  is_nullable: 1

=head2 subject

  data_type: 'varchar'
  is_nullable: 1
  size: 1024

=head2 ban_time

  data_type: 'bigint'
  is_nullable: 1

=head2 recidive

  data_type: 'boolean'
  is_nullable: 1

=head2 country

  data_type: 'varchar'
  is_nullable: 1
  size: 16

=head2 raw

  data_type: 'jsonb'
  is_nullable: 0

=head2 escalations

  data_type: 'bigint[]'
  is_nullable: 1

=head2 auto_escalated

  data_type: 'timestamp with time zone'
  is_nullable: 1

=cut

__PACKAGE__->add_columns(
  "id",
  {
    data_type         => "bigint",
    is_auto_increment => 1,
    is_nullable       => 0,
    sequence          => "baphomet_alerts_id_seq",
  },
  "instance",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "host",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "timestamp",
  { data_type => "timestamp with time zone", is_nullable => 0 },
  "event_id",
  { data_type => "varchar", is_nullable => 0, size => 64 },
  "event_type",
  { data_type => "varchar", is_nullable => 0, size => 32 },
  "kur",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "path",
  { data_type => "varchar", is_nullable => 1, size => 1024 },
  "score",
  { data_type => "double precision", is_nullable => 1 },
  "signature",
  { data_type => "varchar", is_nullable => 1, size => 2048 },
  "severity",
  { data_type => "varchar", is_nullable => 1, size => 32 },
  "classification",
  { data_type => "varchar", is_nullable => 1, size => 1024 },
  "src_ip",
  { data_type => "inet", is_nullable => 1 },
  "dest_ip",
  { data_type => "inet", is_nullable => 1 },
  "subject",
  { data_type => "varchar", is_nullable => 1, size => 1024 },
  "ban_time",
  { data_type => "bigint", is_nullable => 1 },
  "recidive",
  { data_type => "boolean", is_nullable => 1 },
  "country",
  { data_type => "varchar", is_nullable => 1, size => 16 },
  "raw",
  { data_type => "jsonb", is_nullable => 0 },
  "escalations",
  { data_type => "bigint[]", is_nullable => 1 },
  "auto_escalated",
  { data_type => "timestamp with time zone", is_nullable => 1 },
);

=head1 PRIMARY KEY

=over 4

=item * L</id>

=back

=cut

__PACKAGE__->set_primary_key("id");


# You can replace this text with custom code or comments, and it will be preserved on regeneration
1;
