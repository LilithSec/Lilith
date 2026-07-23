use utf8;
package Lilith::Schema::Result::Escalation;

=head1 NAME

Lilith::Schema::Result::Escalation

=head1 DESCRIPTION

One escalation attempt of an alert to an escalation target. Every
attempt is recorded, including ones refused before a send (unknown or
disabled target). C<table_name> is the short table type
(suricata/sagan/cape/baphomet) as used by L<Lilith>'s search(), C<raw> is the
payload the escalation type actually sent, C<status> is
pending/sent/failed, and C<target_name> snapshots the target's name at
attempt time so history stays readable after a target is deleted
(which nulls C<target_id> via the FK).

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<escalations>

=cut

__PACKAGE__->table("escalations");

=head1 ACCESSORS

=head2 id

  data_type: 'bigint'
  is_auto_increment: 1
  is_nullable: 0
  sequence: 'escalations_id_seq'

=head2 table_name

  data_type: 'varchar'
  is_nullable: 0
  size: 64

=head2 alert_id

  data_type: 'bigint'
  is_nullable: 0

=head2 event_id

  data_type: 'varchar'
  is_nullable: 1
  size: 64

=head2 target_id

  data_type: 'bigint'
  is_nullable: 1

=head2 target_name

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 status

  data_type: 'varchar'
  is_nullable: 0
  size: 32

=head2 note

  data_type: 'text'
  is_nullable: 1

=head2 requested_by

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 error

  data_type: 'text'
  is_nullable: 1

=head2 raw

  data_type: 'jsonb'
  is_nullable: 1

=head2 timestamp

  data_type: 'timestamp with time zone'
  is_nullable: 0

=cut

__PACKAGE__->add_columns(
  "id",
  {
    data_type         => "bigint",
    is_auto_increment => 1,
    is_nullable       => 0,
    sequence          => "escalations_id_seq",
  },
  "table_name",
  { data_type => "varchar", is_nullable => 0, size => 64 },
  "alert_id",
  { data_type => "bigint", is_nullable => 0 },
  "event_id",
  { data_type => "varchar", is_nullable => 1, size => 64 },
  "target_id",
  { data_type => "bigint", is_nullable => 1 },
  "target_name",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "status",
  { data_type => "varchar", is_nullable => 0, size => 32 },
  "note",
  { data_type => "text", is_nullable => 1 },
  "requested_by",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "error",
  { data_type => "text", is_nullable => 1 },
  "raw",
  { data_type => "jsonb", is_nullable => 1 },
  "timestamp",
  { data_type => "timestamp with time zone", is_nullable => 0 },
);

=head1 PRIMARY KEY

=over 4

=item * L</id>

=back

=cut

__PACKAGE__->set_primary_key("id");

1;
