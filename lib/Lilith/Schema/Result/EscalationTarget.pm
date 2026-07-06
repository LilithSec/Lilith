use utf8;
package Lilith::Schema::Result::EscalationTarget;

=head1 NAME

Lilith::Schema::Result::EscalationTarget

=head1 DESCRIPTION

A configured escalation destination. C<type> selects the
L<Lilith::Escalate> type module to use and C<config> is that module's
configuration stored as JSONB.

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<escalation_targets>

=cut

__PACKAGE__->table("escalation_targets");

=head1 ACCESSORS

=head2 id

  data_type: 'bigint'
  is_auto_increment: 1
  is_nullable: 0
  sequence: 'escalation_targets_id_seq'

=head2 name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 type

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 config

  data_type: 'jsonb'
  is_nullable: 0

=head2 enabled

  data_type: 'boolean'
  is_nullable: 0

=head2 description

  data_type: 'varchar'
  is_nullable: 1
  size: 2048

=head2 updated

  data_type: 'timestamp with time zone'
  is_nullable: 0

=cut

__PACKAGE__->add_columns(
  "id",
  {
    data_type         => "bigint",
    is_auto_increment => 1,
    is_nullable       => 0,
    sequence          => "escalation_targets_id_seq",
  },
  "name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "type",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "config",
  { data_type => "jsonb", is_nullable => 0 },
  "enabled",
  { data_type => "boolean", is_nullable => 0 },
  "description",
  { data_type => "varchar", is_nullable => 1, size => 2048 },
  "updated",
  { data_type => "timestamp with time zone", is_nullable => 0 },
);

=head1 PRIMARY KEY

=over 4

=item * L</id>

=back

=cut

__PACKAGE__->set_primary_key("id");

__PACKAGE__->add_unique_constraint( "escalation_targets_name_key", ["name"] );

1;
