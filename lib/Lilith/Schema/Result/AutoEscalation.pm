use utf8;
package Lilith::Schema::Result::AutoEscalation;

=head1 NAME

Lilith::Schema::Result::AutoEscalation

=head1 DESCRIPTION

A automatic escalation rule. C<rule> is the match/actions DSL stored as
JSONB and compiled into a L<Rule::Engine> ruleset by
L<Lilith::AutoEscalate> when auto_escalate() runs. C<tables> scopes
which alert tables (suricata/sagan/cape/baphomet) the rule applies to
(a rule that names no tables defaults to suricata/sagan/cape),
C<priority> orders evaluation (lower first), and C<stop_on_match> keeps
later rules from firing on an alert an earlier rule already matched.

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<auto_escalations>

=cut

__PACKAGE__->table("auto_escalations");

=head1 ACCESSORS

=head2 id

  data_type: 'bigint'
  is_auto_increment: 1
  is_nullable: 0
  sequence: 'auto_escalations_id_seq'

=head2 name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 enabled

  data_type: 'boolean'
  is_nullable: 0

=head2 priority

  data_type: 'integer'
  is_nullable: 0

=head2 tables

  data_type: 'varchar[]'
  is_nullable: 0

=head2 rule

  data_type: 'jsonb'
  is_nullable: 0

=head2 stop_on_match

  data_type: 'boolean'
  is_nullable: 0

=head2 description

  data_type: 'varchar'
  is_nullable: 1
  size: 2048

=head2 last_matched

  data_type: 'timestamp with time zone'
  is_nullable: 1

=head2 match_count

  data_type: 'bigint'
  is_nullable: 0

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
    sequence          => "auto_escalations_id_seq",
  },
  "name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "enabled",
  { data_type => "boolean", is_nullable => 0 },
  "priority",
  { data_type => "integer", is_nullable => 0 },
  "tables",
  { data_type => "varchar[]", is_nullable => 0 },
  "rule",
  { data_type => "jsonb", is_nullable => 0 },
  "stop_on_match",
  { data_type => "boolean", is_nullable => 0 },
  "description",
  { data_type => "varchar", is_nullable => 1, size => 2048 },
  "last_matched",
  { data_type => "timestamp with time zone", is_nullable => 1 },
  "match_count",
  { data_type => "bigint", is_nullable => 0 },
  "updated",
  { data_type => "timestamp with time zone", is_nullable => 0 },
);

=head1 PRIMARY KEY

=over 4

=item * L</id>

=back

=cut

__PACKAGE__->set_primary_key("id");

__PACKAGE__->add_unique_constraint( "auto_escalations_name_key", ["name"] );

1;
