use utf8;

package Lilith::Schema::Result::ReceiverApikey;

=head1 NAME

Lilith::Schema::Result::ReceiverApikey

=head1 DESCRIPTION

A bearer key accepted by C<mojo_lilith_receiver>. Only the SHA-256 of the key
is stored (C<key_sha256>); the key itself is shown once at creation and is not
recoverable. C<allowed_ips> and C<allowed_instances> optionally scope where the
key may be used and which instance names it may write; an empty/NULL value on
either means "no restriction on that axis". C<allowed_instances> entries may use
the C<*> and C<?> shell-style wildcards.

=cut

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 TABLE: C<receiver_apikeys>

=cut

__PACKAGE__->table("receiver_apikeys");

=head1 ACCESSORS

=head2 id

  data_type: 'bigint'
  is_auto_increment: 1
  is_nullable: 0
  sequence: 'receiver_apikeys_id_seq'

=head2 name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 key_sha256

  data_type: 'varchar'
  is_nullable: 0
  size: 44

=head2 enabled

  data_type: 'boolean'
  is_nullable: 0

=head2 allowed_ips

  data_type: 'cidr[]'
  is_nullable: 1

=head2 allowed_instances

  data_type: 'varchar[]'
  is_nullable: 1

=head2 description

  data_type: 'varchar'
  is_nullable: 1
  size: 2048

=head2 last_used

  data_type: 'timestamp with time zone'
  is_nullable: 1

=head2 created

  data_type: 'timestamp with time zone'
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
		sequence          => "receiver_apikeys_id_seq",
	},
	"name",
	{ data_type => "varchar", is_nullable => 0, size => 255 },
	"key_sha256",
	{ data_type => "varchar", is_nullable => 0, size => 44 },
	"enabled",
	{ data_type => "boolean", is_nullable => 0 },
	"allowed_ips",
	{ data_type => "cidr[]", is_nullable => 1 },
	"allowed_instances",
	{ data_type => "varchar[]", is_nullable => 1 },
	"description",
	{ data_type => "varchar", is_nullable => 1, size => 2048 },
	"last_used",
	{ data_type => "timestamp with time zone", is_nullable => 1 },
	"created",
	{ data_type => "timestamp with time zone", is_nullable => 0 },
	"updated",
	{ data_type => "timestamp with time zone", is_nullable => 0 },
);

=head1 PRIMARY KEY

=over 4

=item * L</id>

=back

=cut

__PACKAGE__->set_primary_key("id");

__PACKAGE__->add_unique_constraint( "receiver_apikeys_name_key",       ["name"] );
__PACKAGE__->add_unique_constraint( "receiver_apikeys_key_sha256_key", ["key_sha256"] );

1;
