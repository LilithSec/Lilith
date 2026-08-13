package Lilith::ConfigUtil;

use strict;
use warnings;
use Exporter qw( import );

our @EXPORT_OK = qw( to_bool );

=head1 NAME

Lilith::ConfigUtil - shared helpers for reading the TOML config.

=head1 DESCRIPTION

Coercions every reader of the config needs, whatever it is configuring. This
lives on its own so that a caller reading one flag does not have to load a
feature module -- and its dependencies -- to do it.

=head1 FUNCTIONS

=head2 to_bool

Coerce a config flag into 1/0. Needed because the L<TOML> parser returns the
bare strings C<'true'> and C<'false'> for TOML booleans, and both are truthy in
Perl -- so C<cape_enable = false> would otherwise read as true. A real boolean
object, a number, or a yes/no-ish string are all handled; C<'false'>, C<'0'>,
C<'no'>, C<'off'>, the empty string, and undef are false, everything else true.

    my $on = Lilith::ConfigUtil::to_bool( $toml->{cape_enable} );

=cut

sub to_bool {
	my ($value) = @_;
	return 0 unless defined $value;
	return ( $value ? 1 : 0 ) if ref $value;                                   # a real boolean object
	return 0                  if $value =~ /\A\s*(?:0|false|no|off|)\s*\z/i;
	return 1;
}

1;
