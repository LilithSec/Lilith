# extend -- print a LibreNMS style extend of recent alert counts, for wiring
# into snmpd:
#
#     extend lilith /usr/local/bin/lilith extend
#
# -Z applies the gzip+base64 compression LibreNMS accepts, which matters
# because an SNMP response is size-limited and a busy sensor's counts are not
# small. The class_ignore/sid_ignore config keys trim what is counted here
# without keeping anything out of the database.
#
#     lilith extend -m 5 -Z
package Lilith::CLI::Command::Extend;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use JSON         ();
use MIME::Base64 qw( encode_base64 );
use Gzip::Faster qw( gzip );

sub abstract { 'print a LibreNMS style extend' }

sub usage_desc { '%c extend %o' }

sub opt_spec {
	return (
		[ 'm=s',    'how far back to search, in minutes', { default => 5 } ],
		[ 'Z',      'enable Gzip+Base64 LibreNMS compression' ],
		[ 'pretty', 'pretty print the JSON' ],
	);
}

# Build the extend data and print it, compressed when asked.
#
# The gzip+base64 form exists because an SNMP response is size limited and a
# busy sensor's counts are not small. The newline is stripped from the base64
# and a single one added back, since the extend protocol wants exactly one
# line.
#
# Args:
#
#   - $opt :: the parsed options. -m is the window in minutes, -Z asks for the
#     compressed form, --pretty indents the plain JSON.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the extend, as one line of base64 with
# -Z, otherwise as JSON.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $to_return = $self->lilith->extend( go_back_minutes => $opt->{m}, );

	my $json = JSON->new;
	if ( $opt->{pretty} ) {
		$json->canonical(1);
		$json->pretty(1);
	}

	my $raw_json = $json->encode($to_return);
	if ( $opt->{Z} ) {
		my $compressed = encode_base64( gzip($raw_json) );
		$compressed =~ s/\n//g;
		$compressed = $compressed . "\n";
		print $compressed;
	} else {
		print $raw_json;
	}
	if ( !$opt->{pretty} && !$opt->{Z} ) {
		print "\n";
	}

	return;
} ## end sub execute

1;
