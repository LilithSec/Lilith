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
