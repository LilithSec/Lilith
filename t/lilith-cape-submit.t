#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use JSON          qw( decode_json );
use File::Temp    qw( tempfile );
use HTTP::Response ();

use_ok('Lilith::CapeSubmit') or BAIL_OUT('Lilith::CapeSubmit failed to load');

# A sample file to submit. Starts with the DOS "MZ" magic so file(1) recognizes
# it as an executable, giving fileinfo.magic something non-empty.
my ( $fh, $sample ) = tempfile( 'lilith-cape-XXXXXX', TMPDIR => 1, UNLINK => 1, SUFFIX => '.exe' );
binmode $fh;
print $fh "MZ\x90\x00" . ( "A" x 200 );
close($fh);

# Capture the request instead of putting it on the wire, and answer with a
# response the test dictates. Returns the decoded json payload plus the request
# so a test can inspect headers and the multipart body.
my $LAST_REQUEST;
my $NEXT_RESPONSE = HTTP::Response->new( 200, 'OK' );
{
	no warnings qw( redefine once );
	*LWP::UserAgent::request = sub { $LAST_REQUEST = $_[1]; return $NEXT_RESPONSE; };
}

sub payload_of {
	my ($request) = @_;
	my ($json) = $request->content =~ /name="json"\r?\n\r?\n(\{.*?\})\r?\n--/s;
	return decode_json($json);
}

# ===========================================================================
# Setup / validation failures die before any request is made.
# ===========================================================================
throws_ok {
	Lilith::CapeSubmit->new( enabled => 0, servers => { a => { url => 'http://x/' } } )->submit( file => $sample );
}
qr/not enabled/, 'submit dies when cape_enable is off';

throws_ok {
	Lilith::CapeSubmit->new( enabled => 1, servers => {} )->submit( file => $sample );
}
qr/no cape servers/, 'submit dies with no servers configured';

throws_ok {
	Lilith::CapeSubmit->new( enabled => 1, servers => { a => { url => 1 }, b => { url => 2 } } )
		->submit( file => $sample );
}
qr/more than one cape server/, 'submit dies when the server is ambiguous';

throws_ok {
	Lilith::CapeSubmit->new( enabled => 1, servers => { a => { url => 'http://x/' } } )
		->submit( file => $sample, server => 'nope' );
}
qr/no cape server named/, 'submit dies for an unknown named server';

throws_ok {
	Lilith::CapeSubmit->new( enabled => 1, servers => { a => { url => 'http://x/', apikey_needed => 1 } } )
		->submit( file => $sample );
}
qr/needs an API key/, 'submit dies when a key is required but not set';

throws_ok {
	Lilith::CapeSubmit->new( enabled => 1, servers => { a => { url => 'http://x/' } } )
		->submit( file => '/nonexistent/sample' );
}
qr/does not exist/, 'submit dies for an unreadable file';

# ===========================================================================
# A successful submission: payload shape, upload name, and where the key goes.
# ===========================================================================
{
	my $submitter = Lilith::CapeSubmit->new(
		enabled => 1,
		servers => { main => { url => 'http://127.0.0.1:9/', apikey_needed => 1, apikey => 'SECRET123' } },
	);
	my $result = $submitter->submit( file => $sample, slug => 'hunt' );

	my ($sample_basename) = $sample =~ m{([^/]+)$};

	is( $result->{status}, 'ok',   'a 2xx response yields status ok' );
	is( $result->{server}, 'main', 'the server name is reported' );
	like( $result->{sha256}, qr/^[0-9a-f]{64}$/, 'sha256 computed' );
	like( $result->{name}, qr/^hunt-[0-9]+-\Q$sample_basename\E$/,
		'upload name is slug-unixtime-basename' );

	# the key rides the Authorization header, not the JSON
	is( $LAST_REQUEST->header('Authorization'), 'Bearer SECRET123', 'API key sent as bearer token' );

	my $payload = payload_of($LAST_REQUEST);
	ok( exists $payload->{lilith_cape_submit}, 'lilith_cape_submit block present' );
	ok( exists $payload->{fileinfo},           'fileinfo is a top-level sibling, not nested' );
	ok( !exists $payload->{lilith_cape_submit}{fileinfo}, 'fileinfo is NOT under lilith_cape_submit' );
	ok( !exists $payload->{lilith_cape_submit}{apikey},   'the API key is not in the submission block' );

	unlike( $LAST_REQUEST->content =~ /name="json".*?--/s ? $& : '',
		qr/SECRET123/, 'the API key never appears in the json payload' );

	my $lcs = $payload->{lilith_cape_submit};
	is( $lcs->{slug}, 'hunt',              'slug carried in the block' );
	is( $lcs->{to},   'http://127.0.0.1:9/', 'to is the server url' );
	like( $lcs->{time}, qr/^[0-9]+$/, 'time is a bare epoch' );
	is( $lcs->{filename}, $result->{name}, 'block filename is the upload name' );
	for my $h (qw( md5 sha1 sha256 )) {
		is( $lcs->{$h}, $result->{$h}, "block carries $h" );
	}

	my $fi = $payload->{fileinfo};
	my ($basename) = $sample =~ m{([^/]+)$};
	is( $fi->{filename}, $basename, 'fileinfo.filename is the raw basename (no path)' );
	unlike( $fi->{filename}, qr{/}, 'fileinfo.filename has no slash' );
	ok( defined $fi->{magic} && $fi->{magic} ne '', 'fileinfo.magic is populated' );
	like( $fi->{size}, qr/^[0-9]+$/, 'fileinfo.size is numeric' );
	for my $h (qw( md5 sha1 sha256 )) {
		is( $fi->{$h}, $result->{$h}, "fileinfo carries $h" );
	}

	# the multipart form field the receiver dispatches on
	like( $LAST_REQUEST->content, qr/name="type"\r?\n\r?\nlilith_cape_submit/, 'form type is lilith_cape_submit' );
}

# ===========================================================================
# A server that needs no key sends an empty bearer and no key material.
# ===========================================================================
{
	my $submitter = Lilith::CapeSubmit->new(
		enabled => 1,
		servers => { open => { url => 'http://127.0.0.1:9/' } },
	);
	$submitter->submit( file => $sample );
	is( $LAST_REQUEST->header('Authorization'), 'Bearer ', 'no-key server sends an empty bearer' );
}

# ===========================================================================
# A non-2xx response comes back as an error result rather than dying.
# ===========================================================================
{
	$NEXT_RESPONSE = HTTP::Response->new( 500, 'Internal Server Error' );
	my $submitter = Lilith::CapeSubmit->new(
		enabled => 1,
		servers => { main => { url => 'http://127.0.0.1:9/' } },
	);
	my $result = $submitter->submit( file => $sample );
	is( $result->{status}, 'error', 'a 5xx response yields status error' );
	like( $result->{error}, qr/500/, 'the error carries the status' );
	like( $result->{http_status}, qr/500/, 'the http_status is recorded' );
}

# ===========================================================================
# Default slug falls back to 'lilith'.
# ===========================================================================
{
	$NEXT_RESPONSE = HTTP::Response->new( 200, 'OK' );
	my $submitter = Lilith::CapeSubmit->new(
		enabled => 1,
		servers => { main => { url => 'http://127.0.0.1:9/' } },
	);
	my $result = $submitter->submit( file => $sample );
	like( $result->{name}, qr/^lilith-/, 'default slug is lilith' );
}

# ===========================================================================
# The name option: bytes come from file, but the logical name (upload name and
# fileinfo.filename) comes from name -- for a web upload whose on-disk path is a
# temp file. A directory in name is stripped to the basename.
# ===========================================================================
{
	$NEXT_RESPONSE = HTTP::Response->new( 200, 'OK' );
	my $submitter = Lilith::CapeSubmit->new(
		enabled => 1,
		servers => { main => { url => 'http://127.0.0.1:9/' } },
	);
	my $result = $submitter->submit( file => $sample, slug => 's', name => '/some/path/real name.exe' );

	like( $result->{name}, qr/^s-[0-9]+-real name\.exe$/, 'upload name uses the name option basename' );

	my $payload = payload_of($LAST_REQUEST);
	is( $payload->{fileinfo}{filename}, 'real name.exe', 'fileinfo.filename is the name basename, path stripped' );
	# the bytes (and thus hashes) still come from the real file
	is( $payload->{fileinfo}{sha256}, $result->{sha256}, 'hashes still computed from the file bytes' );
}

# ===========================================================================
# TOML-boolean handling: the TOML parser yields the bare strings 'true'/'false'
# for booleans, both truthy in Perl, so enabled and apikey_needed must coerce
# them rather than take them at face value.
# ===========================================================================
{
	is( Lilith::CapeSubmit::to_bool('true'),  1, 'to_bool("true") is 1' );
	is( Lilith::CapeSubmit::to_bool('false'), 0, 'to_bool("false") is 0' );
	is( Lilith::CapeSubmit::to_bool('0'),     0, 'to_bool("0") is 0' );
	is( Lilith::CapeSubmit::to_bool(undef),   0, 'to_bool(undef) is 0' );
	is( Lilith::CapeSubmit::to_bool(1),       1, 'to_bool(1) is 1' );

	# enabled given the TOML string 'false' really is disabled
	throws_ok {
		Lilith::CapeSubmit->new( enabled => 'false', servers => { a => { url => 'http://x/' } } )
			->submit( file => $sample );
	}
	qr/not enabled/, 'enabled => "false" (TOML string) is treated as off';

	# apikey_needed => 'false' (TOML string) must NOT demand a key
	$NEXT_RESPONSE = HTTP::Response->new( 200, 'OK' );
	my $ok = Lilith::CapeSubmit->new(
		enabled => 'true',
		servers => { a => { url => 'http://127.0.0.1:9/', apikey_needed => 'false' } },
	)->submit( file => $sample );
	is( $ok->{status}, 'ok', 'apikey_needed => "false" does not require a key' );

	# apikey_needed => 'true' (TOML string) with no key still dies
	throws_ok {
		Lilith::CapeSubmit->new(
			enabled => 'true',
			servers => { a => { url => 'http://127.0.0.1:9/', apikey_needed => 'true' } },
		)->submit( file => $sample );
	}
	qr/needs an API key/, 'apikey_needed => "true" with no key still refuses';
}

done_testing();
