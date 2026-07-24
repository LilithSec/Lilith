package Lilith::CapeSubmit;

use strict;
use warnings;
use Digest::MD5           ();
use Digest::SHA           ();
use File::Basename        qw( basename );
use LWP::UserAgent        ();
use HTTP::Request::Common qw( POST );
use JSON                  qw( encode_json );
use Sys::Hostname         qw( hostname );

=head1 NAME

Lilith::CapeSubmit - Submit a local file to a CAPEv2 box for detonation.

=head1 SYNOPSIS

    my $submitter = Lilith::CapeSubmit->new(
        enabled => $toml->{cape_enable},
        slug    => $toml->{cape_slug},
        servers => $toml->{cape_servers},
    );

    my $result = $submitter->submit(
        server => 'main',
        file   => '/tmp/putty.exe',
    );
    die $result->{error} if $result->{status} ne 'ok';

=head1 DESCRIPTION

Where L<Lilith::Receiver> is the ingest side (sensors pushing EVE rows in), this
is an egress side: it hands a local sample to a CAPEv2 submission endpoint
(C<mojo_cape_submit>) for detonation. It computes the sample's hashes, size, and
libmagic description, builds the C<lilith_cape_submit> submission payload, and
POSTs the file plus that payload as C<multipart/form-data>, mirroring how
C<suricata_extract_submit> from CAPE-Utils submits Suricata-extracted files.

=head2 PAYLOAD

The POST carries the file itself (uploaded under the name
C<< $slug-$unixtime-$basename >>) and a C<json> field holding two top-level keys,
shaped so a CAPE box already parsing Suricata extract records sees a familiar
C<.fileinfo>:

    {
      "lilith_cape_submit": {
        "filename": "lilith-1753208651-putty.exe",
        "host":     "<the host running this>",
        "to":       "<the server url>",
        "time":     1753208651,
        "slug":     "lilith",
        "md5":      "...",
        "sha1":     "...",
        "sha256":   "..."
      },
      "fileinfo": {
        "filename": "putty.exe",
        "magic":    "PE32 executable (GUI) Intel 80386, for MS Windows",
        "md5":      "...",
        "sha1":     "...",
        "sha256":   "...",
        "size":     723678
      }
    }

The API key, when the server needs one, is sent as the bearer token and the
C<apikey> form field only; it is never placed in the JSON body.

=head1 METHODS

=head2 new

    my $submitter = Lilith::CapeSubmit->new(
        enabled => $bool,        # whether submission is turned on (cape_enable)
        slug    => $slug,        # default slug; defaults to 'lilith'
        servers => \%servers,    # the cape_servers table
        timeout => 30,           # optional LWP timeout in seconds
    );

C<servers> is a hash of server-name to a hash with:

    - url           :: where to POST. Required per server.
    - apikey_needed :: whether the server requires an API key.
    - apikey        :: the API key to send when one is needed.

=cut

sub new {
	my ( $class, %opts ) = @_;

	my $self = {
		enabled => to_bool( $opts{enabled} ),
		slug    => ( defined( $opts{slug} ) && $opts{slug} ne '' ) ? $opts{slug}    : 'lilith',
		servers => ( ref( $opts{servers} ) eq 'HASH' )             ? $opts{servers} : {},
		timeout => defined( $opts{timeout} )                       ? $opts{timeout} : 30,
	};
	bless $self, $class;

	return $self;
} ## end sub new

=head2 to_bool

Coerce a config flag into 1/0. Needed because the L<TOML> parser returns the
bare strings C<'true'> and C<'false'> for TOML booleans, and both are truthy in
Perl -- so C<apikey_needed = false> would otherwise read as true. A real boolean
object, a number, or a yes/no-ish string are all handled; C<'false'>, C<'0'>,
C<'no'>, C<'off'>, the empty string, and undef are false, everything else true.

    my $on = Lilith::CapeSubmit::to_bool( $toml->{cape_enable} );

=cut

sub to_bool {
	my ($value) = @_;
	return 0 unless defined $value;
	return ( $value ? 1 : 0 ) if ref $value;                                   # a real boolean object
	return 0                  if $value =~ /\A\s*(?:0|false|no|off|)\s*\z/i;
	return 1;
}

=head2 servers

Returns the configured server names, sorted.

    my @names = $submitter->servers;

=cut

sub servers {
	my ($self) = @_;
	return ( sort keys( %{ $self->{servers} } ) );
}

=head2 submit

Submit one file to a configured CAPE server. Returns a result hash ref; a setup
problem (submission disabled, unknown/ambiguous server, unreadable file, missing
API key) dies, while a completed request that the server rejected comes back with
C<< status => 'error' >> and the HTTP status in C<http_status>.

    my $result = $submitter->submit(
        server => 'main',    # optional when exactly one server is configured
        file   => $path,
        slug   => 'foo',     # optional; overrides the default slug
        name   => 'orig.exe',# optional; the logical name, when $path is a temp file
    );

The bytes are always read from C<file>. C<name> is the logical filename the
sample is known by -- its basename becomes C<fileinfo.filename> and drives the
upload name. It defaults to C<file>'s basename, and is used when the on-disk
path is a temporary copy (e.g. a web upload) whose name is not the real one.

The result hash ref carries:

    - status      :: 'ok' on a 2xx response, otherwise 'error'.
    - server      :: the server name used.
    - name        :: the upload name ($slug-$unixtime-$basename).
    - http_status :: the response status line, when a request was made.
    - md5 / sha1 / sha256 / size / magic :: the computed sample facts.
    - error       :: set when status is 'error'.

=cut

sub submit {
	my ( $self, %opts ) = @_;

	die("cape submission is not enabled (cape_enable is not set)\n") unless $self->{enabled};

	my $file = $opts{file};
	die("no file given to submit\n")                                         unless defined($file) && $file ne '';
	die( '"' . $file . '" does not exist or is not a readable file' . "\n" ) unless -f $file       && -r $file;

	my ( $server_name, $server ) = $self->_resolve_server( $opts{server} );

	my $url = $server->{url};
	die( 'cape server "' . $server_name . '" has no url set' . "\n" )
		unless defined($url) && $url ne '';

	# only send an API key when the server is configured to need one, and refuse
	# to submit if it needs one but none is set rather than silently sending none
	my $apikey = '';
	if ( to_bool( $server->{apikey_needed} ) ) {
		$apikey = $server->{apikey};
		die( 'cape server "' . $server_name . '" needs an API key but none is set' . "\n" )
			unless defined($apikey) && $apikey ne '';
	}

	my $slug = ( defined( $opts{slug} ) && $opts{slug} ne '' ) ? $opts{slug} : $self->{slug};

	# facts about the sample: the raw filename (no leading path), the hashes in a
	# single pass, the size, and the libmagic description. The logical name comes
	# from the name option when given (a web upload's temp path is not the real
	# name), else from the file path; basename strips any directory either way.
	my $name_source = ( defined( $opts{name} ) && $opts{name} ne '' ) ? $opts{name} : $file;
	my $basename    = basename($name_source);
	my $hashes      = $self->_hashes($file);
	my $size        = -s $file;
	my $magic       = $self->_magic($file);

	# submission time drives the upload name; there is no flow time here
	my $unixtime    = time;
	my $upload_name = $slug . '-' . $unixtime . '-' . $basename;

	my $payload = {
		lilith_cape_submit => {
			filename => $upload_name,
			host     => hostname,
			to       => $url,
			time     => $unixtime + 0,
			slug     => $slug,
			md5      => $hashes->{md5},
			sha1     => $hashes->{sha1},
			sha256   => $hashes->{sha256},
		},
		fileinfo => {
			filename => $basename,
			magic    => $magic,
			md5      => $hashes->{md5},
			sha1     => $hashes->{sha1},
			sha256   => $hashes->{sha256},
			size     => $size,
		},
	};

	my $result = {
		status => 'error',
		server => $server_name,
		name   => $upload_name,
		md5    => $hashes->{md5},
		sha1   => $hashes->{sha1},
		sha256 => $hashes->{sha256},
		size   => $size,
		magic  => $magic,
	};

	my $response;
	eval {
		my $ua = LWP::UserAgent->new(
			ssl_opts => { verify_hostname => 0, SSL_verify_mode => 0 },
			timeout  => $self->{timeout},
		);
		$response = $ua->request(
			POST $url,
			Authorization => 'Bearer ' . $apikey,
			Content_Type  => 'form-data',
			Content       => [
				apikey   => $apikey,
				type     => 'lilith_cape_submit',
				filename => [ $file, $upload_name ],
				json     => encode_json($payload),
			],
		);
	};
	if ($@) {
		$result->{error} = 'submission to "' . $url . '" failed... ' . $@;
		return $result;
	}

	$result->{http_status} = $response->status_line;
	if ( $response->is_success ) {
		$result->{status} = 'ok';
	} else {
		$result->{error} = 'server responded ' . $response->status_line;
	}

	return $result;
} ## end sub submit

# Pick the server hash for a name, or the sole server when no name is given.
# Dies when the name is unknown, or when none is given but there is not exactly
# one to fall back to.
sub _resolve_server {
	my ( $self, $name ) = @_;

	my @names = $self->servers;
	die("no cape servers are configured (cape_servers)\n") unless @names;

	if ( defined($name) && $name ne '' ) {
		die( 'no cape server named "' . $name . '" is configured' . "\n" )
			unless ref( $self->{servers}{$name} ) eq 'HASH';
		return ( $name, $self->{servers}{$name} );
	}

	die( 'more than one cape server is configured (' . join( ', ', @names ) . '); pick one with --server' . "\n" )
		if @names > 1;

	return ( $names[0], $self->{servers}{ $names[0] } );
} ## end sub _resolve_server

# md5/sha1/sha256 of a file, computed in a single streaming pass so a large
# sample is never slurped whole into memory.
sub _hashes {
	my ( $self, $file ) = @_;

	my $md5    = Digest::MD5->new;
	my $sha1   = Digest::SHA->new(1);
	my $sha256 = Digest::SHA->new(256);

	open( my $fh, '<:raw', $file ) or die( 'cannot read "' . $file . '" for hashing... ' . $! . "\n" );
	while ( read( $fh, my $buffer, 65536 ) ) {
		$md5->add($buffer);
		$sha1->add($buffer);
		$sha256->add($buffer);
	}
	close($fh);

	return {
		md5    => $md5->hexdigest,
		sha1   => $sha1->hexdigest,
		sha256 => $sha256->hexdigest,
	};
} ## end sub _hashes

# The libmagic description of a file, akin to what Suricata records as
# fileinfo.magic. Prefer File::LibMagic when it is installed; otherwise fall back
# to the file(1) binary, invoked without a shell so a crafted filename cannot
# inject. Returns undef when neither is available.
sub _magic {
	my ( $self, $file ) = @_;

	my $description = eval {
		require File::LibMagic;
		my $flm = File::LibMagic->new;
		if ( $flm->can('info_from_filename') ) {
			my $info = $flm->info_from_filename($file);
			return ref($info) eq 'HASH' ? $info->{description} : undef;
		}
		return $flm->describe_filename($file);
	};
	return $description if defined($description) && $description ne '';

	$description = eval {
		open( my $fh, '-|', 'file', '-b', '--', $file ) or die("cannot run file(1)... $!");
		local $/ = undef;
		my $out = <$fh>;
		close($fh);
		$out =~ s/\s+\z// if defined($out);
		return $out;
	};

	return ( defined($description) && $description ne '' ) ? $description : undef;
} ## end sub _magic

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
