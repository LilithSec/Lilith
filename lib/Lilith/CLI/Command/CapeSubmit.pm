# cape_submit -- hand one or more local files to a CAPEv2 box
# (mojo_cape_submit) for detonation. Needs cape_enable set and at least one
# [cape_servers.NAME] configured; --server may be left off when exactly one
# exists. Each file's hashes, size, and libmagic description are computed and
# sent alongside it.
#
# Exits non-zero if any file failed, so a shell loop notices.
#
#     lilith cape_submit /tmp/sample.exe
#     lilith cape_submit --server main --slug hunt /tmp/a.exe /tmp/b.dll
package Lilith::CLI::Command::CapeSubmit;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::CapeSubmit ();

sub command_names { 'cape_submit' }

sub abstract { 'submit a file to a CAPEv2 box for detonation' }

sub usage_desc { '%c cape_submit %o <file> [<file> ...]' }

sub description {
	return
		  "Submits one or more local files to a configured CAPEv2 box for detonation,\n"
		. "reading cape_enable, cape_slug, and the cape_servers table from the config\n"
		. "file. The server is picked with --server, or defaults to the only configured\n"
		. "server when there is just one. Exits non-zero if any file failed to submit.";
}

sub opt_spec {
	my ($class) = @_;
	return (
		[ 'server|s=s', 'the configured cape server to submit to' ],
		[ 'slug=s',     'the slug to submit with; defaults to cape_slug' ],
		[ 'file|f=s@',  'a file to submit; may be given multiple times or as arguments' ],
		$class->output_opt_spec,
	);
}

# Refuse the run when no file was named at all. Only that a file was named is
# checked here -- whether it can actually be read is left to the submit itself,
# which reports it per file, so one bad path among several does not stop the
# rest going out.
#
# Args:
#
#   - $opt :: the parsed options. --file is looked at, which is repeatable.
#   - $args :: array ref of the file paths given positionally. Files may come
#     either way, and the two are pooled.
#
# Returns: nothing meaningful when the run may proceed; otherwise calls
# usage_error, which prints the usage and exits non-zero.
sub validate_args {
	my ( $self, $opt, $args ) = @_;

	# files may come either as positional arguments or via --file
	my @files = ( @{ $opt->{file} || [] }, @{$args} );
	if ( !@files ) {
		$self->usage_error('at least one file to submit is required');
	}

	return;
} ## end sub validate_args

# Submit each named file and report how each went.
#
# A file that fails is recorded as a failed result and the rest still go, so
# one unreadable path or one rejection does not cost the whole batch.
#
# Args:
#
#   - $opt :: the parsed options. --server picks the CAPE box (optional when
#     only one is configured), --slug overrides the default cape_slug, and
#     --file names files alongside any given positionally.
#   - $args :: array ref of the file paths given positionally, pooled with
#     --file.
#
# Returns: does not return. Renders a row per file -- the path, the server, the
# name it was uploaded under, whether it succeeded, its sha256, and any error
# -- then exits 1 when any file failed and 0 otherwise, so a shell loop notices
# a partial failure rather than reading the zero from the last success.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $config = $self->config;

	my $submitter = Lilith::CapeSubmit->new(
		enabled => $config->{cape_enable},
		slug    => $config->{cape_slug},
		servers => $config->{cape_servers},
	);

	my @files = ( @{ $opt->{file} || [] }, @{$args} );

	my @results;
	foreach my $file (@files) {
		my $result = eval { $submitter->submit( server => $opt->{server}, slug => $opt->{slug}, file => $file, ); };

		# a setup problem (disabled, unknown server, unreadable file, ...) dies;
		# turn it into an error row so one bad file does not abort the rest
		if ($@) {
			( my $why = $@ ) =~ s/\s+\z//;
			$result = { status => 'error', error => $why };
		}
		$result->{file} = $file;

		push( @results, $result );
	} ## end foreach my $file (@files)

	my $failed = scalar( grep { $_->{status} ne 'ok' } @results );

	$self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( \@results, $opt->{pretty} ) },
		table => sub {
			my $tb = $self->table( 'File', 'Server', 'Upload Name', 'Status', 'SHA256', 'Error' );
			my @td;
			foreach my $result (@results) {
				push(
					@td,
					[
						$result->{file},
						defined( $result->{server} ) ? $result->{server} : '',
						defined( $result->{name} )   ? $result->{name}   : '',
						$result->{status},
						defined( $result->{sha256} ) ? $result->{sha256} : '',
						defined( $result->{error} )  ? $result->{error}  : '',
					]
				);
			} ## end foreach my $result (@results)
			$tb->add_rows( \@td );
			print $tb->draw;

			return;
		},
	);

	exit( $failed ? 1 : 0 );
} ## end sub execute

1;
