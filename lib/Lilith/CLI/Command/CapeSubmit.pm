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

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	# files may come either as positional arguments or via --file
	my @files = ( @{ $opt->{file} || [] }, @{$args} );
	if ( !@files ) {
		$self->usage_error('at least one file to submit is required');
	}

	return;
} ## end sub validate_args

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
