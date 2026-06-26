package Lilith::Web;

use Mojo::Base 'Mojolicious';
use Mojo::File  qw(curfile);
use TOML        qw(from_toml);
use File::Slurp qw(read_file);
use Lilith      ();

# File::ShareDir is optional — only available once the dist is installed.
my $SHARE_DIR;
eval {
	require File::ShareDir;
	$SHARE_DIR = File::ShareDir::dist_dir('Lilith');
};
# Development fallback: share/ lives three directories up from lib/Lilith/Web.pm
unless ( $SHARE_DIR && -d $SHARE_DIR ) {
	$SHARE_DIR = curfile->dirname->dirname->dirname->child('share')->to_string;
}
die "Cannot locate Lilith share directory\n" unless -d $SHARE_DIR;

=head1 NAME

Lilith::Web - Mojolicious web frontend for Lilith.

=head1 SYNOPSIS

    # Start via lilith-web script
    lilith-web daemon

    # Or directly
    LILITH_CONFIG=/usr/local/etc/lilith.toml lilith-web daemon -l http://*:8080

=head1 DESCRIPTION

Mojolicious application providing a web UI for searching Suricata, Sagan, and
CAPE alerts stored in the Lilith PostgreSQL database.

The config file path is read from the C<LILITH_CONFIG> environment variable,
defaulting to C</usr/local/etc/lilith.toml>.

=cut

sub startup {
	my $self = shift;

	my $config_file = $ENV{LILITH_CONFIG} // '/usr/local/etc/lilith.toml';

	die "Config file '$config_file' does not exist\n"
		unless -f $config_file;

	my $toml_raw = read_file($config_file)
		or die 'Failed to read "' . $config_file . '"';

	my ( $toml, $err ) = from_toml($toml_raw);
	die "Error parsing toml '$config_file': $err\n" unless $toml;

	my $lilith = Lilith->new(
		dsn  => $toml->{dsn},
		user => $toml->{user},
		pass => $toml->{pass},
	);

	$self->helper( lilith => sub {$lilith} );

	my $dnstracer_flags = [];
	if ( ref $toml->{dnstracer_flags} eq 'ARRAY' ) {
		$dnstracer_flags = $toml->{dnstracer_flags};
	}
	$self->helper( dnstracer_flags  => sub {$dnstracer_flags} );
	$self->helper( dnstracer_enable => sub { $toml->{dnstracer_enable} ? 1 : 0 } );

	# Point Mojolicious at share/templates and share/public so the app works
	# both when installed (File::ShareDir path) and when run from the repo.
	unshift @{ $self->renderer->paths }, "$SHARE_DIR/templates";
	unshift @{ $self->static->paths },   "$SHARE_DIR/public";

	my $r = $self->routes;
	$r->get('/')->to( cb => sub { $_[0]->redirect_to('/search') } );
	$r->get('/search')->to('search#index');
	$r->get('/event/:table/:id')->to('event#view');
	$r->get('/api/ipinfo/*ip')->to('api#ipinfo');
	$r->get('/api/domaininfo/*domain')->to('api#domaininfo');
}

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
