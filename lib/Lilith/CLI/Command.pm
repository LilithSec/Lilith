package Lilith::CLI::Command;

use strict;
use warnings;
use parent 'App::Cmd::Command';
use Lilith          ();
use TOML            qw( from_toml );
use File::Slurp     qw( read_file );
use JSON            ();
use Text::ANSITable ();

=head1 NAME

Lilith::CLI::Command - base class for C<lilith> subcommands.

=head1 DESCRIPTION

Shared behavior for every command under L<Lilith::CLI::Command>: lazy access to
the parsed config and the L<Lilith> object (both cached on the app object so a
command only builds them once), plus the JSON and table output helpers that
were duplicated across the old action ladder.

=head1 METHODS

=head2 config

Returns the parsed TOML config as a hash ref, read from the C<--config> file
and cached on the app object. Dies if the file is missing or unparsable.

=head2 lilith

Returns the L<Lilith> object built from the config, cached on the app object.

=head2 print_json( $data, $pretty )

Encodes C<$data> as JSON and prints it, canonicalized and pretty when
C<$pretty> is true, with a trailing newline only when not pretty.

=head2 table( @columns )

Returns a L<Text::ANSITable> with the standard Lilith border/theme and the
given columns, styled with the alternating padding the old output used.

=head2 output_opt_spec

Returns the shared C<--output>/C<--pretty> opt spec entries used by the
commands that can render either a table or JSON. Meant to be included in
a command's C<opt_spec> like below.

    sub opt_spec {
        my ($class) = @_;
        return (
            [ 'id=s', 'the row ID' ],
            $class->output_opt_spec,
        );
    }

=head2 output_dispatch( $opt, %renderers )

Dispatches on C<< $opt->{output} >>, calling the matching code ref from
C<%renderers> (keyed C<table>, C<json>, etc) and returning its return
value. Dies with C<No applicable output found> when C<--output> names an
output no renderer was passed for.

    return $self->output_dispatch(
        $opt,
        json  => sub { $self->print_json( $rows, $opt->{pretty} ) },
        table => sub { ... },
    );

=head2 migration

Returns a L<DBIx::Class::Migration> for L<Lilith::Schema>, built with the
dsn/user/pass from the config file. Used by the deploy, migrate, and
schema_version commands.

=cut

# Reproduce the old getopt behavior (no_ignore_case + bundling) for every
# command's own option parsing.
sub _option_processing_params {
	my ( $class, @args ) = @_;

	return ( $class->usage_desc(@args), $class->opt_spec(@args), { getopt_conf => [qw( no_ignore_case bundling )] }, );
}

sub config {
	my ($self) = @_;

	my $app = $self->app;
	return $app->{_config} if $app->{_config};

	my $file = $self->app->global_options->config;
	if ( !-f $file ) {
		die( '"' . $file . '" does not exist' . "\n" );
	}

	my $raw = read_file($file) or die( 'Failed to read "' . $file . '"' . "\n" );

	my ( $toml, $err ) = from_toml($raw);
	unless ($toml) {
		die "Error parsing toml,'" . $file . "'" . $err;
	}

	return $app->{_config} = $toml;
} ## end sub config

sub lilith {
	my ($self) = @_;

	my $app = $self->app;
	return $app->{_lilith} if $app->{_lilith};

	my $toml = $self->config;

	return $app->{_lilith} = Lilith->new(
		dsn                        => $toml->{dsn},
		user                       => $toml->{user},
		pass                       => $toml->{pass},
		debug                      => $self->app->global_options->debug,
		class_ignore               => $toml->{class_ignore},
		sid_ignore                 => $toml->{sid_ignore},
		suricata_class_ignore      => $toml->{suricata_class_ignore},
		suricata_sid_ignore        => $toml->{suricata_sid_ignore},
		sagan_class_ignore         => $toml->{sagan_class_ignore},
		sagan_sid_ignore           => $toml->{sagan_sid_ignore},
		escalation_type_namespaces => $toml->{escalation_type_namespaces},
	);
} ## end sub lilith

sub print_json {
	my ( $self, $data, $pretty ) = @_;

	my $json = JSON->new;
	if ($pretty) {
		$json->canonical(1);
		$json->pretty(1);
	}
	print $json->encode($data);
	if ( !$pretty ) {
		print "\n";
	}

	return;
} ## end sub print_json

sub table {
	my ( $self, @columns ) = @_;

	my $tb = Text::ANSITable->new;
	$tb->border_style( $ENV{Lilith_table_border} );
	$tb->color_theme( $ENV{Lilith_table_color} );

	my $header_int = 0;
	foreach my $header (@columns) {
		$tb->set_column_style( $header_int, pad => ( ( $header_int % 2 ) != 0 ? 1 : 0 ) );
		$header_int++;
	}
	$tb->columns( \@columns );

	return $tb;
} ## end sub table

sub output_opt_spec {
	return (
		[ 'output=s', 'output type: table or json', { default => 'table' } ],
		[ 'pretty',   'pretty print the JSON' ],
	);
}

sub output_dispatch {
	my ( $self, $opt, %renderers ) = @_;

	my $renderer = $renderers{ $opt->{output} };
	if ( !defined($renderer) ) {
		die('No applicable output found');
	}

	return $renderer->();
} ## end sub output_dispatch

sub migration {
	my ($self) = @_;

	my $toml = $self->config;

	require Lilith::Schema;
	require DBIx::Class::Migration;

	return DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $toml->{dsn}, $toml->{user}, $toml->{pass} ],
	);
} ## end sub migration

1;
