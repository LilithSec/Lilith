package Lilith::CLI::Command::Deploy;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::Schema         ();
use DBIx::Class::Migration ();

sub command_names { 'deploy' }

sub abstract { 'deploy the schema into a fresh database' }

sub usage_desc { '%c deploy %o' }

sub description {
	return
		  "Installs the current schema version into an empty database using\n"
		. "DBIx::Class::Migration, reading dsn/user/pass from the config file. Run this\n"
		. "once, after the database and role exist. For an already-deployed database that\n"
		. "needs to move to a newer schema, use migrate instead.";
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $toml = $self->config;

	my $migration = DBIx::Class::Migration->new(
		schema_class => 'Lilith::Schema',
		schema_args  => [ $toml->{dsn}, $toml->{user}, $toml->{pass} ],
	);

	eval { $migration->install; };
	if ($@) {
		die( 'Failed to deploy the schema... ' . $@ );
	}

	print 'deployed schema version ' . $Lilith::Schema::VERSION . "\n";

	return;
} ## end sub execute

1;
