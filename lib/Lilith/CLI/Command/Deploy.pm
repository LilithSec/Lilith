# deploy -- install the current schema into an empty database. Run once, after
# the database and role exist; use migrate for one already deployed. See
# docs/install.md.
#
#     lilith deploy
package Lilith::CLI::Command::Deploy;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::Schema ();

sub command_names { 'deploy' }

sub abstract { 'deploy the schema into a fresh database' }

sub description {
	return
		  "Installs the current schema version into an empty database using\n"
		. "DBIx::Class::Migration, reading dsn/user/pass from the config file. Run this\n"
		. "once, after the database and role exist. For an already-deployed database that\n"
		. "needs to move to a newer schema, use migrate instead.";
}

# Install the schema into an empty database.
#
# Args:
#
#   - $opt :: the parsed options. This command has none; the connection details
#     come from the config file.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the version it deployed. Dies with
# 'Failed to deploy the schema... ' and the underlying error otherwise, which
# is what running it against a database that already has the schema gives.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $migration = $self->migration;

	eval { $migration->install; };
	if ($@) {
		die( 'Failed to deploy the schema... ' . $@ );
	}

	print 'deployed schema version ' . $Lilith::Schema::VERSION . "\n";

	return;
} ## end sub execute

1;
