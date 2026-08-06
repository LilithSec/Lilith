# migrate -- move an already-deployed database to the schema this release
# expects. A no-op when it is already current; use deploy for an empty
# database. See docs/install.md for the upgrade notes, in particular that the
# 4 -> 5 step builds indexes and blocks writes while it does.
#
#     lilith migrate
package Lilith::CLI::Command::Migrate;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::Schema ();

sub command_names { 'migrate' }

sub abstract { 'upgrade an existing database to the current schema' }

sub usage_desc { '%c migrate %o' }

sub description {
	return
		  "Upgrades an already-deployed database to the schema version this release\n"
		. "expects, using DBIx::Class::Migration and the config file's dsn/user/pass. It\n"
		. "is a no-op when the database is already current. For a fresh, empty database\n"
		. "use deploy instead.\n\n"
		. "The 4 -> 5 step adds indexes to existing tables: a plain CREATE INDEX blocks\n"
		. "writes (the ingest daemon and the receiver) until each finishes building, while\n"
		. "reads keep working, so run it during a quiet window on a busy sensor.";
} ## end sub description

# Upgrade the database to the current schema.
#
# Args:
#
#   - $opt :: the parsed options. This command has none; the connection details
#     come from the config file.
#   - $args :: array ref of leftover positional arguments. Unused.
#
# Returns: nothing meaningful. Prints the version the database now carries. A
# no-op when it was already current. Dies with 'Failed to upgrade the
# schema... ' and the underlying error otherwise, which is what running it
# against a database that was never deployed gives.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $migration = $self->migration;

	eval { $migration->upgrade; };
	if ($@) {
		die( 'Failed to upgrade the schema... ' . $@ );
	}

	print 'schema is now at version ' . $Lilith::Schema::VERSION . "\n";

	return;
} ## end sub execute

1;
