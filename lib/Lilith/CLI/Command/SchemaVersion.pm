package Lilith::CLI::Command::SchemaVersion;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Lilith::Schema ();

sub command_names { 'schema_version' }

sub abstract { 'show the deployed schema version and this release' }

sub usage_desc { '%c schema_version %o' }

sub description {
	return
		  "Prints the schema version recorded in the database alongside the version this\n"
		. "release of Lilith expects, and whether a deploy or upgrade is pending. Reads\n"
		. "dsn/user/pass from the config file and changes nothing.";
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $migration = $self->migration;

	my $code = $Lilith::Schema::VERSION;

	# database_version dies when the version-storage table is absent (a database
	# that has never been deployed); treat that as "none deployed".
	my $installed;
	eval { $installed = $migration->dbic_dh->database_version; };

	print 'this release: ' . $code . "\n";
	if ( !defined($installed) ) {
		print "deployed:     none (run: lilith deploy)\n";
	} else {
		print 'deployed:     ' . $installed . "\n";
		if ( $installed < $code ) {
			print "status:       upgrade pending (run: lilith migrate)\n";
		} elsif ( $installed == $code ) {
			print "status:       current\n";
		} else {
			print "status:       database is newer than this release\n";
		}
	} ## end else [ if ( !defined($installed) ) ]

	return;
} ## end sub execute

1;
