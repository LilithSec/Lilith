#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Find ();
use File::Spec ();

# Every share/fixtures/<version>/conf directory must carry a placeholder file so
# the directory survives in git and, crucially, installs: DBIx::Class::Migration
# expects fixtures/<version>/conf to already exist under the share dir and, when
# it does not, tries to mkdir it there -- which fails for a non-root
# `lilith migrate` against a root-owned system share dir.
#
# The placeholder must NOT be named ".exists": ExtUtils::Install hardcodes
# skipping that reserved MakeMaker marker name (return if $origfile eq ".exists"),
# so a .exists placeholder is silently dropped at `make install` and the
# directory never appears. This test guards against reintroducing that name.

my $fixtures = File::Spec->catdir(qw( share fixtures ));
plan skip_all => "no $fixtures directory (not run from the dist root)"
	unless -d $fixtures;

my @conf_dirs;
File::Find::find(
	sub { push @conf_dirs, $File::Find::name if -d $_ && $_ eq 'conf' },
	$fixtures,
);
@conf_dirs = sort @conf_dirs;

ok( scalar @conf_dirs, "found fixtures conf directories under $fixtures" );

for my $dir (@conf_dirs) {
	opendir( my $dh, $dir ) or die "opendir $dir: $!";
	my @files = grep { $_ ne '.' && $_ ne '..' && -f File::Spec->catfile( $dir, $_ ) } readdir($dh);
	closedir($dh);

	ok( scalar @files, "$dir carries a placeholder file (so the dir installs)" );
	is_deeply(
		[ grep { $_ eq '.exists' } @files ],
		[],
		"$dir has no reserved .exists placeholder (ExtUtils::Install would skip it)"
	);
}

done_testing;
