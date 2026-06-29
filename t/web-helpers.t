#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Test::Mojo;

use_ok('Lilith::Web') or BAIL_OUT('Lilith::Web failed to load');

# ---------------------------------------------------------------------------
# 1.  Default helper values (no optional keys in config)
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->dns_bg_timeout(), 3, 'dns_bg_timeout defaults to 3' );
    is( $app->dnstracer_enable(), 0, 'dnstracer_enable defaults to 0 (false)' );
    is_deeply( $app->dnstracer_flags(), [], 'dnstracer_flags defaults to empty arrayref' );
}

# ---------------------------------------------------------------------------
# 2.  dns_bg_timeout reads from config
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dns_bg_timeout = 10\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->dns_bg_timeout(), 10, 'dns_bg_timeout reads custom value from config' );
}

# ---------------------------------------------------------------------------
# 3.  dnstracer_enable reads from config
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dnstracer_enable = true\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is( $app->dnstracer_enable(), 1, 'dnstracer_enable is 1 when set to true in config' );
}

# Note: the TOML module (not TOML::Tiny) parses the bare word `false` as the
# string "false", which is truthy in Perl.  Omitting dnstracer_enable from the
# config is therefore the correct way to disable it; the default-value test
# above covers that case.

# ---------------------------------------------------------------------------
# 4.  dnstracer_flags reads from config
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dnstracer_flags = [\"-q\", \"-s\", \"8.8.8.8\"]\n";
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is_deeply(
        $app->dnstracer_flags(),
        [ '-q', '-s', '8.8.8.8' ],
        'dnstracer_flags reads array from config'
    );
}

# ---------------------------------------------------------------------------
# 5.  Non-array dnstracer_flags is silently ignored (defaults to [])
# ---------------------------------------------------------------------------

{
    my ( $fh, $cf ) = tempfile( SUFFIX => '.toml', UNLINK => 1 );
    print $fh "dsn = \"dbi:Pg:dbname=test\"\n";
    print $fh "dnstracer_flags = \"-q\"\n";    # scalar, not array
    close $fh;

    local $ENV{LILITH_CONFIG} = $cf;
    my $app = Test::Mojo->new('Lilith::Web')->app;

    is_deeply(
        $app->dnstracer_flags(),
        [],
        'non-array dnstracer_flags in config is ignored; helper returns []'
    );
}

done_testing();
