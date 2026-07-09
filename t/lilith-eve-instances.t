#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

# eve_instances() now lives in Lilith::CLI::Util (it was previously a plain sub
# in the src_bin/lilith script, string-eval'd out of it here).
use Lilith::CLI::Util qw( eve_instances );

# ---------------------------------------------------------------------------
# Instances are read from [eves.*] and keyed by the sub-table name.
# ---------------------------------------------------------------------------

{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    my $toml = {
        dsn          => 'dbi:Pg:dbname=test',
        class_ignore => [ 'a', 'b' ],           # array, not an instance
        eves         => {
            'suricata-eve' => { instance => 'foo-pie', type => 'suricata', eve => '/var/log/a.json' },
            'sagan-eve'    => { type     => 'sagan',   eve  => '/var/log/b.json' },
        },
    };

    my %files = eve_instances($toml);

    is_deeply(
        [ sort keys %files ],
        [ 'sagan-eve', 'suricata-eve' ],
        'instances come from the [eves.*] table'
    );
    is( $files{'suricata-eve'}{eve},  '/var/log/a.json', 'instance config carried through' );
    is( $files{'suricata-eve'}{type}, 'suricata',        'instance type carried through' );
    is( scalar(@warnings), 0, 'no warnings for a clean [eves.*] config' );
}

# ---------------------------------------------------------------------------
# No eves table => no instances (and no false positives from other config).
# ---------------------------------------------------------------------------

{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    my %files = eve_instances( { dsn => 'x', geoip_ip_city => '/p', class_ignore => ['a'] } );
    is_deeply( \%files, {}, 'no [eves.*] table yields no instances' );
    is( scalar(@warnings), 0, 'scalars/arrays do not trigger warnings' );
}

# ---------------------------------------------------------------------------
# A stray top-level table (old-style instance) is ignored but warned about.
# ---------------------------------------------------------------------------

{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    my $toml = {
        dsn            => 'x',
        'suricata-eve' => { type => 'suricata', eve => '/var/log/old.json' },    # old top-level style
        eves           => { 'new-eve' => { type => 'suricata', eve => '/var/log/new.json' } },
    };

    my %files = eve_instances($toml);

    is_deeply( [ keys %files ], ['new-eve'], 'stray top-level table is not treated as an instance' );
    ok(
        ( grep { /\[suricata-eve\].*\[eves\.suricata-eve\]/ } @warnings ),
        'stray top-level table warns with a "did you mean [eves.X]" hint'
    );
}

done_testing();
