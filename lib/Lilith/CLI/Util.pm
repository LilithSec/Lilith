package Lilith::CLI::Util;

use strict;
use warnings;
use Exporter    qw( import );
use File::Slurp qw( read_file );
use JSON        qw( decode_json );

our @EXPORT_OK = qw(
	eve_instances
	esc_parse_set
	esc_lookup_target
	esc_resolve_targets
	ae_read_rule
);

=head1 NAME

Lilith::CLI::Util - shared helper functions for the C<lilith> subcommands.

=head1 DESCRIPTION

These were plain subs in the old monolithic C<lilith> script (and were pulled
out of it by string-eval in the test suite). They now live here so the commands
and the tests can just import them.

=head1 FUNCTIONS

=head2 eve_instances( $toml )

Builds the instance => config hash for C<< Lilith->run >> from the parsed TOML.
EVE instances live under the C<[eves.*]> table; any leftover top-level table is
warned about in case it is an old-style instance definition.

=head2 esc_parse_set( @set )

Parses repeated C<--set key=value> items into a config hash ref, dying on
anything malformed.

=head2 esc_lookup_target( $lilith, $tid, $name )

Looks up a escalation target, by C<$tid> when given and by C<$name> otherwise.

=head2 esc_resolve_targets( $lilith, $to )

Resolves the comma separated C<--to> list into an array ref of escalation
target IDs.

=head2 ae_read_rule( $rule )

Reads the C<--rule> value, either a JSON string or, when it begins with C<@>,
the path to a file holding the JSON. Returns the decoded hash ref.

=cut

sub eve_instances {
	my ($toml) = @_;

	my %files;
	if ( ref( $toml->{eves} ) eq 'HASH' ) {
		foreach my $name ( keys( %{ $toml->{eves} } ) ) {
			next unless ref( $toml->{eves}{$name} ) eq 'HASH';
			$files{$name} = $toml->{eves}{$name};
		}
	}

	# Warn about stray top-level tables, which were instances prior to the move
	# under [eves.*].
	foreach my $key ( keys( %{$toml} ) ) {
		next if $key eq 'eves';
		next unless ref( $toml->{$key} ) eq 'HASH';
		warn(     'Top-level table ['
				. $key
				. '] is no longer used as an EVE instance; '
				. 'did you mean [eves.'
				. $key . ']?'
				. "\n" );
	} ## end foreach my $key ( keys( %{$toml} ) )

	return %files;
} ## end sub eve_instances

sub esc_parse_set {
	my (@set) = @_;

	my %config;
	foreach my $item (@set) {
		if ( $item =~ /^([A-Za-z0-9_]+)=(.*)$/s ) {
			$config{$1} = $2;
		} else {
			die( '"' . $item . '" for --set is not in the form key=value' );
		}
	}

	return \%config;
} ## end sub esc_parse_set

sub esc_lookup_target {
	my ( $lilith, $tid, $name ) = @_;

	if ( defined($tid) && $tid ne '' ) {
		if ( $tid !~ /^[0-9]+$/ ) {
			die( '"' . $tid . '" for --tid is not numeric' );
		}
		return $lilith->escalation_target_get($tid);
	}

	if ( defined($name) && $name ne '' ) {
		my $targets = $lilith->escalation_targets;
		my ($match) = grep { $_->{name} eq $name } @{$targets};
		if ( !$match ) {
			die(      'no escalation target named "'
					. $name . '"'
					. ( @{$targets} ? '; known: ' . join( ', ', map { $_->{name} } @{$targets} ) : '' ) );
		}
		return $match;
	} ## end if ( defined($name) && $name ne '' )

	die('either --tid or --name is required for picking the escalation target');
} ## end sub esc_lookup_target

sub esc_resolve_targets {
	my ( $lilith, $to ) = @_;

	my @tokens = grep { $_ ne '' } split( /\s*,\s*/, defined($to) ? $to : '' );
	if ( !@tokens ) {
		die('--to is required and must be a comma separated list of escalation target IDs or names');
	}

	my $targets;
	my @ids;
	foreach my $token (@tokens) {
		if ( $token =~ /^[0-9]+$/ ) {
			push( @ids, $token );
			next;
		}

		if ( !defined($targets) ) {
			$targets = $lilith->escalation_targets;
		}
		my ($match) = grep { $_->{name} eq $token } @{$targets};
		if ( !$match ) {
			die(      'no escalation target named "'
					. $token . '"'
					. ( @{$targets} ? '; known: ' . join( ', ', map { $_->{name} } @{$targets} ) : '' ) );
		}
		push( @ids, $match->{id} );
	} ## end foreach my $token (@tokens)

	return \@ids;
} ## end sub esc_resolve_targets

sub ae_read_rule {
	my ($rule) = @_;

	if ( !defined($rule) || $rule eq '' ) {
		die('--rule is required and must be a JSON object (or @file)');
	}

	my $json = $rule;
	if ( $rule =~ /^\@(.+)$/ ) {
		my $file = $1;
		$json = read_file($file) or die( 'failed to read rule file "' . $file . '"' );
	}

	my $decoded;
	eval { $decoded = decode_json($json); };
	if ( $@ || ref($decoded) ne 'HASH' ) {
		die( 'could not parse --rule as a JSON object: ' . ( $@ ? $@ : 'not a object' ) );
	}

	return $decoded;
} ## end sub ae_read_rule

1;
