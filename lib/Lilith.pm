package Lilith;

use 5.006;
use strict;
use warnings;
use POE qw(Wheel::FollowTail);
use JSON;
use Sys::Hostname;
use DBI;
use Digest::SHA qw(sha256_base64);
use File::ReadBackwards;

=head1 NAME

Lilith - Reads 

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    my $toml_raw = read_file($config_file) or die 'Failed to read "' . $config_file . '"';
    my ( $toml, $err ) = from_toml($toml_raw);
    unless ($toml) {
        die "Error parsing toml,'" . $config_file . "'" . $err;
    }

     Lilith->create_table(
                          dsn=>$toml->{dsn},
                          sagan=>$toml->{sagan},
                          suricata=>$toml->{suricata},
                          user=>$toml->{user},
                          pass=>$toml->{pass},
                         );

    my %files;
    my @toml_keys = keys( %{$toml} );
    my $int       = 0;
    while ( defined( $toml_keys[$int] ) ) {
        my $item = $toml_keys[$int];

        if ( ref( $toml->{$item} ) eq "HASH" ) {
                # add the file in question
                $files{$item} = $toml->{$item};
        }

        $int++;
    }

    Lilith->run(
                dsn=>$toml->{dsn},
                sagan=>$toml->{sagan},
                suricata=>$toml->{suricata},
                user=>$toml->{user},
                pass=>$toml->{pass},
                files=>\%files,
               );

=head1 FUNCTIONS

=head2 run

Start processing.

    Lilith->run(
                dsn=>$toml->{dsn},
                sagan=>$toml->{sagan},
                suricata=>$toml->{suricata},
                user=>$toml->{user},
                pass=>$toml->{pass},
                files=>\%files,
               );

=cut

sub run {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user} = 'lilith';
	}

	if ( !defined( $opts{sagan} ) ) {
		$opts{sagan} = 'sagan_alerts';
	}

	if ( !defined( $opts{suricata} ) ) {
		$opts{suricata} = 'suricata_alerts';
	}

	my $dbh = DBI->connect_cached( $opts{dsn}, $opts{user}, $opts{pass} );

	# process each file
	my $file_count = 0;
	foreach my $item_key ( keys( %{ $opts{files} } ) ) {
		my $item = $opts{files}->{$item_key};
		if ( !defined( $item->{instance} ) ) {
			warn( 'No instance name specified for ' . $item_key . ' so using that as the instance name' );
			$item->{instance} = $item_key;
		}

		if ( !defined( $item->{type} ) ) {
			die( 'No type specified for ' . $item->{instance} );
		}

		if ( !defined( $item->{eve} ) ) {
			die( 'No file specified for ' . $item->{instance} );
		}

		# create each POE session out for each EVE file we are following
		POE::Session->create(
			inline_states => {
				_start => sub {
					$_[HEAP]{tailor} = POE::Wheel::FollowTail->new(
						Filename   => $_[HEAP]{eve},
						InputEvent => "got_log_line",
					);
				},
				got_log_line => sub {
					my $json;
					eval { $json = decode_json( $_[ARG0] ) };
					if ($@) {
						return;
					}

					eval {
						if (   defined($json)
							&& defined( $json->{event_type} )
							&& $json->{event_type} eq 'alert' )
						{
							# put the event ID together
							my $event_id
								= sha256_base64( $_[HEAP]{instance}
									. $_[HEAP]{host}
									. $json->{timestamp}
									. $json->{flow_id}
									. $json->{in_iface} );

							# handle if suricata
							if ( $_[HEAP]{type} eq 'suricata' ) {
								my $sth
									= $_[HEAP]{dbh}->prepare( 'insert into '
										. $_[HEAP]{suricata}
										. ' ( instance, host, timestamp, flow_id, event_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, app_proto, flow_pkts_toserver, flow_bytes_toserver, flow_pkts_toclient, flow_bytes_toclient, flow_start, raw ) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);' );
								$sth->execute(
									$_[HEAP]{instance},           $_[HEAP]{host},
									$json->{timestamp},           $event_id,
									$json->{flow_id},             $json->{in_iface},
									$json->{src_ip},              $json->{src_port},
									$json->{dest_ip},             $json->{dest_port},
									$json->{proto},               $json->{app_proto},
									$json->{flow}{pkts_toserver}, $json->{flow}{bytes_toserver},
									$json->{flow}{pkts_toclient}, $json->{flow}{bytes_toclient},
									$json->{flow}{start},         $_[ARG0]
								);
							}

							#handle if sagan
							elsif ( $_[HEAP]{type} eq 'sagan' ) {
								my $sth
									= $dbh->prepare( 'insert into '
										. $_[HEAP]{sagan}
										. ' ( instance, instance_host, timestamp, event_id, flow_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, facility, host, level, priority, program, proto, xff, stream, raw) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );' );
								$sth->execute(
									$_[HEAP]{instance}, $_[HEAP]{host},     $json->{timestamp}, $event_id,
									$json->{flow_id},   $json->{in_iface},  $json->{src_ip},    $json->{src_port},
									$json->{dest_ip},   $json->{dest_port}, $json->{proto},     $json->{facility},
									$json->{host},      $json->{level},     $json->{priority},  $json->{program},
									$json->{proto},     $json->{xff},       $json->{stream},    $_[ARG0],
								);
							}
						}
						if ($@) {
							warn( 'SQL INSERT issue... ' . $@ );
						}
					}

				},
			},
			heap => {
				eve      => $item->{eve},
				type     => $item->{type},
				suricata => $opts{suricata},
				sagan    => $opts{sagan},
				dbh      => $dbh,
				host     => hostname,
				instance => $item->{instance},
			},
		);

	}

	POE::Kernel->run;
}

=head2 create_tables

Just creates the required tables in the DB.

     Lilith->create_tables(
                          dsn=>$toml->{dsn},
                          sagan=>$toml->{sagan},
                          suricata=>$toml->{suricata},
                          user=>$toml->{user},
                          pass=>$toml->{pass},
                         );

=cut

sub create_tables {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user} = 'lilith';
	}

	if ( !defined( $opts{sagan} ) ) {
		$opts{sagan} = 'sagan_alerts';
	}

	if ( !defined( $opts{suricata} ) ) {
		$opts{suricata} = 'suricata_alerts';
	}

	my $dbh = DBI->connect_cached( $opts{dsn}, $opts{user}, $opts{pass} );

	my $sth
		= $dbh->prepare( 'create table '
			. $opts{suricata} . ' ('
			. 'id bigserial NOT NULL, '
			. 'instance varchar(255),'
			. 'host varchar(255),'
			. 'timestamp TIMESTAMP WITH TIME ZONE, '
			. 'event_id varchar(64), '
			. 'flow_id bigint, '
			. 'in_iface varchar(255), '
			. 'src_ip inet, '
			. 'src_port integer, '
			. 'dest_ip inet, '
			. 'dest_port integer, '
			. 'proto varchar(32), '
			. 'app_proto varchar(255), '
			. 'flow_pkts_toserver integer, '
			. 'flow_bytes_toserver integer, '
			. 'flow_pkts_toclient integer, '
			. 'flow_bytes_toclient integer, '
			. 'flow_start TIMESTAMP WITH TIME ZONE, '
			. 'raw json NOT NULL, '
			. 'PRIMARY KEY(id) );' );
	$sth->execute();

	$sth
		= $dbh->prepare( 'create table '
			. $opts{sagan} . ' ('
			. 'id bigserial NOT NULL, '
			. 'instance varchar(255), '
			. 'instance_host varchar(255), '
			. 'timestamp TIMESTAMP WITH TIME ZONE, '
			. 'event_id varchar(64), '
			. 'flow_id bigint, '
			. 'in_iface varchar(255), '
			. 'src_ip inet, '
			. 'src_port integer, '
			. 'dest_ip inet, '
			. 'dest_port integer, '
			. 'proto varchar(32), '
			. 'facility varchar(255), '
			. 'host varchar(255), '
			. 'level varchar(255), '
			. 'priority varchar(255), '
			. 'program varchar(255), '
			. 'xff inet, '
			. 'stream bigint, '
			. 'raw json NOT NULL, '
			. 'PRIMARY KEY(id) );' );
	$sth->execute();
}

=head2 extend

	Lilith->extend(
		dsn      => $toml->{dsn},
		sagan    => $toml->{sagan},
		suricata => $toml->{suricata},
		user     => $toml->{user},
		pass     => $toml->{pass},
		files    => \%files,
		rules    => $rules_toml,
	);

=cut

sub extend {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{max_age} ) ) {
		$opts{max_age} = 300;
	}

	my @rule_keys = keys( %{ $opts{rules} } );

	my $host = hostname;

	my $from = time;
	my $till = $from - $opts{max_age};

	# librenms return hash
	my $to_return = {
		data        => {},
		version     => 1,
		error       => '0',
		errorString => '',
		alert       => '0',
		alertString => ''
	};

	# IDs of found alerts
	my @suricata_alert_ids;
	my @sagan_alert_ids;

}

=head2 search

=cut

sub search {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{max_age} ) ) {
		$opts{max_age} = 300;
	}

	my @rule_keys = keys( %{ $opts{rules} } );

	my $host = hostname;

	my $dbh = DBI->connect_cached( $opts{dsn}, $opts{user}, $opts{pass} );

	
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-lilith at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Lilith>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Lilith


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Lilith>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Lilith>

=item * Search CPAN

L<https://metacpan.org/release/Lilith>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Lilith
