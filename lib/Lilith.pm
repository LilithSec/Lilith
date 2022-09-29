package Lilith;

use 5.006;
use strict;
use warnings;
use POE qw(Wheel::FollowTail);
use JSON;
use Sys::Hostname;
use DBI;

=head1 NAME

Lilith - Reads 

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Lilith;

    my $lilith = Lilith->run({
                              dsn=>'dbi:Pg:dbname='
                              pw=>''
                              user=>''
                              eves=>
                              }
                             );


=head1 FUNCTIONS

=head2 run

=cut

sub run {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{eve} ) ) {
		die('"eve" is not defined');
	}

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user}='lilith';
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
	foreach my $item ( keys( %{ $opts{files} } ) ) {

		POE::Session->create(
			inline_states => {
				_start => sub {
					$_[HEAP]{tailor} = POE::Wheel::FollowTail->new(
						Filename   => $_[HEAP]{file},
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
						}
						if ( $_[HEAP]{type} eq 'suricata' ) {
							my $sth = $_[HEAP]{dbh}->do(
								'insert into ? '
									. ' ( sensor, host, timestamp, flow_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, app_proto, flow_pkts_toserver, flow_bytes_toserver, flow_pkts_toclient, flow_bytes_toclient, flow_start, raw ) '
									. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);',
								$_[HEAP]{suricata},            $_[HEAP]{host},
								$json->{timestamp},            $json->{flow_id},
								$json->{in_iface},             $json->{src_ip},
								$json->{src_port},             $json->{dest_ip},
								$json->{dest_port},            $json->{proto},
								$json->{app_proto},            $json->{flow}{pkts_toserver},
								$json->{flow}{bytes_toserver}, $json->{flow}{pkts_toclient},
								$json->{flow}{bytes_toclient}, $json->{flow}{start},
								$json
							);
						}
						elsif ( $_[HEAP]{type} eq 'sagan' ) {
							my $sth = $dbh->prepare(
								'insert into ?'
									. ' ( sensor, sensor_host, timestamp, flow_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, facility, host, level, priority, program, proto, xff, stream, raw) '
									. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );',
								$_[HEAP]{suricata}, $_[HEAP]{host},    $json->{timestamp}, $json->{flow_id},
								$json->{in_iface},  $json->{src_ip},   $json->{src_port},  $json->{dest_ip},
								$json->{dest_port}, $json->{proto},    $json->{facility},  $json->{host},
								$json->{level},     $json->{priority}, $json->{program},   $json->{proto},
								$json->{xff},       $json->{stream},   $json,
							);
						}
					};
					if ($@) {
						warn( 'SQL INSERT issue... ' . $@ );
					}

				},
			},
			heap => {
				file     => $item->{eve},
				type     => $item->{type},
				suricata => $opts{suricata},
				sagan    => $opts{sagan},
				dbh      => $dbh,
				host     => hostname,
			},
		);

	}

	POE::Kernel->run;
}

=head2 create_table

=cut

sub create_table {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user}='lilith';
	}

	if ( !defined( $opts{sagan} ) ) {
		$opts{sagan} = 'sagan_alerts';
	}

	if ( !defined( $opts{suricata} ) ) {
		$opts{suricata} = 'suricata_alerts';
	}

	my $dbh = DBI->connect_cached( $opts{dsn}, $opts{user}, $opts{pass} );

	my $sth
		= $dbh->prepare( 'create table '.$opts{suricata}.' ('
			. 'id bigserial NOT NULL, '
			. 'sensor varchar(255),'
			. 'host varchar(255),'
			. 'timestamp TIMESTAMP WITH TIME ZONE, '
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
	$sth->execute( );

	$sth
		= $dbh->prepare( 'create table '.$opts{sagan}.' ('
			. 'id bigserial NOT NULL, '
			. 'sensor varchar(255), '
			. 'sensor_host varchar(255), '
			. 'timestamp TIMESTAMP WITH TIME ZONE, '
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
	$sth->execute( );
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
