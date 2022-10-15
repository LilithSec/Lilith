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

     my $lilith=Lilith->new(
                            dsn=>$toml->{dsn},
                            sagan=>$toml->{sagan},
                            suricata=>$toml->{suricata},
                            user=>$toml->{user},
                            pass=>$toml->{pass},
                           );


     $lilith->create_table(
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

    $ilith->run(
                files=>\%files,
               );

=head1 FUNCTIONS

=head1 new

Initiates it.

    my $lilith=Lilith->run(
                           dsn=>$toml->{dsn},
                           sagan=>$toml->{sagan},
                           suricata=>$toml->{suricata},
                           user=>$toml->{user},
                           pass=>$toml->{pass},
                          );

=cut

sub new{
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

	my $self={
			  dsn=>$opts{dsn},
			  user=>$opts{user},
			  pass=>$opts{pass},
			  sagan=>$opts{sagan},
			  suricata=>$opts{suricata},
			  };
	bless $self;

	return $self;
}

=head2 run

Start processing.

    $lilith->run(
                 files=>\%files,
                );

=cut

sub run {
	my ( $self, %opts ) = @_;

	my $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} );

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
										. ' ( instance, host, timestamp, flow_id, event_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, app_proto, flow_pkts_toserver, flow_bytes_toserver, flow_pkts_toclient, flow_bytes_toclient, flow_start, classification, signature, gid, sid, rev, raw ) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);
								$sth->execute(
									$_[HEAP]{instance},           $_[HEAP]{host},
									$json->{timestamp},           $event_id,
									$json->{flow_id},             $json->{in_iface},
									$json->{src_ip},              $json->{src_port},
									$json->{dest_ip},             $json->{dest_port},
									$json->{proto},               $json->{app_proto},
									$json->{flow}{pkts_toserver}, $json->{flow}{bytes_toserver},
									$json->{flow}{pkts_toclient}, $json->{flow}{bytes_toclient},
									$json->{flow}{start},         $json->{alert}{category},
									$json->{alert}{signature},    $json->{alert}{gid},
									$json->{alert}{signature_id}, $json->{alert}{rev},
									$_[ARG0]
								);
							}

							#handle if sagan
							elsif ( $_[HEAP]{type} eq 'sagan' ) {
								my $sth
									= $dbh->prepare( 'insert into '
										. $_[HEAP]{sagan}
										. ' ( instance, instance_host, timestamp, event_id, flow_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, facility, host, level, priority, program, proto, xff, stream, classification, signature, gid, sid, rev, raw) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);
								$sth->execute(
									$_[HEAP]{instance},           $_[HEAP]{host},
									$json->{timestamp},           $event_id,
									$json->{flow_id},             $json->{in_iface},
									$json->{src_ip},              $json->{src_port},
									$json->{dest_ip},             $json->{dest_port},
									$json->{proto},               $json->{facility},
									$json->{host},                $json->{level},
									$json->{priority},            $json->{program},
									$json->{proto},               $json->{xff},
									$json->{stream},              $json->{alert}{category},
									$json->{alert}{signature},    $json->{alert}{gid},
									$json->{alert}{signature_id}, $json->{alert}{rev},
									$_[ARG0],
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
				suricata => $self->{suricata},
				sagan    => $self->{sagan},
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

     $lilith->create_tables(
                            dsn=>$toml->{dsn},
                            sagan=>$toml->{sagan},
                            suricata=>$toml->{suricata},
                            user=>$toml->{user},
                            pass=>$toml->{pass},
                           );

=cut

sub create_tables {
	my ( $self, %opts ) = @_;

	my $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} );

	my $sth
		= $dbh->prepare( 'create table '
			. $self->{suricata} . ' ('
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
			. 'classification varchar(1024), '
			. 'signature varchar(2048),'
			. 'gid int, '
			. 'sid bigint, '
			. 'rev bigint, '
			. 'raw json NOT NULL, '
			. 'PRIMARY KEY(id) );' );
	$sth->execute();

	$sth
		= $dbh->prepare( 'create table '
			. $self->{sagan} . ' ('
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
			. 'classification varchar(1024), '
			. 'signature varchar(2048),'
			. 'gid int, '
			. 'sid bigint, '
			. 'rev bigint, '
			. 'raw json NOT NULL, '
			. 'PRIMARY KEY(id) );' );
	$sth->execute();
}

=head2 extend

	my $return=$lilith->extend(
		                       max_age=>5,
	                          );

=cut

sub extend {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{max_age} ) ) {
		$opts{max_age} = 5;
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
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{table} ) ) {
		$opts{table} = 'suricata';
	}
	else {
		if ( $opts{table} ne 'suricata' && $opts{table} ne 'sagan' ) {
			die( '"' . $opts{table} . '" is not a known table type' );
		}
	}

	if ( !defined( $opts{go_back_minutes} ) ) {
		$opts{go_back_minutes} = '5';
	}
	else {
		if ( $opts{go_back_minutes} =~ /^[0-9]+$/ ) {
			die( '"' . $opts{go_back_minutes} . '" for go_back_minutes is not numeric' );
		}
	}

	my $table = $self->{suricata};
	if ( $opts{table} eq 'sagan' ) {
		$table = $self->{sagan};
	}

	my @rule_keys = keys( %{ $opts{rules} } );

	my $host = hostname;

	my $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} );

	my @sql_args;
	my $sql
		= 'select * from '
		. $table
		. " where timestamp >= CURRENT_TIMESTAMP - interval '"
		. $opts{go_back_minutes}
		. " minutes'";

	if ( defined( $opts{src_ip} ) ) {
		push( @sql_args, $opts{src_ip} );
		$sql = $sql . ' and src_ip = ?';
	}

	if ( defined( $opts{src_port} ) ) {
		push( @sql_args, $opts{src_port} );
		$sql = $sql . ' and src_port = ?';
	}

	if ( defined( $opts{dst_ip} ) ) {
		push( @sql_args, $opts{dst_ip} );
		$sql = $sql . ' and dst_ip = ?';
	}

	if ( defined( $opts{dst_port} ) ) {
		push( @sql_args, $opts{dst_port} );
		$sql = $sql . ' and dst_port = ?';
	}

	if ( defined( $opts{ip} ) ) {
		push( @sql_args, $opts{ip} );
		push( @sql_args, $opts{ip} );
		$sql = $sql . ' and ( src_ip = ? or dst_ip = ? )';
	}

	if ( defined( $opts{port} ) ) {
		push( @sql_args, $opts{port} );
		push( @sql_args, $opts{port} );
		$sql = $sql . ' and ( src_port = ? or dst_port = ? )';
	}

	if ( defined( $opts{alert_id} ) ) {
		push( @sql_args, $opts{alert_id} );
		$sql = $sql . ' and alert_id = ?';
	}

	if ( defined( $opts{host} ) ) {
		push( @sql_args, $opts{host} );
		if ( defined( $opts{host_like} ) && $opts{host_like} ) {
			$sql = $sql . ' and host like ?';
		}
		else {
			$sql = $sql . ' and host = ?';
		}
	}

	if ( defined( $opts{instance_host} ) ) {
		push( @sql_args, $opts{instance_host} );
		if ( defined( $opts{host_like} ) && $opts{instance_host_like} ) {
			$sql = $sql . ' and instance_host like ?';
		}
		else {
			$sql = $sql . ' and instance_host = ?';
		}
	}

	if ( defined( $opts{in_iface_like} ) ) {
		push( @sql_args, $opts{in_iface} );
		if ( defined( $opts{in_iface_like} ) && $opts{in_iface_like} ) {
			$sql = $sql . ' and in_iface like ?';
		}
		else {
			$sql = $sql . ' and in_iface = ?';
		}
	}

	if ( defined( $opts{proto} ) ) {
		push( @sql_args, $opts{proto} );
		$sql = $sql . ' and proto = ?';
	}

	if ( defined( $opts{app_proto} ) ) {
		push( @sql_args, $opts{app_proto} );
		if ( defined( $opts{app_proto_like} ) && $opts{app_proto_like} ) {
			$sql = $sql . ' and app_proto like ?';
		}
		else {
			$sql = $sql . ' and app_proto = ?';
		}
	}

	if ( defined( $opts{instance} ) ) {
		push( @sql_args, $opts{instance} );
		if ( defined( $opts{instance_like} ) && $opts{instance_like} ) {
			$sql = $sql . ' and instance like ?';
		}
		else {
			$sql = $sql . ' and instance = ?';
		}
	}

	if ( defined( $opts{class} ) ) {
		push( @sql_args, $opts{class} );
		if ( defined( $opts{class_like} ) && $opts{class_like} ) {
			$sql = $sql . ' and classification like ?';
		}
		else {
			$sql = $sql . ' and classification = ?';
		}
	}

	if ( defined( $opts{signature} ) ) {
		push( @sql_args, $opts{signature} );
		if ( defined( $opts{signature_like} ) && $opts{signature_like} ) {
			$sql = $sql . ' and signature like ?';
		}
		else {
			$sql = $sql . ' and signature = ?';
		}
	}

	if (defined($opts{gid})) {
		# remove and tabs or spaces
		$opts{gid}=~s/[\ \t]//g;
		my @arg_split=split(/\,/, $opts{gid});
		# process each item
		foreach my $arg (@arg_split) {
			# match the start of the item
			if ($arg =~ /^[0-9]+$/) {
				push(@sql_args, $arg);
				$sql = $sql . ' and gid = ?';
			}elsif ($arg =~ /^\<\=[0-9]+$/) {
				$arg=~s/^\<\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid <= ?';
			}elsif ($arg =~ /^\<[0-9]+$/) {
				$arg=~s/^\<//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid < ?';
			}elsif ($arg =~ /^\>\=[0-9]+$/) {
				$arg=~s/^\>\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid >= ?';
			}elsif ($arg =~ /^\>[0-9]+$/) {
				$arg=~s/^\>\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid > ?';
			}elsif ($arg =~ /^\![0-9]+$/) {
				$arg=~s/^\!//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid != ?';
			}elsif ($arg =~ /^$/) {
				# only exists for skipping when some one has passes something starting
				# with a ,, ending with a,, or with ,, in it.
			}else {
				# if we get here, it means we don't have a valid use case for what ever was passed and should error
				die('"'.$arg.'" does not appear to be a valid item for a numeric search for the gid');
			}
		}
	}

	if (defined($opts{sid})) {
		# remove and tabs or spaces
		$opts{sid}=~s/[\ \t]//g;
		my @arg_split=split(/\,/, $opts{sid});
		# process each item
		foreach my $arg (@arg_split) {
			# match the start of the item
			if ($arg =~ /^[0-9]+$/) {
				push(@sql_args, $arg);
				$sql = $sql . ' and sid = ?';
			}elsif ($arg =~ /^\<\=[0-9]+$/) {
				$arg=~s/^\<\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and sid <= ?';
			}elsif ($arg =~ /^\<[0-9]+$/) {
				$arg=~s/^\<//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid < ?';
			}elsif ($arg =~ /^\>\=[0-9]+$/) {
				$arg=~s/^\>\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and sid >= ?';
			}elsif ($arg =~ /^\>[0-9]+$/) {
				$arg=~s/^\>\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and sid > ?';
			}elsif ($arg =~ /^\![0-9]+$/) {
				$arg=~s/^\!//;
				push(@sql_args, $arg);
				$sql = $sql . ' and sid != ?';
			}elsif ($arg =~ /^$/) {
				# only exists for skipping when some one has passes something starting
				# with a ,, ending with a,, or with ,, in it.
			}else {
				# if we get here, it means we don't have a valid use case for what ever was passed and should error
				die('"'.$arg.'" does not appear to be a valid item for a numeric search for the sid');
			}
		}
	}

		if (defined($opts{sid})) {
		# remove and tabs or spaces
		$opts{rev}=~s/[\ \t]//g;
		my @arg_split=split(/\,/, $opts{rev});
		# process each item
		foreach my $arg (@arg_split) {
			# match the start of the item
			if ($arg =~ /^[0-9]+$/) {
				push(@sql_args, $arg);
				$sql = $sql . ' and rev = ?';
			}elsif ($arg =~ /^\<\=[0-9]+$/) {
				$arg=~s/^\<\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and rev <= ?';
			}elsif ($arg =~ /^\<[0-9]+$/) {
				$arg=~s/^\<//;
				push(@sql_args, $arg);
				$sql = $sql . ' and gid < ?';
			}elsif ($arg =~ /^\>\=[0-9]+$/) {
				$arg=~s/^\>\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and rev >= ?';
			}elsif ($arg =~ /^\>[0-9]+$/) {
				$arg=~s/^\>\=//;
				push(@sql_args, $arg);
				$sql = $sql . ' and rev > ?';
			}elsif ($arg =~ /^\![0-9]+$/) {
				$arg=~s/^\!//;
				push(@sql_args, $arg);
				$sql = $sql . ' and rev != ?';
			}elsif ($arg =~ /^$/) {
				# only exists for skipping when some one has passes something starting
				# with a ,, ending with a,, or with ,, in it.
			}else {
				# if we get here, it means we don't have a valid use case for what ever was passed and should error
				die('"'.$arg.'" does not appear to be a valid item for a numeric search for the rev');
			}
		}
	}

	$sql = $sql . ';';

	my $sth = $dbh->prepare($sql);
	$sth->execute(@sql_args);

	my $found = ();
	while ( my $row = $sth->fetchrow_hashref ) {
		push( @{$found}, $row );
	}

	return $found;
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
