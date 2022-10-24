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

sub new {
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

	if ( !defined( $opts{sid_ignore} ) ) {
		my @empty_array;
		$opts{sid_ignore} = \@empty_array;
	}

	if ( !defined( $opts{class_ignore} ) ) {
		my @empty_array;
		$opts{class_ignore} = \@empty_array;
	}

	my $self = {
		sid_ignore   => $opts{sid_ignore},
		class_ignore => $opts{class_ignore},
		dsn          => $opts{dsn},
		user         => $opts{user},
		pass         => $opts{pass},
		sagan        => $opts{sagan},
		suricata     => $opts{suricata},
		debug        => $opts{debug},
		class_map    => {
			'Not Suspicious Traffic'                                      => '!SusT',
			'Unknown Traffic'                                             => 'Unknown T',
			'Attempted Information Leak'                                  => '!IL',
			'Information Leak'                                            => 'IL',
			'Large Scale Information Leak'                                => 'LrgSclIL',
			'Attempted Denial of Service'                                 => 'ADoS',
			'Denial of Service'                                           => 'DoS',
			'Attempted User Privilege Gain'                               => 'AUPG',
			'Unsuccessful User Privilege Gain'                            => '!SucUsrPG',
			'Successful User Privilege Gain'                              => 'SucUsrPG',
			'Attempted Administrator Privilege Gain'                      => '!SucAdmPG',
			'Successful Administrator Privilege Gain'                     => 'SucAdmPG',
			'Decode of an RPC Query'                                      => 'DRPCQ',
			'Executable code was detected'                                => 'ExeCode',
			'A suspicious string was detected'                            => 'SusString',
			'A suspicious filename was detected'                          => 'SusFilename',
			'An attempted login using a suspicious username was detected' => '!LoginUsername',
			'A system call was detected'                                  => 'Syscall',
			'A TCP connection was detected'                               => 'TCPconn',
			'A Network Trojan was detected'                               => 'NetTrojan',
			'A client was using an unusual port'                          => 'OddClntPrt',
			'Detection of a Network Scan'                                 => 'NetScan',
			'Detection of a Denial of Service Attack'                     => 'DOS',
			'Detection of a non-standard protocol or event'               => 'NS PoE',
			'Generic Protocol Command Decode'                             => 'GPCD',
			'access to a potentially vulnerable web application'          => 'PotVulWebApp',
			'Web Application Attack'                                      => 'WebAppAtk',
			'Misc activity'                                               => 'MiscActivity',
			'Misc Attack'                                                 => 'MiscAtk',
			'Generic ICMP event'                                          => 'GenICMP',
			'Inappropriate Content was Detected'                          => '!AppCont',
			'Potential Corporate Privacy Violation'                       => 'PotCorpPriVio',
			'Attempt to login by a default username and password'         => '!DefUserPass',
			'Targeted Malicious Activity was Detected'                    => 'TargetedMalAct',
			'Exploit Kit Activity Detected'                               => 'ExpKit',
			'Device Retrieving External IP Address Detected'              => 'RetrExtIP',
			'Domain Observed Used for C2 Detected'                        => 'C2domain',
			'Possibly Unwanted Program Detected'                          => 'PotUnwantedProg',
			'Successful Credential Theft Detected'                        => 'CredTheft',
			'Possible Social Engineering Attempted'                       => 'PosSocEng',
			'Crypto Currency Mining Activity Detected'                    => 'Mining',
			'Malware Command and Control Activity Detected'               => 'MalC2act',
			'Potentially Bad Traffic'                                     => 'PotBadTraf',
			'Unsuccessful Admin Privilege'                                => 'SucAdmPG',
			'Exploit Attempt'                                             => 'ExpAtmp',
			'Program Error'                                               => 'ProgErr',
			'Suspicious Command Execution'                                => 'SusProgExec',
			'Network event'                                               => 'NetEvent',
			'System event'                                                => 'SysEvent',
			'Configuration Change'                                        => 'ConfChg',
			'Spam'                                                        => 'Spam',
			'Attempted Access To File or Directory'                       => 'FoDAccAtmp',
			'Suspicious Traffic'                                          => 'SusT',
			'Configuration Error'                                         => 'ConfErr',
			'Hardware Event'                                              => 'HWevent',
		},
		lc_class_map     => {},
		rev_class_map    => {},
		lc_rev_class_map => {},
	};
	bless $self;

	my @keys = keys( %{ $self->{class_map} } );
	foreach my $key (@keys) {
		$self->{lc_class_map}{ lc($key) }                           = $self->{class_map}{$key};
		$self->{rev_class_map}{ $self->{class_map}{$key} }          = $key;
		$self->{lc_rev_class_map}{ lc( $self->{class_map}{$key} ) } = $key;
	}

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

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
	if ($@) {
		warn($@);
	}

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
					my $self = $_[HEAP]{self};
					my $json;
					eval { $json = decode_json( $_[ARG0] ) };
					if ($@) {
						return;
					}

					my $dbh;
					eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
					if ($@) {
						warn($@);
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
									= $dbh->prepare( 'insert into '
										. $self->{suricata}
										. ' ( instance, host, timestamp, flow_id, event_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, app_proto, flow_pkts_toserver, flow_bytes_toserver, flow_pkts_toclient, flow_bytes_toclient, flow_start, classification, signature, gid, sid, rev, raw ) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);
								$sth->execute(
									$_[HEAP]{instance},           $_[HEAP]{host},
									$json->{timestamp},           $json->{flow_id},
									$event_id,                    $json->{in_iface},
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
										. $self->{sagan}
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
				host     => hostname,
				instance => $item->{instance},
				self     => $self,
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
			. 'instance varchar(255) NOT NULL,'
			. 'host varchar(255) NOT NULL,'
			. 'timestamp TIMESTAMP WITH TIME ZONE NOT NULL, '
			. 'event_id varchar(64) NOT NULL, '
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
			. 'instance varchar(255)  NOT NULL, '
			. 'instance_host varchar(255)  NOT NULL, '
			. 'timestamp TIMESTAMP WITH TIME ZONE, '
			. 'event_id varchar(64) NOT NULL, '
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

	#
	# basic requirements sanity checking
	#

	if ( !defined( $opts{table} ) ) {
		$opts{table} = 'suricata';
	}
	else {
		if ( $opts{table} ne 'suricata' && $opts{table} ne 'sagan' ) {
			die( '"' . $opts{table} . '" is not a known table type' );
		}
	}

	if ( !defined( $opts{go_back_minutes} ) ) {
		$opts{go_back_minutes} = '1440';
	}
	else {
		if ( $opts{go_back_minutes} !~ /^[0-9]+$/ ) {
			die( '"' . $opts{go_back_minutes} . '" for go_back_minutes is not numeric' );
		}
	}

	if ( defined( $opts{limit} ) && $opts{limit} !~ /^[0-9]+$/ ) {
		die( '"' . $opts{limit} . '" is not numeric and limit needs to be numeric' );
	}

	if ( defined( $opts{offset} ) && $opts{offset} !~ /^[0-9]+$/ ) {
		die( '"' . $opts{offset} . '" is not numeric and offset needs to be numeric' );
	}

	if ( defined( $opts{order_by} ) && $opts{order_by} !~ /^[\_a-zA-Z]+$/ ) {
		die( '"' . $opts{order_by} . '" is set for order_by and it does not match /^[\_a-zA-Z]+$/' );
	}

	if ( defined( $opts{order_dir} ) && $opts{order_dir} ne 'ASC' && $opts{order_dir} ne 'DESC' ) {
		die( '"' . $opts{order_dir} . '" for order_dir must by either ASC or DESC' );
	}
	elsif ( !defined( $opts{order_dir} ) ) {
		$opts{order_dir} = 'ASC';
	}

	if ( !defined( $opts{order_by} ) ) {
		$opts{order_by} = 'timestamp';
	}

	my $table = $self->{suricata};
	if ( $opts{table} eq 'sagan' ) {
		$table = $self->{sagan};
	}

	#
	# make sure all the set variables are not dangerous or potentially dangerous
	#

	my @to_check = (
		'src_ip',         'src_port',      'dest_ip',            'dest_port',
		'ip',             'port',          'alert_id',           'host',
		'host_like',      'instance_host', 'instance_host_like', 'instance',
		'instance_like',  'class',         'class_like',         'signature',
		'signature_like', 'app_proto',     'app_proto_like',     'proto',
		'gid',            'sid',           'rev',                'id',
		'event_id'
	);

	foreach my $var_to_check (@to_check) {
		if ( defined( $opts{$var_to_check} ) && $opts{$var_to_check} =~ /[\\\']/ ) {
			die( '"' . $opts{$var_to_check} . '" for "' . $var_to_check . '" matched /[\\\']/' );
		}
	}

	#
	# makes sure order_by is sane
	#

	my @order_by = (
		'src_ip',             'src_port',  'dest_ip',        'dest_port',
		'alert_id',           'host',      'host_like',      'instance_host',
		'instance_host_like', 'instance',  'instance_like',  'class',
		'class_like',         'signature', 'signature_like', 'app_proto',
		'app_proto_like',     'proto',     'gid',            'sid',
		'rev',                'timestamp', 'id'
	);

	my $valid_order_by;

	foreach my $item (@order_by) {
		if ( $item eq $opts{order_by} ) {
			$valid_order_by = 1;
		}
	}

	if ( !$valid_order_by ) {
		die( '"' . $opts{order_by} . '" is not a valid column name for order_by' );
	}

	#
	# assemble
	#

	my $host = hostname;

	my $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} );

	my @sql_args;
	my $sql = 'select * from ' . $table . ' where';
	if ( defined( $opts{no_time} ) && $opts{no_time} ) {
		$sql = $sql . ' id >= 0';
	}
	else {

		$sql = $sql . " timestamp >= CURRENT_TIMESTAMP - interval '" . $opts{go_back_minutes} . " minutes'";
	}

	#
	# add simple items
	#

	my @simple = ( 'src_ip', 'dest_ip', 'alert_id', 'proto', 'event_id' );

	foreach my $item (@simple) {
		if ( defined( $opts{$item} ) ) {
			$sql = $sql . " and " . $item . " = '" . $opts{$item} . "'";
		}
	}

	#
	# add numeric items
	#

	my @numeric = ( 'src_port', 'dest_port', 'gid', 'sid', 'rev', 'id' );

	foreach my $item (@numeric) {
		if ( defined( $opts{$item} ) ) {

			# remove and tabs or spaces
			$opts{$item} =~ s/[\ \t]//g;
			my @arg_split = split( /\,/, $opts{$item} );

			# process each item
			foreach my $arg (@arg_split) {

				# match the start of the item
				if ( $arg =~ /^[0-9]+$/ ) {
					$sql = $sql . " and " . $item . " = '" . $arg . "'";
				}
				elsif ( $arg =~ /^\<\=[0-9]+$/ ) {
					$arg =~ s/^\<\=//;
					$sql = $sql . " and " . $item . " <= '" . $arg . "'";
				}
				elsif ( $arg =~ /^\<[0-9]+$/ ) {
					$arg =~ s/^\<//;
					$sql = $sql . " and " . $item . " < '" . $arg . "'";
				}
				elsif ( $arg =~ /^\>\=[0-9]+$/ ) {
					$arg =~ s/^\>\=//;
					$sql = $sql . " and " . $item . " >= '" . $arg . "'";
				}
				elsif ( $arg =~ /^\>[0-9]+$/ ) {
					$arg =~ s/^\>\=//;
					$sql = $sql . " and " . $item . " > '" . $arg . "'";
				}
				elsif ( $arg =~ /^\![0-9]+$/ ) {
					$arg =~ s/^\!//;
					$sql = $sql . " and " . $item . " != '" . $arg . "'";
				}
				elsif ( $arg =~ /^$/ ) {

					# only exists for skipping when some one has passes something starting
					# with a ,, ending with a,, or with ,, in it.
				}
				else {
					# if we get here, it means we don't have a valid use case for what ever was passed and should error
					die( '"' . $arg . '" does not appear to be a valid item for a numeric search for the ' . $item );
				}
			}
		}
	}

	#
	# handle string items
	#

	my @strings = ( 'host', 'instance_host', 'instance', 'class', 'signature', 'app_proto', 'in_iface' );

	foreach my $item (@strings) {
		if ( defined( $opts{$item} ) ) {
			if ( defined( $opts{ $item . '_like' } ) && $opts{ $item . '_like' } ) {
				$sql = $sql . " and host like '" . $opts{$item} . "'";
			}
			else {
				$sql = $sql . " and " . $item . " = '" . $opts{$item} . "'";
			}
		}
	}

	#
	# more complex items
	#

	if ( defined( $opts{ip} ) ) {
		$sql = $sql . " and ( src_ip = '" . $opts{ip} . "' or dest_ip = '" . $opts{ip} . "' )";
	}

	if ( defined( $opts{port} ) ) {
		$sql = $sql . " and ( src_port = '" . $opts{port} . "'  or dest_port = '" . $opts{port} . "' )";
	}

	#
	# finalize the SQL query... ORDER, LIMIT, and OFFSET
	#

	if ( defined( $opts{order_by} ) ) {
		$sql = $sql . ' ORDER BY ' . $opts{order_by} . ' ' . $opts{order_dir};
	}

	if ( defined( $opts{linit} ) ) {
		$sql = $sql . ' LIMIT ' . $opts{limit};
	}

	if ( defined( $opts{offset} ) ) {
		$sql = $sql . ' OFFSET ' . $opts{offset};
	}

	#
	# run the query
	#

	$sql = $sql . ';';
	if ( $self->{debug} ) {
		warn( 'SQL search "' . $sql . '"' );
	}
	my $sth = $dbh->prepare($sql);
	$sth->execute();

	my $found = ();
	while ( my $row = $sth->fetchrow_hashref ) {
		push( @{$found}, $row );
	}

	$dbh->disconnect;

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
