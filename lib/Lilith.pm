package Lilith;

use 5.006;
use strict;
use warnings;
use POE              qw(Wheel::FollowTail);
use JSON             qw( decode_json encode_json );
use Sys::Hostname    qw( hostname );
use DBI              ();
use Digest::SHA      qw(sha256_base64);
use Sys::Syslog      qw( closelog openlog syslog );
use POSIX            qw( strftime );
use Lilith::Schema       ();
use Lilith::Escalate     ();
use Lilith::AutoEscalate ();

=head1 NAME

Lilith - Work with Suricata/Sagan EVE logs and PostgreSQL.

=head1 VERSION

Version 3.0.0

=cut

our $VERSION = '3.0.0';

=head1 SYNOPSIS

    my $toml_raw = read_file($config_file) or die 'Failed to read "' . $config_file . '"';
    my ( $toml, $err ) = from_toml($toml_raw);
    unless ($toml) {
        die "Error parsing toml,'" . $config_file . "'" . $err;
    }

     my $lilith=Lilith->new(
                            dsn=>$toml->{dsn},
                            user=>$toml->{user},
                            pass=>$toml->{pass},
                           );


     $lilith->create_table(
                           dsn=>$toml->{dsn},
                           user=>$toml->{user},
                           pass=>$toml->{pass},
                          );

    # EVE instances live under the [eves.*] table, keyed by instance name.
    my %files;
    if ( ref( $toml->{eves} ) eq "HASH" ) {
        foreach my $name ( keys( %{ $toml->{eves} } ) ) {
                $files{$name} = $toml->{eves}{$name}
                    if ref( $toml->{eves}{$name} ) eq "HASH";
        }
    }

    $ilith->run(
                files=>\%files,
               );

=head1 FUNCTIONS

=head2 new

Initiates it.

    my $lilith=Lilith->run(
                           dsn=>$toml->{dsn},
                           user=>$toml->{user},
                           pass=>$toml->{pass},
                          );

The args taken by this are as below.

    - dsn :: The DSN to use for with DBI.

    - suricata :: Name of the table for Suricata alerts.
      Default :: suricata_alerts

    - user :: Name for use with DBI for the DB connection.
      Default :: lilith

    - pass :: pass for use with DBI for the DB connection.
      Default :: undef

    - sid_ignore :: Array of SIDs to ignore for Suricata and Sagan
                    for the extend.
      Default :: undef

    - class_ignore :: Array of classes to ignore for the
                      extend for Suricata and Sagan
      Default :: undef

    - suricata_sid_ignore :: Array of SIDs to ignore for Suricata
                             for the extend.
      Default :: undef

    - suricata_class_ignore :: Array of classes to ignore for the
                               extend for Suricata.
      Default :: undef

    - sagan_sid_ignore :: Array of SIDs to ignore for Sagan for
                          the extend.
      Default :: undef

    - sagan_class_ignore :: Array of classes to ignore for the
                            extend for Sagan.
      Default :: undef

    - escalation_type_namespaces :: Array of additional namespaces to
                                    search for escalation type modules,
                                    searched after Lilith::Escalate::Type.
      Default :: []

=cut

sub new {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user} = 'lilith';
	}

	if ( !defined( $opts{sid_ignore} ) ) {
		my @empty_array;
		$opts{sid_ignore} = \@empty_array;
	}

	if ( !defined( $opts{class_ignore} ) ) {
		my @empty_array;
		$opts{class_ignore} = \@empty_array;
	}

	if ( !defined( $opts{suricata_sid_ignore} ) ) {
		my @empty_array;
		$opts{suricata_sid_ignore} = \@empty_array;
	}

	if ( !defined( $opts{suricata_class_ignore} ) ) {
		my @empty_array;
		$opts{suricata_class_ignore} = \@empty_array;
	}

	if ( !defined( $opts{sagan_sid_ignore} ) ) {
		my @empty_array;
		$opts{sagan_sid_ignore} = \@empty_array;
	}

	if ( !defined( $opts{sagan_class_ignore} ) ) {
		my @empty_array;
		$opts{sagan_class_ignore} = \@empty_array;
	}

	if ( ref( $opts{escalation_type_namespaces} ) ne 'ARRAY' ) {
		my @empty_array;
		$opts{escalation_type_namespaces} = \@empty_array;
	}

	my $self = {
		escalation_type_namespaces => $opts{escalation_type_namespaces},
		sid_ignore            => $opts{sid_ignore},
		suricata_sid_ignore   => $opts{suricata_sid_ignore},
		sagan_sid_ignore      => $opts{sagan_sid_ignore},
		class_ignore          => $opts{class_ignore},
		suricata_class_ignore => $opts{suricata_class_ignore},
		sagan_class_ignore    => $opts{sagan_class_ignore},
		dsn                   => $opts{dsn},
		user                  => $opts{user},
		pass                  => $opts{pass},
		debug                 => $opts{debug},
		class_map             => {
			'Not Suspicious Traffic'                                      => '!SusT',
			'Unknown Traffic'                                             => 'UnknownT',
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
			'An attempted login using a suspicious username was detected' => '!LoginUser',
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
			''                                                            => 'blankC',
		},
		lc_class_map     => {},
		rev_class_map    => {},
		lc_rev_class_map => {},
		snmp_class_map   => {},
	};
	bless $self;

	my @keys = keys( %{ $self->{class_map} } );
	foreach my $key (@keys) {
		my $lc_key = lc($key);
		$self->{lc_class_map}{$lc_key}                              = $self->{class_map}{$key};
		$self->{rev_class_map}{ $self->{class_map}{$key} }          = $key;
		$self->{lc_rev_class_map}{ lc( $self->{class_map}{$key} ) } = $key;
		$self->{snmp_class_map}{$lc_key}                            = $self->{class_map}{$key};
		$self->{snmp_class_map}{$lc_key}                            = $self->{class_map}{$key};
		$self->{snmp_class_map}{$lc_key} =~ s/^\!/not\_/;
		$self->{snmp_class_map}{$lc_key} =~ s/\ /\_/;
	} ## end foreach my $key (@keys)

	return $self;
} ## end sub new

=head2 run

Start processing. This method is not expected to return.

    $lilith->run(
                 files=>{
                        foo=>{
                              type=>'suricata',
                              instance=>'foo-pie',
                              eve=>'/var/log/suricata/alerts-pie.json',
                              },
                        'foo-lae'=>{
                                    type=>'sagan',
                                    eve=>'/var/log/sagan/alerts-lae.json',
                                    },
                        },
                );

One argument named 'files' is taken and it is hash of
hashes. The keys are below.

    - type :: Either 'suricata', 'sagan', or 'cape', depending
              on the type it is.

    - eve :: Path to the EVE file to read.

    - instance :: Instance name. If not specified the key
                  is used.

=cut

sub run {
	my ( $self, %opts ) = @_;

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
	if ($@) {
		warn($@);
		openlog( 'lilith', undef, 'daemon' );
		syslog( 'LOG_ERR', $@ );
		closelog;
	}

	# process each file
	my $file_count = 0;
	foreach my $item_key ( keys( %{ $opts{files} } ) ) {
		my $item = $opts{files}->{$item_key};
		if ( !defined( $item->{instance} ) ) {
			warn( 'No instance name specified for ' . $item_key . ' so using that as the instance name' );
			$item->{instance} = $item_key;
		}

		# Skip malformed instances with a warning rather than dying, so one bad
		# entry does not take down monitoring of the valid ones.
		if ( !defined( $item->{type} ) ) {
			warn( 'No type specified for ' . $item->{instance} . '; skipping this instance' );
			next;
		} elsif ( $item->{type} ne 'suricata' && $item->{type} ne 'sagan' && $item->{type} ne 'cape' ) {
			warn(     'Type, '
					. $item->{type}
					. ', for instance '
					. $item->{instance}
					. ' is not a known type; skipping this instance' );
			next;
		}

		if ( !defined( $item->{eve} ) ) {
			warn( 'No file specified for ' . $item->{instance} . '; skipping this instance' );
			next;
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
						openlog( 'lilith', undef, 'daemon' );
						syslog( 'LOG_ERR', $@ );
						closelog;
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
									= $dbh->prepare( 'insert into suricata_alerts'
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
							} ## end if ( $_[HEAP]{type} eq 'suricata' )

							#handle if sagan
							elsif ( $_[HEAP]{type} eq 'sagan' ) {
								my $sth
									= $dbh->prepare( 'insert into sagan_alerts'
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
							} elsif ( $_[HEAP]{type} eq 'cape' ) {
								my $sth
									= $dbh->prepare( 'insert into cape_alerts'
										. ' ( instance, target, instance_host, task, start, stop, malscore, subbed_from_ip, subbed_from_host, pkg, md5, sha1, sha256, slug, url, url_hostname, proto, src_ip, src_port, dest_ip, dest_port, size, raw ) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);

								my $url;
								if ( defined( $json->{http} ) && defined( $json->{http}{url} ) ) {
									$url = $json->{http}{url};
								}

								my $url_hostname;
								if ( defined( $json->{http} ) && defined( $json->{http}{hostname} ) ) {
									$url_hostname = $json->{http}{hostname};
								}

								my $proto;
								if ( defined( $json->{proto} ) ) {
									$proto = $json->{proto};
								}

								my $src_ip;
								if ( defined( $json->{src_ip} ) ) {
									$src_ip = $json->{src_ip};
								}

								my $src_port;
								if ( defined( $json->{src_port} ) ) {
									$src_port = $json->{src_port};
								}

								my $dest_ip;
								if ( defined( $json->{dest_ip} ) ) {
									$dest_ip = $json->{dest_ip};
								}

								my $dest_port;
								if ( defined( $json->{dest_port} ) ) {
									$dest_port = $json->{dest_port};
								}

								my $size;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{size} ) ) {
									$size = $json->{cape_submit}{size};
								} elsif ( defined( $json->{fileinfo} ) && defined( $json->{fileinfo}{size} ) ) {
									$size = $json->{fileinfo}{size};
								}

								# figure out what to use for the target
								my $target;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{name} ) ) {
									$target = $json->{cape_submit}{name};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{name} ) )
								{
									$target = $json->{suricata_extract_submit}{name};
								} else {
									$target = $json->{row}{target};
								}

								my $subbed_from_ip;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{remote_ip} ) )
								{
									$subbed_from_ip = $json->{cape_submit}{remote_ip};
								}

								my $subbed_from_host;
								if (   defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{host} ) )
								{
									$subbed_from_host = $json->{suricata_extract_submit}{host};
								}

								my $md5;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{md5} ) ) {
									$md5 = $json->{cape_submit}{md5};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{md5} ) )
								{
									$md5 = $json->{suricata_extract_submit}{md5};
								}

								my $sha1;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{sha1} ) ) {
									$sha1 = $json->{cape_submit}{sha1};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{sha1} ) )
								{
									$sha1 = $json->{suricata_extract_submit}{sha1};
								}

								my $sha256;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{sha256} ) ) {
									$sha256 = $json->{cape_submit}{sha256};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{sha256} ) )
								{
									$sha256 = $json->{suricata_extract_submit}{sha256};
								}

								my $slug;
								if ( defined( $json->{suricata_extract_submit}{slug} ) ) {
									$slug = $json->{suricata_extract_submit}{slug};
								} elsif ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{slug} ) )
								{
									$slug = $json->{cape_submit}{slug};
								}

								$target =~ s/^.*\///g;
								$sth->execute(
									$_[HEAP]{instance},       $target,
									$_[HEAP]{host},           $json->{row}{id},
									$json->{row}{started_on}, $json->{row}{completed_on},
									$json->{malscore},        $subbed_from_ip,
									$subbed_from_host,        $json->{row}{package},
									$md5,                     $sha1,
									$sha256,                  $slug,
									$url,                     $url_hostname,
									$proto,                   $src_ip,
									$src_port,                $dest_ip,
									$dest_port,               $size,
									$_[ARG0],
								);
							} ## end elsif ( $_[HEAP]{type} eq 'cape' )
						} ## end if ( defined($json) && defined( $json->{event_type...}))
						if ($@) {
							warn( 'SQL INSERT issue... ' . $@ );
							openlog( 'lilith', undef, 'daemon' );
							syslog( 'LOG_ERR', 'SQL INSERT issue... ' . $@ );
							closelog;
						}
					} ## end eval

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

	} ## end foreach my $item_key ( keys( %{ $opts{files} } ...))

	POE::Kernel->run;
} ## end sub run

=head2 extend

	my $return=$lilith->extend(
		                       go_back_minutes=>5,
	                          );

=cut

sub extend {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{go_back_minutes} ) ) {
		$opts{go_back_minutes} = 5;
	}

	#
	# basic initial stuff
	#

	# librenms return hash
	my $to_return = {
		data => {
			totals             => { total => 0, },
			sagan_instances    => {},
			suricata_instances => {},
			sagan_totals       => { total => 0, },
			suricata_totals    => { total => 0, },
		},
		version     => 1,
		error       => '0',
		errorString => '',
	};

	#
	# Do the search in eval incase of failure
	#

	my $sagan_found    = ();
	my $suricata_found = ();
	eval {
		my $dbh;
		eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
		if ($@) {
			die( 'DBI->connect_cached failure.. ' . $@ );
		}

		my $hostname = hostname;

		#
		# suricata SQL bit
		#

		my $sql
			= 'select * from suricata_alerts'
			. " where timestamp >= CURRENT_TIMESTAMP - interval '"
			. $opts{go_back_minutes}
			. " minutes' and host ='"
			. $hostname . "'";

		$sql = $sql . ';';
		if ( $self->{debug} ) {
			warn( 'SQL search "' . $sql . '"' );
		}
		my $sth = $dbh->prepare($sql);
		$sth->execute();

		while ( my $row = $sth->fetchrow_hashref ) {
			push( @{$suricata_found}, $row );
		}

		#
		# Sagan SQL bit
		#

		$sql
			= 'select * from sagan_alerts'
			. " where timestamp >= CURRENT_TIMESTAMP - interval '"
			. $opts{go_back_minutes}
			. " minutes' and instance_host = '"
			. $hostname . "'";

		$sql = $sql . ';';
		if ( $self->{debug} ) {
			warn( 'SQL search "' . $sql . '"' );
		}
		$sth = $dbh->prepare($sql);
		$sth->execute();

		while ( my $row = $sth->fetchrow_hashref ) {
			push( @{$sagan_found}, $row );
		}

	};
	if ($@) {
		$to_return->{error}       = 1;
		$to_return->{errorString} = $@;
	}

	foreach my $row ( @{$suricata_found} ) {
		$to_return->{data}{totals}{total}++;
		$to_return->{data}{suricata_totals}{total}++;
		my $snmp_class = $self->get_short_class_snmp( $row->{classification} );
		if ( !defined( $to_return->{data}{totals}{$snmp_class} ) ) {
			$to_return->{data}{totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{suricata_totals}{$snmp_class} ) ) {
			$to_return->{data}{suricata_totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{suricata_totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{suricata_instances}{ $row->{instance} } ) ) {
			$to_return->{data}{suricata_instances}{ $row->{instance} } = { total => 0 };
		}
		$to_return->{data}{suricata_instances}{ $row->{instance} }{total}++;
		if ( !defined( $to_return->{data}{suricata_instances}{ $row->{instance} }{$snmp_class} ) ) {
			$to_return->{data}{suricata_instances}{ $row->{instance} }{$snmp_class} = 1;
		} else {
			$to_return->{data}{suricata_instances}{ $row->{instance} }{$snmp_class}++;
		}
	} ## end foreach my $row ( @{$suricata_found} )

	foreach my $row ( @{$sagan_found} ) {
		$to_return->{data}{totals}{total}++;
		$to_return->{data}{sagan_totals}{total}++;
		my $snmp_class = $self->get_short_class_snmp( $row->{classification} );
		if ( !defined( $to_return->{data}{totals}{$snmp_class} ) ) {
			$to_return->{data}{totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{sagan_totals}{$snmp_class} ) ) {
			$to_return->{data}{sagan_totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{sagan_totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{sagan_instances}{ $row->{instance} } ) ) {
			$to_return->{data}{sagan_instances}{ $row->{instance} } = { total => 0 };
		}
		$to_return->{data}{sagan_instances}{ $row->{instance} }{total}++;
		if ( !defined( $to_return->{data}{sagan_instances}{ $row->{instance} }{$snmp_class} ) ) {
			$to_return->{data}{sagan_instances}{ $row->{instance} }{$snmp_class} = 1;
		} else {
			$to_return->{data}{sagan_instances}{ $row->{instance} }{$snmp_class}++;
		}
	} ## end foreach my $row ( @{$sagan_found} )

	return $to_return;
} ## end sub extend

=head2 get_short_class

Get SNMP short class name for a class.

    my $short_class_name=$lilith->get_short_class($class);

=cut

sub get_short_class {
	my ( $self, $class ) = @_;

	if ( !defined($class) ) {
		return ('undefC');
	}

	if ( defined( $self->{lc_class_map}->{ lc($class) } ) ) {
		return $self->{lc_class_map}->{ lc($class) };
	}

	return ('unknownC');
} ## end sub get_short_class

=head2 get_short_class_snmp

Get SNMP short class name for a class. This
is the same as the short class name, but with /^\!/
replaced with 'not_'.

    my $snmp_class_name=$lilith->get_short_class_snmp($class);

=cut

sub get_short_class_snmp {
	my ( $self, $class ) = @_;

	if ( !defined($class) ) {
		return ('undefC');
	}

	if ( defined( $self->{snmp_class_map}->{ lc($class) } ) ) {
		return $self->{snmp_class_map}->{ lc($class) };
	}

	return ('unknownC');
} ## end sub get_short_class_snmp

=head2 get_short_class_snmp_list

Gets a list of short SNMP class names.

    my $snmp_classes=$lilith->get_short_class_snmp_list;

    foreach my $item (@{ $snmp_classes }){
        print $item."\n";
    }

=cut

sub get_short_class_snmp_list {
	my ($self) = @_;

	my $snmp_classes = [ 'undefC', 'unknownC' ];
	foreach my $item ( keys( %{ $self->{snmp_class_map} } ) ) {
		push( @{$snmp_classes}, $self->{snmp_class_map}{$item} );
	}

	return $snmp_classes;
} ## end sub get_short_class_snmp_list

=head2 search

Searches the specified table and returns a array of found rows. This is a wrapper around
Lilith::Schema. If you are looking for something more complex, read L<DBIx::Class>,
L<SQL::Abstract::Classic>, and L<Lilith::Schema>.

    - table :: 'suricata', 'cape', 'sagan' depending on the desired table to
               use. Will die if something other is specified. The table
               name used is based on what was passed to new(if not the
               default).
      Default :: suricata

    - go_back_minutes :: How far back to search in minutes.
      Default :: 1440

    - limit :: Limit on how many to return.
      Default :: undef

    - offset :: Offset for when using limit.
      Default :: undef

    - order_by :: Column to order by.
      Default :: timetamp
      Cape Default :: id

    - order_dir :: Direction to order.
      Default :: ASC

Below are simple search items that if given will be matched via a basic equality.

    - src_ip
    - dest_ip
    - event_id
    - md5
    - sha1
    - sha256
    - subbed_from_ip

    # will become "and src_ip = '192.168.1.2'"
    src_ip => '192.168.1.2',

Below are a list of numeric items. The value taken is a array and anything
prefixed '!' with add as a and not equal.

    - src_port
    - dest_port
    - gid
    - sid
    - rev
    - id
    - size
    - malscore
    - task

    # will become "and src_port = '22' and src_port != ''512'"
    src_port => ['22', '!512'],

Below are a list of string items.

    - host
    - instance_host
    - instance
    - class
    - signature
    - app_proto
    - in_iface
    - url
    - url_hostname
    - slug
    - pkg

    # will become "and host = 'foo.bar'"
    host => 'foo.bar',

    # will become "and class != 'foo'"
    class => '!foo',

    # will become "and instance like '%foo'"
    instance => '%foo',

class may also be a array. Positive items are ORed together while
negated items are ANDed.

    # will become "and class in ( 'foo', 'bar' )"
    class => ['foo', 'bar'],

    # will become "and ( class in ( 'foo', 'bar' ) or class like 'derp%' )"
    class => ['foo', 'bar', 'derp%'],

    # will become "and class != 'foo' and class not like 'derp%'"
    class => ['!foo', '!derp%'],

    # will become "and instance not like '%foo'"
    instance => '!%foo',

Below are complex items.

    - ip
    - port

Each matches either the source or destination column. A plain value is
ORed across the two columns; a '!'-negated value is ANDed (so it must be
absent from both sides). port additionally accepts the numeric comparison
operators (<, <=, >, >=). Several values may be given at once, either as an
arrayref or as a comma separated string; positive items are ORed together
and negated items are ANDed.

    # will become "and ( src_ip = '192.168.1.2' or dest_ip = '192.168.1.2' )"
    ip => '192.168.1.2'

    # will become "and ( src_ip != '192.168.1.2' and dest_ip != '192.168.1.2' )"
    ip => '!192.168.1.2'

    # will become "and ( src_port = '22' or dest_port = '22' )"
    port => '22'

    # will become "and ( src_port != '22' and dest_port != '22' )"
    port => '!22'

    # will become "and ( src_port = '22' or dest_port = '22'
    #                    or src_port = '80' or dest_port = '80' )"
    port => '22,80'

=cut

sub search {
	my ( $self, %opts ) = @_;

	if ( defined( $opts{table} ) ) {
		if ( $opts{table} ne 'suricata' && $opts{table} ne 'sagan' && $opts{table} ne 'cape' ) {
			die( '"' . $opts{table} . '" is not a known table type' );
		}
	}
	my $table            = 'SuricataAlert';
	my $default_order_by = 'timestamp';
	if ( $opts{table} eq 'sagan' ) {
		$table = 'SaganAlert';
	} elsif ( $opts{table} eq 'cape' ) {
		$table            = 'CapeAlert';
		$default_order_by = 'id';
	}

	if ( !defined( $opts{order_by} ) ) {
		$opts{order_by} = $default_order_by;
	}

	if ( !defined( $opts{go_back_minutes} ) ) {
		$opts{go_back_minutes} = '1440';
	} else {
		if ( $opts{go_back_minutes} !~ /^[0-9]+$/ ) {
			die( '"' . $opts{go_back_minutes} . '" for go_back_minutes is not numeric' );
		}
	}
	my $go_back_time = 'CURRENT_TIMESTAMP - interval \'' . $opts{go_back_minutes} . ' minutes\'';

	if ( defined( $opts{order_dir} ) && $opts{order_dir} ne 'ASC' && $opts{order_dir} ne 'DESC' ) {
		die( '"' . $opts{order_dir} . '" for order_dir must by either ASC or DESC' );
	} elsif ( !defined( $opts{order_dir} ) ) {
		$opts{order_dir} = 'ASC';
	}

	my $go_back_column = 'timestamp';
	if ( $opts{table} eq 'cape' ) {
		$go_back_column = 'stop';
	}

	my $schema = Lilith::Schema->connect( $self->{dsn}, $self->{user}, $self->{pass}, );

	my $search = { $go_back_column => { '>=', \$go_back_time } };

	#
	# add simple items
	#

	my @simple = ( 'src_ip', 'dest_ip', 'proto', 'event_id', 'md5', 'sha1', 'sha256', 'subbed_from_ip' );

	foreach my $item (@simple) {
		if ( defined( $opts{$item} ) ) {
			$search->{$item} = $opts{$item};
		}
	}

	#
	# add numeric items
	#

	my @numeric = ( 'src_port', 'dest_port', 'gid', 'sid', 'rev', 'id', 'size', 'malscore', 'task' );

	foreach my $item (@numeric) {
		if ( defined( $opts{$item} ) ) {
			# process each item
			my @found;
			foreach my $arg ( @{ $opts{$item} } ) {
				$arg =~ s/[\ \t]//g;

				my $equality = '=';
				my $number;

				# match the start of the item
				if ( $arg =~ /^[0-9]+$/ ) {
					$number = $arg;
				} elsif ( $arg =~ /^\<\=[0-9]+$/ ) {
					$arg =~ s/^\<\=//;
					$equality = '<=';
					$number   = $arg;
				} elsif ( $arg =~ /^\<[0-9]+$/ ) {
					$arg =~ s/^\<//;
					$equality = '<';
					$number   = $arg;
				} elsif ( $arg =~ /^\>\=[0-9]+$/ ) {
					$arg =~ s/^\>\=//;
					$equality = '>=';
					$number   = $arg;
				} elsif ( $arg =~ /^\>[0-9]+$/ ) {
					$arg =~ s/^\>\=//;
					$equality = '>';
					$number   = $arg;
				} elsif ( $arg =~ /^\![0-9]+$/ ) {
					$arg =~ s/^\!//;
					$equality = '!=';
					$number   = $arg;
				} elsif ( $arg =~ /^$/ ) {

					# only exists for skipping when some one has passes something starting
					# with a ,, ending with a,, or with ,, in it.
				} else {
					# if we get here, it means we don't have a valid use case for what ever was passed and should error
					die( '"' . $arg . '" does not appear to be a valid item for a numeric search for the ' . $item );
				}
				if ( defined($number) ) {
					push( @found, { $equality, $number } );
				}
			} ## end foreach my $arg ( @{ $opts{$item} } )
			if ( defined( $found[0] ) && !defined( $found[1] ) ) {
				$search->{$item} = $found[0];
			} elsif ( defined( $found[0] ) && defined( $found[1] ) ) {
				# The terms must be spread as separate elements after '-and'; a
				# single nested arrayref ( [ '-and' => \@found ] ) is instead ORed
				# by SQL::Abstract, so e.g. "!22, !443" became "!= 22 OR != 443",
				# which is true for every row and filtered nothing.
				$search->{$item} = [ '-and' => @found ];
			}
		} ## end if ( defined( $opts{$item} ) )
	} ## end foreach my $item (@numeric)

	#
	# more complex items
	#

	if ( defined( $opts{ip} ) && $opts{ip} ne '' ) {
		my @tokens = ref $opts{ip} eq 'ARRAY' ? @{ $opts{ip} } : split( /\s*,\s*/, $opts{ip} );

		# Positive addresses are ORed across src/dest and across items; a
		# '!'-negated address must be absent on BOTH sides, so it becomes an
		# AND ( src != X AND dest != X ) and each is ANDed into the query.
		my @positive;
		my @negative;
		foreach my $token (@tokens) {
			next if !defined($token) || $token eq '';
			if ( $token =~ s/^\!// ) {
				push( @negative,
					{ '-and' => [ { src_ip => { '!=' => $token } }, { dest_ip => { '!=' => $token } } ] } );
			} else {
				push( @positive, { src_ip => { '=' => $token } }, { dest_ip => { '=' => $token } } );
			}
		}

		if ( @positive || @negative ) {
			if ( !defined( $search->{'-and'} ) ) {
				$search->{'-and'} = [];
			}
			push( @{ $search->{'-and'} }, { '-or' => \@positive } ) if @positive;
			push( @{ $search->{'-and'} }, @negative );
		}
	}

	if ( defined( $opts{port} ) && $opts{port} ne '' ) {
		my @tokens = ref $opts{port} eq 'ARRAY' ? @{ $opts{port} } : split( /\s*,\s*/, $opts{port} );

		# Positive ports are ORed across src/dest and across items; a negated
		# port must be absent on BOTH sides, so it becomes an AND
		# ( src != 22 AND dest != 22 ) and each is ANDed into the query.
		my @positive;
		my @negative;
		foreach my $token (@tokens) {
			$token =~ s/[\ \t]//g;
			next if $token eq '';

			my $equality;
			my $number;
			if ( $token =~ /^([0-9]+)$/ ) {
				$equality = '=';
				$number   = $1;
			} elsif ( $token =~ /^\<\=([0-9]+)$/ ) {
				$equality = '<=';
				$number   = $1;
			} elsif ( $token =~ /^\<([0-9]+)$/ ) {
				$equality = '<';
				$number   = $1;
			} elsif ( $token =~ /^\>\=([0-9]+)$/ ) {
				$equality = '>=';
				$number   = $1;
			} elsif ( $token =~ /^\>([0-9]+)$/ ) {
				$equality = '>';
				$number   = $1;
			} elsif ( $token =~ /^\!([0-9]+)$/ ) {
				$equality = '!=';
				$number   = $1;
			} else {
				die( '"' . $token . '" does not appear to be a valid item for a port search' );
			}

			if ( $equality eq '!=' ) {
				push( @negative,
					{ '-and' => [ { src_port => { $equality => $number } }, { dest_port => { $equality => $number } } ] }
				);
			} else {
				push( @positive, { src_port => { $equality => $number } }, { dest_port => { $equality => $number } } );
			}
		} ## end foreach my $token (@tokens)

		if ( @positive || @negative ) {
			if ( !defined( $search->{'-and'} ) ) {
				$search->{'-and'} = [];
			}
			push( @{ $search->{'-and'} }, { '-or' => \@positive } ) if @positive;
			push( @{ $search->{'-and'} }, @negative );
		}
	}

	#
	# handle string items
	#

	if ( defined( $opts{class} ) ) {
		my @class_args = ref $opts{class} eq 'ARRAY' ? @{ $opts{class} } : ( $opts{class} );

		# positive items are ORed together, negated items are ANDed
		my @in;
		my @positive;
		my @negative;
		foreach my $val (@class_args) {
			if ( !defined($val) || $val eq '' ) {
				next;
			}
			if ( $val =~ /^\!/ ) {
				$val =~ s/^\!//;
				push( @negative, { ( $val =~ /\%/ ? '-not_like' : '!=' ) => $val } );
			} elsif ( $val =~ /\%/ ) {
				push( @positive, { 'like' => $val } );
			} else {
				push( @in, $val );
			}
		}
		if ( defined( $in[0] ) && !defined( $in[1] ) ) {
			unshift( @positive, { '=' => $in[0] } );
		} elsif ( defined( $in[1] ) ) {
			unshift( @positive, { '-in' => \@in } );
		}

		my @clauses;
		if ( defined( $positive[0] ) && !defined( $positive[1] ) ) {
			push( @clauses, { classification => $positive[0] } );
		} elsif ( defined( $positive[1] ) ) {
			push( @clauses, { '-or' => [ map { { classification => $_ } } @positive ] } );
		}
		foreach my $item (@negative) {
			push( @clauses, { classification => $item } );
		}

		if ( defined( $clauses[0] ) ) {
			if ( !defined( $search->{'-and'} ) ) {
				$search->{'-and'} = [];
			}
			push( @{ $search->{'-and'} }, @clauses );
		}
	} ## end if ( defined( $opts{class} ) )

	my @strings = (
		'host',         'instance_host', 'instance',
		'signature',    'app_proto',     'in_iface', 'url',
		'url_hostname', 'slug',          'pkg',      'subbed_from_host'
	);
	foreach my $item (@strings) {
		if ( defined( $opts{$item} ) ) {
			if ( $opts{$item} =~ /\%/ ) {
				if ( $opts{$item} =~ /^\!/ ) {
					$opts{$item} =~ s/^\!//;
					$search->{$item} = { '-not_like', $opts{$item} };
				} else {
					$search->{$item} = { 'like', $opts{$item} };
				}
			} else {
				if ( $opts{$item} =~ /^\!/ ) {
					$opts{$item} =~ s/^\!//;
					$search->{$item} = { '!=', $opts{$item} };
				} else {
					$search->{$item} = { '=', $opts{$item} };
				}
			}
		} ## end if ( defined( $opts{$item} ) )
	} ## end foreach my $item (@strings)

	my %result_attrs = (
		order_by     => $opts{order_by} . ' ' . $opts{order_dir},
		result_class => 'DBIx::Class::ResultClass::HashRefInflator',
	);
	$result_attrs{rows}   = $opts{limit}  if defined $opts{limit};
	$result_attrs{offset} = $opts{offset} if defined $opts{offset};

	my @fetch_results = $schema->resultset($table)->search( $search, \%result_attrs )->all;

	return \@fetch_results;
} ## end sub search

=head2 escalation_types

Returns a array ref of the names of the available escalation types,
including any found under the additional namespaces passed to new.

    my $types = $lilith->escalation_types;

=cut

sub escalation_types {
	my ($self) = @_;

	return Lilith::Escalate->types( $self->{escalation_type_namespaces} );
}

=head2 escalation_type_info

Returns a hash ref describing a escalation type; its name, description,
and config fields. Dies if the type can not be resolved.

    my $info = $lilith->escalation_type_info('Webhook');

=cut

sub escalation_type_info {
	my ( $self, $type ) = @_;

	return Lilith::Escalate->type_info( $type, $self->{escalation_type_namespaces} );
}

=head2 escalation_targets

Returns a array ref of every escalation target, sorted by name, with
the config decoded into a hash ref.

    my $targets = $lilith->escalation_targets;

=cut

sub escalation_targets {
	my ($self) = @_;

	my $dbh = $self->_escalation_dbh;

	my $sth = $dbh->prepare('select * from escalation_targets order by name;');
	$sth->execute();

	my @targets;
	while ( my $row = $sth->fetchrow_hashref ) {
		$row->{config} = $self->_escalation_decode_config( $row->{config} );
		push( @targets, $row );
	}

	return \@targets;
} ## end sub escalation_targets

=head2 escalation_target_get

Fetches a single escalation target by ID, with the config decoded into
a hash ref. Dies if the ID is not numeric or no such target exists.

    my $target = $lilith->escalation_target_get(3);

=cut

sub escalation_target_get {
	my ( $self, $id ) = @_;

	if ( !defined($id) || $id !~ /^[0-9]+$/ ) {
		die('escalation target id is required and must be numeric');
	}

	my $dbh = $self->_escalation_dbh;

	my $sth = $dbh->prepare('select * from escalation_targets where id = ?;');
	$sth->execute($id);

	my $row = $sth->fetchrow_hashref;
	if ( !$row ) {
		die( 'no escalation target with the id "' . $id . '"' );
	}

	$row->{config} = $self->_escalation_decode_config( $row->{config} );

	return $row;
} ## end sub escalation_target_get

=head2 escalation_target_create

Creates a new escalation target and returns its ID. The type must
resolve to a escalation type module and the config must pass that
module's check_config.

    my $id = $lilith->escalation_target_create(
                                               name        => 'soc-hook',
                                               type        => 'Webhook',
                                               config      => { url => 'https://soc.foo.bar/hook' },
                                               description => 'SOC webhook',
                                               enabled     => 1,
                                              );

=cut

sub escalation_target_create {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{name} ) || $opts{name} eq '' ) {
		die('"name" is required');
	}

	if ( ref( $opts{config} ) ne 'HASH' ) {
		$opts{config} = {};
	}

	my $module = Lilith::Escalate->type_module( $opts{type}, $self->{escalation_type_namespaces} );
	if ( $module->can('check_config') ) {
		$module->check_config( $opts{config} );
	}

	my $enabled = ( !defined( $opts{enabled} ) || $opts{enabled} ) ? 1 : 0;

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare( 'insert into escalation_targets ( name, type, config, enabled, description )'
			. ' VALUES ( ?, ?, ?, ?, ? ) RETURNING id;' );
	$sth->execute( $opts{name}, $opts{type}, encode_json( $opts{config} ), $enabled, $opts{description} );

	my ($id) = $sth->fetchrow_array;

	return $id;
} ## end sub escalation_target_create

=head2 escalation_target_update

Updates a escalation target. Any of name, type, config, description,
or enabled may be given; unspecified items keep their current value.
The resulting type/config combination is revalidated.

    $lilith->escalation_target_update(
                                      id      => 3,
                                      enabled => 0,
                                     );

=cut

sub escalation_target_update {
	my ( $self, %opts ) = @_;

	my $existing = $self->escalation_target_get( $opts{id} );

	my $name        = defined( $opts{name} ) && $opts{name} ne '' ? $opts{name} : $existing->{name};
	my $type        = defined( $opts{type} ) && $opts{type} ne '' ? $opts{type} : $existing->{type};
	my $config      = ref( $opts{config} ) eq 'HASH' ? $opts{config} : $existing->{config};
	my $description = exists( $opts{description} ) ? $opts{description} : $existing->{description};
	my $enabled     = exists( $opts{enabled} ) ? ( $opts{enabled} ? 1 : 0 ) : ( $existing->{enabled} ? 1 : 0 );

	my $module = Lilith::Escalate->type_module( $type, $self->{escalation_type_namespaces} );
	if ( $module->can('check_config') ) {
		$module->check_config($config);
	}

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare( 'update escalation_targets set name = ?, type = ?, config = ?, enabled = ?,'
			. ' description = ?, updated = now() where id = ?;' );
	$sth->execute( $name, $type, encode_json($config), $enabled, $description, $opts{id} );

	return 1;
} ## end sub escalation_target_update

=head2 escalation_target_delete

Deletes a escalation target by ID. Past escalations to it are kept,
with their target_id nulled via the FK.

    $lilith->escalation_target_delete(3);

=cut

sub escalation_target_delete {
	my ( $self, $id ) = @_;

	if ( !defined($id) || $id !~ /^[0-9]+$/ ) {
		die('escalation target id is required and must be numeric');
	}

	my $dbh = $self->_escalation_dbh;

	my $sth = $dbh->prepare('delete from escalation_targets where id = ?;');
	$sth->execute($id);

	return 1;
} ## end sub escalation_target_delete

=head2 escalate

Escalates a event to one or more escalation targets, recording each
attempt in the escalations table along with the payload the type
actually sent. Attempts refused before a send (a unknown or disabled
target) are recorded as failed too, with target_id null when there is
no valid target row to reference; the target's name is snapshotted
into target_name when known so history stays readable after a target
is deleted. Each recorded escalation ID is also appended to the alert
row's escalations array, in the same transaction as the insert, so
anything reading the alert tables can see whether/how many times a
alert has been escalated without querying the escalations table.
Returns a array ref with one hash ref per target, each having the
keys target_id, target_name, escalation_id, status, and error.

    my $results = $lilith->escalate(
                                    table        => 'suricata',
                                    id           => 42,
                                    target_ids   => [ 1, 2 ],
                                    note         => 'C2 traffic to a known bad host',
                                    requested_by => 'kitsune',
                                   );

=cut

sub escalate {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{table} ) ) {
		$opts{table} = 'suricata';
	}
	if ( $opts{table} ne 'suricata' && $opts{table} ne 'sagan' && $opts{table} ne 'cape' ) {
		die( '"' . $opts{table} . '" is not a known table type' );
	}

	if ( !defined( $opts{id} ) || $opts{id} !~ /^[0-9]+$/ ) {
		die('"id" is required and must be numeric');
	}

	if ( ref( $opts{target_ids} ) ne 'ARRAY' || !@{ $opts{target_ids} } ) {
		die('"target_ids" is required and must be a non-empty array');
	}
	foreach my $target_id ( @{ $opts{target_ids} } ) {
		if ( !defined($target_id) || $target_id !~ /^[0-9]+$/ ) {
			die('every item of "target_ids" must be numeric');
		}
	}

	# use a large go_back_minutes to bypass the time window when fetching
	# a specific event by ID
	my $found = $self->search(
		table           => $opts{table},
		id              => [ $opts{id} ],
		go_back_minutes => 525600,
		limit           => 1,
	);
	my $event = $found->[0];
	if ( !$event ) {
		die( 'no event with the id "' . $opts{id} . '" found in the ' . $opts{table} . ' table' );
	}

	my $dbh = $self->_escalation_dbh;

	my $alert_table = $opts{table} . '_alerts';

	# Records one escalation attempt: inserts the escalations row and appends
	# its ID to the alert row's escalations array in one transaction, so the
	# two can not drift. Committed before any send happens so a alert row
	# lock is never held across a slow outbound send.
	my $record = sub {
		my ( $row_target_id, $target_name, $status, $error ) = @_;

		my $escalation_id;
		$dbh->begin_work;
		eval {
			my $insert
				= $dbh->prepare(
				'insert into escalations ( table_name, alert_id, event_id, target_id, target_name, status, note, requested_by, error )'
					. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ? ) RETURNING id;' );
			$insert->execute( $opts{table}, $event->{id}, $event->{event_id},
				$row_target_id, $target_name, $status, $opts{note}, $opts{requested_by}, $error );
			($escalation_id) = $insert->fetchrow_array;

			my $append
				= $dbh->prepare( 'update '
					. $alert_table
					. ' set escalations = array_append( coalesce( escalations, \'{}\'::bigint[] ), ? ) where id = ?;' );
			$append->execute( $escalation_id, $event->{id} );

			$dbh->commit;
		};
		if ($@) {
			my $why = $@;
			eval { $dbh->rollback; };
			die($why);
		}

		return $escalation_id;
	};

	my @results;
	foreach my $target_id ( @{ $opts{target_ids} } ) {
		my $sth = $dbh->prepare('select * from escalation_targets where id = ?;');
		$sth->execute($target_id);
		my $target = $sth->fetchrow_hashref;

		# a missing or disabled target is refused before any send, but the
		# attempt is still recorded; target_id is null for a missing target
		# as there is no valid row for the FK to reference
		if ( !$target || !$target->{enabled} ) {
			my $error
				= !$target
				? 'no escalation target with the id "' . $target_id . '"'
				: 'escalation target "' . $target->{name} . '" is disabled';
			my $escalation_id = $record->(
				( $target ? $target_id       : undef ),
				( $target ? $target->{name} : undef ),
				'failed', $error
			);
			push(
				@results,
				{
					target_id     => $target_id,
					target_name   => ( $target ? $target->{name} : undef ),
					escalation_id => $escalation_id,
					status        => 'failed',
					error         => $error,
				}
			);
			next;
		} ## end if ( !$target || !$target->{enabled} )

		my $escalation_id = $record->( $target_id, $target->{name}, 'pending', undef );

		my $payload;
		eval {
			my $module = Lilith::Escalate->type_module( $target->{type}, $self->{escalation_type_namespaces} );
			$payload = $module->escalate(
				event        => $event,
				table        => $opts{table},
				config       => $self->_escalation_decode_config( $target->{config} ),
				note         => $opts{note},
				requested_by => $opts{requested_by},
				target_name  => $target->{name},
			);
		};
		my $error  = $@ ? $@ : undef;
		my $status = $error ? 'failed' : 'sent';

		my $raw_json;
		if ( defined($payload) ) {
			eval { $raw_json = encode_json($payload); };
		}

		my $update = $dbh->prepare('update escalations set status = ?, error = ?, raw = ? where id = ?;');
		$update->execute( $status, $error, $raw_json, $escalation_id );

		push(
			@results,
			{
				target_id     => $target_id,
				target_name   => $target->{name},
				escalation_id => $escalation_id,
				status        => $status,
				error         => $error,
			}
		);
	} ## end foreach my $target_id ( @{ $opts{target_ids} ...})

	return \@results;
} ## end sub escalate

=head2 escalation_test

Sends a synthetic test event to a escalation target without recording
anything in the escalations table. Returns the payload the type sent.
Dies on failure.

    my $payload = $lilith->escalation_test(id => 3);

=cut

sub escalation_test {
	my ( $self, %opts ) = @_;

	my $target = $self->escalation_target_get( $opts{id} );

	my $event = {
		id             => 0,
		event_id       => 'lilith-escalation-test',
		instance       => 'lilith-test',
		host           => hostname,
		timestamp      => strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime ),
		src_ip         => '192.0.2.1',
		src_port       => 11111,
		dest_ip        => '192.0.2.2',
		dest_port      => 443,
		proto          => 'TCP',
		classification => 'Test Escalation',
		signature      => 'Lilith escalation test',
		raw            => { test => 1 },
	};

	my $module = Lilith::Escalate->type_module( $target->{type}, $self->{escalation_type_namespaces} );

	return $module->escalate(
		event       => $event,
		table       => 'test',
		config      => $target->{config},
		note        => 'This is a test escalation from Lilith.',
		target_name => $target->{name},
		test        => 1,
	);
} ## end sub escalation_test

=head2 escalations_for

Returns the escalations recorded for a event as a array ref of hash
refs, newest first, each joined with the target's current type as
target_type. target_name is the name snapshotted at attempt time,
falling back to the target's current name for rows predating the
snapshot column.

    my $escalations = $lilith->escalations_for(
                                               table => 'suricata',
                                               id    => 42,
                                              );

=cut

sub escalations_for {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{table} ) ) {
		$opts{table} = 'suricata';
	}
	if ( $opts{table} ne 'suricata' && $opts{table} ne 'sagan' && $opts{table} ne 'cape' ) {
		die( '"' . $opts{table} . '" is not a known table type' );
	}

	if ( !defined( $opts{id} ) || $opts{id} !~ /^[0-9]+$/ ) {
		die('"id" is required and must be numeric');
	}

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare( 'select e.*, t.name as target_current_name, t.type as target_type from escalations e'
			. ' left join escalation_targets t on e.target_id = t.id'
			. ' where e.table_name = ? and e.alert_id = ? order by e.timestamp desc, e.id desc;' );
	$sth->execute( $opts{table}, $opts{id} );

	my @escalations;
	while ( my $row = $sth->fetchrow_hashref ) {
		if ( !defined( $row->{target_name} ) ) {
			$row->{target_name} = $row->{target_current_name};
		}
		delete( $row->{target_current_name} );
		push( @escalations, $row );
	}

	return \@escalations;
} ## end sub escalations_for

=head2 auto_escalations

Returns a array ref of every auto escalation rule, ordered by priority
then name, with each row's C<rule> decoded to a hash ref and C<tables>
to a array ref.

    my $rules = $lilith->auto_escalations;

=cut

sub auto_escalations {
	my ($self) = @_;

	my $dbh = $self->_escalation_dbh;

	my $sth = $dbh->prepare('select * from auto_escalations order by priority asc, name asc;');
	$sth->execute();

	my @rules;
	while ( my $row = $sth->fetchrow_hashref ) {
		$row->{rule}   = $self->_auto_decode_rule( $row->{rule} );
		$row->{tables} = $self->_auto_decode_tables( $row->{tables} );
		push( @rules, $row );
	}

	return \@rules;
} ## end sub auto_escalations

=head2 auto_escalation_get

Fetches a single auto escalation rule by ID, with C<rule> decoded to a
hash ref and C<tables> to a array ref. Dies if the ID is not numeric or
no such rule exists.

    my $rule = $lilith->auto_escalation_get(3);

=cut

sub auto_escalation_get {
	my ( $self, $id ) = @_;

	if ( !defined($id) || $id !~ /^[0-9]+$/ ) {
		die('auto escalation id is required and must be numeric');
	}

	my $dbh = $self->_escalation_dbh;

	my $sth = $dbh->prepare('select * from auto_escalations where id = ?;');
	$sth->execute($id);

	my $row = $sth->fetchrow_hashref;
	if ( !$row ) {
		die( 'no auto escalation with the id "' . $id . '"' );
	}

	$row->{rule}   = $self->_auto_decode_rule( $row->{rule} );
	$row->{tables} = $self->_auto_decode_tables( $row->{tables} );

	return $row;
} ## end sub auto_escalation_get

=head2 auto_escalation_create

Creates a auto escalation rule and returns its ID. The rule is
validated by L<Lilith::AutoEscalate>'s check_rule and the tables must
all be known table types.

    my $id = $lilith->auto_escalation_create(
                                             name          => 'high-malscore',
                                             rule          => {
                                                 match   => { field => 'malscore', op => '>=', value => 8 },
                                                 actions => [ { escalate_to => ['soc-hook'] } ],
                                             },
                                             tables        => ['cape'],
                                             priority      => 50,
                                             stop_on_match => 1,
                                             description   => 'escalate nasty cape submissions',
                                             enabled       => 1,
                                            );

=cut

sub auto_escalation_create {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{name} ) || $opts{name} eq '' ) {
		die('"name" is required');
	}

	if ( ref( $opts{rule} ) ne 'HASH' ) {
		die('"rule" is required and must be a hash ref');
	}
	Lilith::AutoEscalate->check_rule( $opts{rule} );

	my $tables = $self->_auto_check_tables( $opts{tables} );

	my $priority = defined( $opts{priority} ) ? $opts{priority} : 100;
	if ( $priority !~ /^-?[0-9]+$/ ) {
		die('"priority" must be an integer');
	}

	my $enabled = ( !defined( $opts{enabled} ) || $opts{enabled} ) ? 1 : 0;
	my $stop    = $opts{stop_on_match} ? 1 : 0;

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare(
		'insert into auto_escalations ( name, enabled, priority, tables, rule, stop_on_match, description )'
			. ' VALUES ( ?, ?, ?, ?::varchar[], ?, ?, ? ) RETURNING id;' );
	$sth->execute( $opts{name}, $enabled, $priority, $self->_pg_text_array($tables),
		encode_json( $opts{rule} ), $stop, $opts{description} );

	my ($id) = $sth->fetchrow_array;

	return $id;
} ## end sub auto_escalation_create

=head2 auto_escalation_update

Updates a auto escalation rule. Any of name, rule, tables, priority,
stop_on_match, description, or enabled may be given; unspecified items
keep their current value. The resulting rule and tables are
revalidated.

    $lilith->auto_escalation_update(
                                    id      => 3,
                                    enabled => 0,
                                   );

=cut

sub auto_escalation_update {
	my ( $self, %opts ) = @_;

	my $existing = $self->auto_escalation_get( $opts{id} );

	my $name = defined( $opts{name} ) && $opts{name} ne '' ? $opts{name} : $existing->{name};
	my $rule = ref( $opts{rule} ) eq 'HASH' ? $opts{rule} : $existing->{rule};
	Lilith::AutoEscalate->check_rule($rule);

	my $tables = exists( $opts{tables} ) ? $self->_auto_check_tables( $opts{tables} ) : $existing->{tables};

	my $priority = defined( $opts{priority} ) ? $opts{priority} : $existing->{priority};
	if ( $priority !~ /^-?[0-9]+$/ ) {
		die('"priority" must be an integer');
	}

	my $stop = exists( $opts{stop_on_match} ) ? ( $opts{stop_on_match} ? 1 : 0 ) : ( $existing->{stop_on_match} ? 1 : 0 );
	my $enabled     = exists( $opts{enabled} )     ? ( $opts{enabled} ? 1 : 0 ) : ( $existing->{enabled} ? 1 : 0 );
	my $description = exists( $opts{description} ) ? $opts{description}          : $existing->{description};

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare( 'update auto_escalations set name = ?, enabled = ?, priority = ?, tables = ?::varchar[],'
			. ' rule = ?, stop_on_match = ?, description = ?, updated = now() where id = ?;' );
	$sth->execute( $name, $enabled, $priority, $self->_pg_text_array($tables),
		encode_json($rule), $stop, $description, $opts{id} );

	return 1;
} ## end sub auto_escalation_update

=head2 auto_escalation_delete

Deletes a auto escalation rule by ID.

    $lilith->auto_escalation_delete(3);

=cut

sub auto_escalation_delete {
	my ( $self, $id ) = @_;

	if ( !defined($id) || $id !~ /^[0-9]+$/ ) {
		die('auto escalation id is required and must be numeric');
	}

	my $dbh = $self->_escalation_dbh;

	my $sth = $dbh->prepare('delete from auto_escalations where id = ?;');
	$sth->execute($id);

	return 1;
} ## end sub auto_escalation_delete

=head2 auto_escalate

Evaluates the enabled auto escalation rules against recently ingested
alerts and, for each match, escalates the alert to the rule's targets
via escalate(). Each scanned alert is stamped with a auto_escalated
time so it is considered exactly once, regardless of whether a rule
matched.

The C<table> option limits processing to a single table type; when
omitted all three (suricata/sagan/cape) are processed.
C<go_back_minutes> bounds how far back to look for alerts that have not
yet been considered (default 5). With C<dry_run> set, no escalation is
sent and nothing is stamped; the returned summary shows what would have
happened. C<requested_by> is prefixed onto the rule name when recording
each escalation (default "auto").

Returns a array ref with one summary hash ref per table processed, each
having the keys C<table>, C<scanned>, C<rules>, C<matched>, C<dry_run>,
and C<escalations> (a array ref of per-match details).

    my $summaries = $lilith->auto_escalate(
                                            go_back_minutes => 5,
                                            dry_run         => 1,
                                           );

=cut

sub auto_escalate {
	my ( $self, %opts ) = @_;

	my @tables = defined( $opts{table} ) ? ( $opts{table} ) : ( 'suricata', 'sagan', 'cape' );
	foreach my $table (@tables) {
		if ( $table ne 'suricata' && $table ne 'sagan' && $table ne 'cape' ) {
			die( '"' . $table . '" is not a known table type' );
		}
	}

	my $minutes = defined( $opts{go_back_minutes} ) ? $opts{go_back_minutes} : 5;
	if ( $minutes !~ /^[0-9]+$/ ) {
		die( '"' . $minutes . '" for go_back_minutes is not numeric' );
	}

	my $dry = $opts{dry_run} ? 1 : 0;
	my $by = defined( $opts{requested_by} ) && $opts{requested_by} ne '' ? $opts{requested_by} : 'auto';

	my $dbh = $self->_escalation_dbh;

	# name -> id map so escalate_to can use target names
	my %target_id;
	my $tsth = $dbh->prepare('select id, name from escalation_targets;');
	$tsth->execute();
	while ( my $row = $tsth->fetchrow_hashref ) {
		$target_id{ $row->{name} } = $row->{id};
	}

	my @summaries;
	foreach my $table (@tables) {
		push(
			@summaries,
			$self->_auto_escalate_table(
				dbh          => $dbh,
				table        => $table,
				minutes      => $minutes,
				dry_run      => $dry,
				requested_by => $by,
				target_id    => \%target_id,
			)
		);
	} ## end foreach my $table (@tables)

	return \@summaries;
} ## end sub auto_escalate

# processes a single table for auto_escalate; see auto_escalate for the
# option meanings
sub _auto_escalate_table {
	my ( $self, %opts ) = @_;

	my $dbh         = $opts{dbh};
	my $table       = $opts{table};
	my $alert_table = $table . '_alerts';
	my $time_column = $table eq 'cape' ? 'stop' : 'timestamp';

	# enabled rules scoped to this table
	my $rsth = $dbh->prepare(
		'select * from auto_escalations where enabled = true and ? = ANY(tables) order by priority asc, id asc;');
	$rsth->execute($table);
	my @rules;
	while ( my $row = $rsth->fetchrow_hashref ) {
		$row->{rule} = $self->_auto_decode_rule( $row->{rule} );
		push( @rules, $row );
	}

	# candidate alerts: not yet considered, within the window
	my $esth = $dbh->prepare( 'select * from '
			. $alert_table
			. ' where auto_escalated is null and '
			. $time_column
			. ' >= CURRENT_TIMESTAMP - interval \''
			. ( $opts{minutes} + 0 )
			. ' minutes\' order by id asc;' );
	$esth->execute();
	my @events;
	while ( my $row = $esth->fetchrow_hashref ) {
		push( @events, $row );
	}

	my $summary = {
		table       => $table,
		scanned     => scalar(@events),
		rules       => scalar(@rules),
		matched     => 0,
		dry_run     => $opts{dry_run},
		escalations => [],
	};

	if ( !@rules || !@events ) {
		$self->_auto_mark( \@events, $dbh, $alert_table ) if !$opts{dry_run};
		return $summary;
	}

	my $matches = Lilith::AutoEscalate->evaluate( rules => \@rules, events => \@events );

	foreach my $match ( @{$matches} ) {
		my $rule  = $match->{rule};
		my $event = $match->{event};
		$summary->{matched}++;

		# gather targets and note across this rule's actions
		my @wanted;
		my $note;
		foreach my $action ( @{ $rule->{rule}{actions} } ) {
			push( @wanted, @{ $action->{escalate_to} } );
			if ( !defined($note) && defined( $action->{note} ) && $action->{note} ne '' ) {
				$note = $action->{note};
			}
		}
		if ( !defined($note) ) {
			$note = 'auto escalation rule "' . $rule->{name} . '"';
		}

		# resolve target names/ids, dropping unknown names
		my @ids;
		my @unknown;
		foreach my $token (@wanted) {
			if ( $token =~ /^[0-9]+$/ ) {
				push( @ids, $token );
			} elsif ( defined( $opts{target_id}{$token} ) ) {
				push( @ids, $opts{target_id}{$token} );
			} else {
				push( @unknown, $token );
			}
		}
		my %seen;
		@ids = grep { !$seen{$_}++ } @ids;

		my $entry = {
			rule_id         => $rule->{id},
			rule_name       => $rule->{name},
			alert_id        => $event->{id},
			target_ids      => \@ids,
			unknown_targets => \@unknown,
		};

		if ( !@ids ) {
			$entry->{status} = 'no-targets';
		} elsif ( $opts{dry_run} ) {
			$entry->{status} = 'dry-run';
		} else {
			my $results;
			eval {
				$results = $self->escalate(
					table        => $table,
					id           => $event->{id},
					target_ids   => \@ids,
					note         => $note,
					requested_by => $opts{requested_by} . ':' . $rule->{name},
				);
			};
			if ($@) {
				$entry->{status} = 'error';
				$entry->{error}  = $@;
			} else {
				$entry->{status}  = 'escalated';
				$entry->{results} = $results;

				my $usth
					= $dbh->prepare(
					'update auto_escalations set last_matched = now(), match_count = match_count + 1 where id = ?;');
				$usth->execute( $rule->{id} );
			}
		} ## end else [ if ( !@ids ) ]

		push( @{ $summary->{escalations} }, $entry );
	} ## end foreach my $match ( @{$matches...})

	$self->_auto_mark( \@events, $dbh, $alert_table ) if !$opts{dry_run};

	return $summary;
} ## end sub _auto_escalate_table

# stamps every scanned alert with auto_escalated = now() so it is not
# reconsidered on the next run
sub _auto_mark {
	my ( $self, $events, $dbh, $alert_table ) = @_;

	return if !@{$events};

	my @ids = map { $_->{id} } @{$events};

	my $sth = $dbh->prepare( 'update ' . $alert_table . ' set auto_escalated = now() where id = ANY(?::bigint[]);' );
	$sth->execute( $self->_pg_text_array( \@ids ) );

	return 1;
} ## end sub _auto_mark

# decodes a auto_escalations rule column into a hash ref
sub _auto_decode_rule {
	my ( $self, $rule ) = @_;

	return $rule if ref($rule) eq 'HASH';

	my $decoded;
	if ( defined($rule) ) {
		eval { $decoded = decode_json($rule); };
	}

	return ref($decoded) eq 'HASH' ? $decoded : {};
} ## end sub _auto_decode_rule

# decodes a tables column into a array ref, accepting either a expanded
# array ref (DBD::Pg default) or a raw PostgreSQL array literal
sub _auto_decode_tables {
	my ( $self, $tables ) = @_;

	return $tables if ref($tables) eq 'ARRAY';

	if ( defined($tables) && !ref($tables) ) {
		my $inner = $tables;
		$inner =~ s/^\{//;
		$inner =~ s/\}$//;
		return [] if $inner eq '';
		my @parts = map {
			my $part = $_;
			$part =~ s/^"//;
			$part =~ s/"$//;
			$part;
		} split( /,/, $inner );
		return \@parts;
	} ## end if ( defined($tables) &&...)

	return [];
} ## end sub _auto_decode_tables

# validates a tables list against the known table types, defaulting to all
# three when none are given; returns a de-duped array ref
sub _auto_check_tables {
	my ( $self, $tables ) = @_;

	my %valid = ( suricata => 1, sagan => 1, cape => 1 );

	if ( ref($tables) ne 'ARRAY' || !@{$tables} ) {
		return [ 'suricata', 'sagan', 'cape' ];
	}

	my %seen;
	my @out;
	foreach my $table ( @{$tables} ) {
		if ( !defined($table) || !$valid{$table} ) {
			die( '"'
					. ( defined($table) ? $table : 'undef' )
					. '" is not a known table type; valid: suricata, sagan, cape' );
		}
		push( @out, $table ) if !$seen{$table}++;
	}

	return \@out;
} ## end sub _auto_check_tables

# builds a PostgreSQL array literal from a array ref, quoting each element
sub _pg_text_array {
	my ( $self, $list ) = @_;

	my @items = map {
		my $item = defined($_) ? $_ : '';
		$item =~ s/(["\\])/\\$1/g;
		'"' . $item . '"';
	} @{$list};

	return '{' . join( ',', @items ) . '}';
} ## end sub _pg_text_array

sub _escalation_dbh {
	my ($self) = @_;

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass}, { RaiseError => 1 } ); };
	if ( $@ || !$dbh ) {
		die( 'DBI->connect_cached failure... ' . $@ );
	}

	return $dbh;
}

sub _escalation_decode_config {
	my ( $self, $config ) = @_;

	if ( ref $config eq 'HASH' ) {
		return $config;
	}

	my $decoded;
	if ( defined($config) ) {
		eval { $decoded = decode_json($config); };
	}

	return ref $decoded eq 'HASH' ? $decoded : {};
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
