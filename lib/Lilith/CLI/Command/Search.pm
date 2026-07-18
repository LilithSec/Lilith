package Lilith::CLI::Command::Search;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Text::ANSITable ();
use Term::ANSIColor qw( color );
use JSON            ();

sub abstract { 'search the database' }

sub usage_desc { '%c search %o' }

sub opt_spec {
	return (
		[ 't=s',         'table to operate on',        { default => 'suricata' } ],
		[ 'output=s',    'output type: table or json', { default => 'table' } ],
		[ 'pretty',      'pretty print the JSON output' ],
		[ 'm=s',         'how far back to search, in minutes' ],
		[ 'order=s',     'column to sort by' ],
		[ 'orderdir=s',  'sort direction, ASC or DSC' ],
		[ 'limit=s',     'row limit' ],
		[ 'offset=s',    'row offset' ],
		[ 'columns=s',   'comma separated list of columns' ],
		[ 'columnset=s', 'named column set', { default => 'default' } ],
		[ 'si=s',        'source IP' ],
		[ 'di=s',        'destination IP' ],
		[ 'ip=s',        'IP, either source or destination' ],
		[ 'sp=s@',       'source port' ],
		[ 'dp=s@',       'destination port' ],
		[ 'p=s',         'port, either source or destination' ],
		[ 'host=s',      'host' ],
		[ 'ih=s',        'instance host' ],
		[ 'i=s',         'instance' ],
		[ 'c=s@',        'classification' ],
		[ 'cN=s',        'classification, negated' ],
		[ 'cl',          'match classification using like' ],
		[ 's=s',         'signature' ],
		[ 'if=s',        'in interface' ],
		[ 'proto=s',     'proto' ],
		[ 'ap=s',        'app proto' ],
		[ 'gid=s@',      'GID' ],
		[ 'sid=s@',      'SID' ],
		[ 'rev=s@',      'rev' ],
		[ 'subip=s',     'the IP the sample was submitted from' ],
		[ 'subhost=s',   'the host the sample was submitted from' ],
		[ 'slug=s',      'the slug it was submitted with' ],
		[ 'pkg=s',       'the detonation package used with CAPEv2' ],
		[ 'malscore=s@', 'the malscore of the sample' ],
		[ 'size=s@',     'the size of the sample' ],
		[ 'target=s',    'the detonation target' ],
		[ 'task=s@',     'the task ID of the run' ],
	);
} ## end sub opt_spec

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith        = $self->lilith;
	my $table         = $opt->{t};
	my $search_output = $opt->{output};
	my $pretty        = $opt->{pretty};
	my $columns       = $opt->{columns};
	my $column_set    = $opt->{columnset};

	# class may be given multiple times and/or comma separated
	my @class = @{ $opt->{c} // [] };
	@class = split( /\s*,\s*/, join( ',', @class ) );

	#
	# run the search
	#
	my $returned = $lilith->search(
		src_ip           => $opt->{si},
		src_port         => $opt->{sp} // [],
		dest_ip          => $opt->{di},
		dest_port        => $opt->{dp} // [],
		ip               => $opt->{ip},
		port             => $opt->{p},
		table            => $table,
		host             => $opt->{host},
		host_not         => undef,
		host_like        => undef,
		instance_host    => $opt->{ih},
		instance         => $opt->{i},
		class            => \@class,
		class_not        => $opt->{cN},
		class_like       => $opt->{cl},
		signature        => $opt->{s},
		app_proto        => $opt->{ap},
		proto            => $opt->{proto},
		gid              => $opt->{gid} // [],
		sid              => $opt->{sid} // [],
		rev              => $opt->{rev} // [],
		order_by         => $opt->{order},
		order_dir        => $opt->{orderdir},
		limit            => $opt->{limit},
		offset           => $opt->{offset},
		go_back_minutes  => $opt->{m},
		subbed_from_ip   => $opt->{subip},
		subbed_from_host => $opt->{subhost},
		slug             => $opt->{slug},
		pkg              => $opt->{pkg},
		in_iface         => $opt->{if},
		malscore         => $opt->{malscore} // [],
		size             => $opt->{size}     // [],
		target           => $opt->{target},
		task             => $opt->{task} // [],
	);

	#
	# assemble the selected output
	#
	if ( $search_output eq 'json' ) {
		$self->print_json( $returned, $pretty );
		return;
	} elsif ( $search_output eq 'table' ) {

		#
		# set the columns if they had not been manually specified
		#
		if ( !defined($columns) ) {
			if ( $table eq 'suricata' ) {
				if ( $column_set eq 'default' ) {
					$columns
						= 'id,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id';
				} elsif ( $column_set eq 'default_timestamp' ) {
					$columns
						= 'timestamp,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id';
				} elsif ( $column_set eq 'default_event' ) {
					$columns
						= 'id,event_id,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id';
				} elsif ( $column_set eq 'default_timestamp_event' ) {
					$columns
						= 'timestamp,event_id,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id';
				} else {
					die( '"' . $column_set . '" is not a known column set' );
				}
			} elsif ( $table eq 'sagan' ) {
				if ( $column_set eq 'default' ) {
					$columns
						= 'id,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id';
				} elsif ( $column_set eq 'default_timestamp' ) {
					$columns
						= 'timestamp,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id';
				} elsif ( $column_set eq 'default_event' ) {
					$columns
						= 'id,event_id,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id';
				} elsif ( $column_set eq 'default_timestamp_event' ) {
					$columns
						= 'timestamp,event_id,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id';
				} else {
					die( '"' . $column_set . '" is not a known column set' );
				}
			} elsif ( $table eq 'cape' ) {
				if ( $column_set eq 'default' ) {
					$columns = 'id,instance,slug,target,size,pkg,malscore,subbed_from_ip,subbed_from_host';
				}
			} elsif ( $table eq 'baphomet' ) {
				if ( $column_set eq 'default' ) {
					$columns = 'id,instance,event_type,src_ip,subject,severity,signature,classification,score';
				} elsif ( $column_set eq 'default_timestamp' ) {
					$columns = 'timestamp,instance,event_type,src_ip,subject,severity,signature,classification,score';
				}
			}
		} ## end if ( !defined($columns) )

		# friendly column names
		my $column_names = {
			'id'                  => 'id',
			'instance'            => 'instance',
			'host'                => 'host',
			'timestamp'           => 'timestamp',
			'event_id'            => 'event_id',
			'flow_id'             => 'flow_id',
			'in_iface'            => 'if',
			'src_ip'              => 'src_ip',
			'src_port'            => 'sport',
			'dest_ip'             => 'dest_ip',
			'dest_port'           => 'dport',
			'proto'               => 'proto',
			'app_proto'           => 'aproto',
			'flow_pkts_toserver'  => 'PtS',
			'flow_bytes_toserver' => 'BtS',
			'flow_pkts_toclient'  => 'PtC',
			'flow_bytes_toclient' => 'BtC',
			'flow_start'          => 'flow_start',
			'classification'      => 'class',
			'signature'           => 'signature',
			'gid'                 => 'gid',
			'sid'                 => 'sid',
			'rev'                 => 'rev',
			'rule_id'             => 'rule_id',
			'facility'            => 'facility',
			'level'               => 'level',
			'priority'            => 'priority',
			'program'             => 'program',
			'xff'                 => 'xff',
			'stream'              => 'stream',
			'event_id'            => 'event',
			'slug'                => 'slug',
			'target'              => 'target',
			'size'                => 'size',
			'pkg'                 => 'pkg',
			'malscore'            => 'malscore',
			'subbed_from_ip'      => 'subbed_from_ip',
			'subbed_from_host'    => 'subbed_from_host',
			'event_type'          => 'event_type',
			'subject'             => 'subject',
			'severity'            => 'severity',
			'score'               => 'score',
			'kur'                 => 'kur',
			'country'             => 'country',
		};

		#
		# init the table
		#
		my $tb = Text::ANSITable->new;
		$tb->border_style( $ENV{Lilith_table_border} );
		$tb->color_theme( $ENV{Lilith_table_color} );

		my @columns_array = split( /,/, $columns );
		my $header_int    = 0;
		my $padding       = 0;
		my @headers;
		foreach my $header (@columns_array) {

			push( @headers, $column_names->{$header} );

			if   ( ( $header_int % 2 ) != 0 ) { $padding = 1; }
			else                              { $padding = 0; }

			$tb->set_column_style( $header_int, pad => $padding );

			$header_int++;
		} ## end foreach my $header (@columns_array)

		$tb->columns( \@headers );

		#
		# process each found row
		#
		my @td;
		foreach my $row ( @{$returned} ) {
			my @new_line;

			foreach my $column (@columns_array) {

				if ( $column eq 'rule_id' ) {
					$row->{rule_id} = $row->{gid} . ':' . $row->{sid} . ':' . $row->{rev};
				}

				if ( defined( $row->{$column} ) && $column eq 'rule_id' ) {
					push( @new_line, $row->{gid} . ':' . $row->{sid} . ':' . $row->{rev} );
				} elsif ( defined( $row->{$column} ) && $column eq 'classification' ) {
					push( @new_line, $lilith->get_short_class( $row->{$column} ) );
				} elsif ( defined( $row->{$column} ) && ( $column eq 'src_ip' || $column eq 'dest_ip' ) ) {
					if ( defined( $ENV{Lilith_IP_color} ) ) {
						if (   $row->{$column} =~ /^192\.168\./
							|| $row->{$column} =~ /^10\./
							|| $row->{$column} =~ /^172\.16/
							|| $row->{$column} =~ /^172\.17/
							|| $row->{$column} =~ /^172\.19/
							|| $row->{$column} =~ /^172\.19/
							|| $row->{$column} =~ /^172\.20/
							|| $row->{$column} =~ /^172\.21/
							|| $row->{$column} =~ /^172\.22/
							|| $row->{$column} =~ /^172\.23/
							|| $row->{$column} =~ /^172\.24/
							|| $row->{$column} =~ /^172\.25/
							|| $row->{$column} =~ /^172\.26/
							|| $row->{$column} =~ /^172\.26/
							|| $row->{$column} =~ /^172\.27/
							|| $row->{$column} =~ /^172\.28/
							|| $row->{$column} =~ /^172\.29/
							|| $row->{$column} =~ /^172\.30/
							|| $row->{$column} =~ /^172\.31/ )
						{
							$row->{$column} = color( $ENV{Lilith_IP_private_color} ) . $row->{$column} . color('reset');
						} elsif ( $row->{$column} =~ /^127\./ ) {
							$row->{$column} = color( $ENV{Lilith_IP_local_color} ) . $row->{$column} . color('reset');
						} else {
							$row->{$column} = color( $ENV{Lilith_IP_remote_color} ) . $row->{$column} . color('reset');
						}
					} ## end if ( defined( $ENV{Lilith_IP_color} ) )
					push( @new_line, $row->{$column} );
				} elsif ( defined( $row->{$column} ) && $column eq 'timestamp' ) {
					if ( $ENV{Lilith_timesamp_drop_micro} ) {
						$row->{$column} =~ s/\.[0-9]+//;
					}
					if ( $ENV{Lilith_timesamp_drop_offset} ) {
						$row->{$column} =~ s/\-[0-9]+$//;
					}
					push( @new_line, $row->{$column} );
				} elsif ( defined( $row->{$column} ) && $column eq 'instance' && $ENV{Lilith_instance_color} ) {
					my $color0 = color( $ENV{Lilith_instance_slug_color} );
					my $color1 = color('reset');
					my $color3 = color( $ENV{Lilith_instance_type_color} );
					my $color4 = color( $ENV{Lilith_instance_loc_color} );
					$row->{$column} =~ s/(^[A-Za-z0-9]+)\-/$color0$1$color1-/;
					$row->{$column} =~ s/\-(ids|pie|lae)$/-$color3$1$color1/;
					$row->{$column} =~ s/\-([A-Za-z0-9\-]+)\-/-$color4$1$color1/;
					push( @new_line, $row->{$column} );
				} elsif ( defined( $row->{$column} ) && ref( $row->{$column} ) eq 'ARRAY' ) {
					# PG array columns, e.g. escalations, come back as array refs
					push( @new_line, join( ',', @{ $row->{$column} } ) );
				} elsif ( defined( $row->{$column} ) ) {
					push( @new_line, $row->{$column} );
				} else {
					push( @new_line, '' );
				}

			} ## end foreach my $column (@columns_array)

			push( @td, \@new_line );
		} ## end foreach my $row ( @{$returned} )

		#
		# print the table
		#
		$tb->add_rows( \@td );
		print $tb->draw;
		return;
	} ## end elsif ( $search_output eq 'table' )

	# bad selection via --output
	die('No applicable output found');
} ## end sub execute

1;
