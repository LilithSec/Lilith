# search -- the default command, and the one most used: query the annals and
# print the matching alerts as a table or as JSON. A bare `lilith`, or one whose
# first argument is an option, lands here.
#
# The filters are described in docs/usage.md. Most share a small grammar: an
# integer option takes a comma separated list with each item negatable by a
# leading !, a string option may match with SQL LIKE wildcards and negate the
# same way, and positive values are ORed while negated ones are ANDed. Which
# columns are shown is picked with --columns or a named --columnset.
#
#     lilith search -m 60 --ip 192.0.2.10 -p 22
#     lilith search -c '!%scan%' --output json
package Lilith::CLI::Command::Search;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use Term::ANSIColor qw( color );

sub abstract { 'search the database' }

# The filters, in three groups: the paging and output options first, then the
# ones common to the suricata/sagan/baphomet tables, then the cape-only ones at
# the end. Nothing here restricts an option to its table -- search() drops a
# filter naming a column the chosen table lacks, so --malscore against suricata
# is ignored rather than an error, which is what lets the web UI hand its
# suricata-shaped form at any table.
sub opt_spec {
	my ($class) = @_;
	return (
		[ 't=s', 'table to operate on', { default => 'suricata' } ],
		$class->output_opt_spec,
		[ 'm=s',         'how far back to search, in minutes' ],
		[ 'order=s',     'column to sort by' ],
		[ 'orderdir=s',  'sort direction, ASC or DESC' ],
		[ 'limit=s',     'row limit' ],
		[ 'offset=s',    'row offset' ],
		[ 'bucket',      'baphomet only: compress rows sharing an instance, signature, and subjects to the newest' ],
		[ 'columns=s',   'comma separated list of columns' ],
		[ 'columnset=s', 'named column set', { default => 'default' } ],
		[ 'si=s',             'source IP' ],
		[ 'di=s',             'destination IP' ],
		[ 'ip=s',             'IP, either source or destination' ],
		[ 'sp=s@',            'source port' ],
		[ 'dp=s@',            'destination port' ],
		[ 'p=s',              'port, either source or destination' ],
		[ 'host=s',           'host' ],
		[ 'ih=s',             'instance host' ],
		[ 'i=s',              'instance' ],
		[ 'c=s@',             'classification' ],
		[ 'class_not|cN=s@',  'classification to exclude; appended to the class list with a leading !' ],
		[ 'class_like|cl=s@', 'classification to match using like; wrapped in % unless the value contains one' ],
		[ 's=s',              'signature' ],
		[ 'if=s',             'in interface' ],
		[ 'proto=s',          'proto' ],
		[ 'ap=s',             'app proto' ],
		[ 'gid=s@',           'GID' ],
		[ 'sid=s@',           'SID' ],
		[ 'rev=s@',           'rev' ],
		[ 'subip=s',          'the IP the sample was submitted from' ],
		[ 'subhost=s',        'the host the sample was submitted from' ],
		[ 'slug=s',           'the slug it was submitted with' ],
		[ 'pkg=s',            'the detonation package used with CAPEv2' ],
		[ 'malscore=s@',      'the malscore of the sample' ],
		[ 'size=s@',          'the size of the sample' ],
		[ 'target=s',         'the detonation target' ],
		[ 'task=s@',          'the task ID of the run' ],
		[ 'user=s',           'the username the line was about' ],
		[
			'subjects=s@',
			"subject vars: JSON for the whole set, VAR=value or bare VAR for one (! negates), 'none' for none (baphomet)"
		],
		[ 'shodan_src_tag=s@',    'Shodan tag on the source' ],
		[ 'shodan_dest_tag=s@',   'Shodan tag on the destination' ],
		[ 'shodan_src_known=s@',  'Shodan cache state for the source: known, unknown, or unchecked' ],
		[ 'shodan_dest_known=s@', 'Shodan cache state for the destination: known, unknown, or unchecked' ],
		[ 'shodan_src_cvss=s@',   'worst CVSS on the source; takes the numeric comparison operators' ],
		[ 'shodan_dest_cvss=s@',  'worst CVSS on the destination; takes the numeric comparison operators' ],
		[ 'cve=s@',               'CVE id the rule names (suricata)' ],
		[
			'shodan_src_cve_match=s@',
			'rule CVEs against the source cache: matched, unmatched, no-cve, or unchecked'
		],
		[
			'shodan_dest_cve_match=s@',
			'rule CVEs against the destination cache: matched, unmatched, no-cve, or unchecked'
		],
		[ 'src_locality=s@',  'which side of local_networks the source sits on: internal or external' ],
		[ 'dest_locality=s@', 'which side of local_networks the destination sits on: internal or external' ],
	);
} ## end sub opt_spec

# Build the search from the options and render the results.
#
# Args:
#
#   - $opt :: the parsed options, as opt_spec above describes them -- the
#     table, the window, paging, which columns to show, and the filters
#     themselves.
#   - $args :: array ref of leftover positional arguments. Unused; every
#     filter is an option.
#
# Returns: whatever the chosen renderer returned. Prints the matching alerts as
# an ANSI table or as JSON, and an empty table or array when nothing matched.
# An unparseable time value or an unknown column dies out of Lilith with the
# reason.
sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith     = $self->lilith;
	my $table      = $opt->{t};
	my $pretty     = $opt->{pretty};
	my $columns    = $opt->{columns};
	my $column_set = $opt->{columnset};

	# class may be given multiple times and/or comma separated
	my @class = @{ $opt->{c} // [] };
	@class = split( /\s*,\s*/, join( ',', @class ) );

	# --cN excludes a class via the leading ! Lilith::search supports
	foreach my $class_not_value ( @{ $opt->{class_not} // [] } ) {
		push( @class, '!' . $class_not_value );
	}

	# --cl like-matches a class; a % in the value triggers like matching in
	# Lilith::search, so wrap the value in % unless it already contains one
	foreach my $class_like_value ( @{ $opt->{class_like} // [] } ) {
		if ( $class_like_value !~ /\%/ ) {
			$class_like_value = '%' . $class_like_value . '%';
		}
		push( @class, $class_like_value );
	}

	# The shodan/cve/locality filters may be given multiple times and/or comma
	# separated, the same as class. Only the ones actually used go into the
	# search, so a blank one adds nothing.
	my %enrich_filter;
	foreach my $enrich_name (
		qw( shodan_src_tag shodan_dest_tag shodan_src_known
		shodan_dest_known shodan_src_cvss shodan_dest_cvss cve
		shodan_src_cve_match shodan_dest_cve_match
		src_locality dest_locality )
		)
	{
		my @values = split( /\s*,\s*/, join( ',', @{ $opt->{$enrich_name} // [] } ) );
		$enrich_filter{$enrich_name} = \@values if @values;
	} ## end foreach my $enrich_name ( qw( shodan_src_tag shodan_dest_tag shodan_src_known...))

	# what the locality filters judge against -- the config's networks, the
	# same list the dashboard dimensions read
	my $toml = $self->config;
	$enrich_filter{local_networks} = $toml->{local_networks}
		if ref $toml->{local_networks} eq 'ARRAY' && @{ $toml->{local_networks} };

	#
	# run the search
	#
	my $returned = $lilith->search(
		%enrich_filter,

		# baphomet only; Lilith::search ignores it elsewhere, like a filter
		# naming a column the table lacks
		bucket => $opt->{bucket},

		src_ip           => $opt->{si},
		src_port         => $opt->{sp} // [],
		dest_ip          => $opt->{di},
		dest_port        => $opt->{dp} // [],
		ip               => $opt->{ip},
		port             => $opt->{p},
		table            => $table,
		host             => $opt->{host},
		instance_host    => $opt->{ih},
		instance         => $opt->{i},
		class            => \@class,
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
		username         => $opt->{user},
		subjects         => $opt->{subjects} // [],
	);

	#
	# assemble the selected output
	#
	return $self->output_dispatch(
		$opt,
		json  => sub { $self->print_json( $returned, $pretty ) },
		table => sub {

			#
			# set the columns if they had not been manually specified
			#
			if ( !defined($columns) ) {
				my %column_sets = (
					suricata => {
						default =>
							'id,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id',
						default_timestamp =>
							'timestamp,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id',
						default_event =>
							'id,event_id,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id',
						default_timestamp_event =>
							'timestamp,event_id,instance,in_iface,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,classification,rule_id',
					},
					sagan => {
						default =>
							'id,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id',
						default_timestamp =>
							'timestamp,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id',
						default_event =>
							'id,event_id,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id',
						default_timestamp_event =>
							'timestamp,event_id,instance,src_ip,host,xff,facility,level,priority,program,signature,classification,rule_id',
					},
					cape => {
						default => 'id,instance,slug,target,size,pkg,malscore,subbed_from_ip,subbed_from_host',
					},
					baphomet => {
						default => 'id,instance,event_type,src_ip,username,severity,signature,classification,score',
						default_timestamp =>
							'timestamp,instance,event_type,src_ip,username,severity,signature,classification,score',
					},
				);
				$columns = $column_sets{$table}{$column_set}
					// die( '"' . $column_set . '" is not a known column set' );

				# a bucketed search compresses each (instance, signature,
				# subjects) group to its newest row; show how many each stands
				# for, as the web Count column does
				$columns .= ',bucket_count' if $opt->{bucket} && $table eq 'baphomet';
			} ## end if ( !defined($columns) )

			# friendly column names; a column not listed here is headed by its own
			# name, so only the actual renames are listed
			my $column_names = {
				'in_iface'            => 'if',
				'src_port'            => 'sport',
				'dest_port'           => 'dport',
				'app_proto'           => 'aproto',
				'flow_pkts_toserver'  => 'PtS',
				'flow_bytes_toserver' => 'BtS',
				'flow_pkts_toclient'  => 'PtC',
				'flow_bytes_toclient' => 'BtC',
				'classification'      => 'class',
				'event_id'            => 'event',
				'username'            => 'user',
				'bucket_count'        => 'count',
			};

			#
			# init the table
			#
			my @columns_array = split( /,/, $columns );
			my @headers       = map { $column_names->{$_} // $_ } @columns_array;
			my $tb            = $self->table(@headers);

			#
			# process each found row
			#
			my @td;
			foreach my $row ( @{$returned} ) {
				my @new_line;

				foreach my $column (@columns_array) {

					# rule_id is not a real column but gid:sid:rev of the row
					if ( $column eq 'rule_id' ) {
						push( @new_line,
							( $row->{gid} // '' ) . ':' . ( $row->{sid} // '' ) . ':' . ( $row->{rev} // '' ) );
					} elsif ( defined( $row->{$column} ) && $column eq 'classification' ) {
						push( @new_line, $lilith->get_short_class( $row->{$column} ) );
					} elsif ( defined( $row->{$column} ) && ( $column eq 'src_ip' || $column eq 'dest_ip' ) ) {
						if ( $ENV{Lilith_IP_color} ) {
							if (   $row->{$column} =~ /^10\./
								|| $row->{$column} =~ /^172\.(?:1[6-9]|2[0-9]|3[01])\./
								|| $row->{$column} =~ /^192\.168\./ )
							{
								$row->{$column}
									= color( $ENV{Lilith_IP_private_color} ) . $row->{$column} . color('reset');
							} elsif ( $row->{$column} =~ /^127\./ ) {
								$row->{$column}
									= color( $ENV{Lilith_IP_local_color} ) . $row->{$column} . color('reset');
							} else {
								$row->{$column}
									= color( $ENV{Lilith_IP_remote_color} ) . $row->{$column} . color('reset');
							}
						} ## end if ( $ENV{Lilith_IP_color} )
						push( @new_line, $row->{$column} );
					} elsif ( defined( $row->{$column} ) && $column eq 'timestamp' ) {
						if ( $ENV{Lilith_timestamp_drop_micro} ) {
							$row->{$column} =~ s/\.[0-9]+//;
						}
						if ( $ENV{Lilith_timestamp_drop_offset} ) {
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
		},
	);
} ## end sub execute

1;
