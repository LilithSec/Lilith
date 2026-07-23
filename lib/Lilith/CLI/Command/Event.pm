package Lilith::CLI::Command::Event;

use strict;
use warnings;
use parent 'Lilith::CLI::Command';
use JSON               qw( decode_json );
use Time::Piece::Guess ();

sub abstract { 'fetch a event' }

sub usage_desc { '%c event %o' }

sub opt_spec {
	return (
		[ 't=s',      'table to operate on', { default => 'suricata' } ],
		[ 'id=s',     'fetch event via row ID' ],
		[ 'event=s',  'fetch event via event ID' ],
		[ 'raw',      'do not decode the EVE JSON' ],
		[ 'pretty',   'pretty print the JSON' ],
		[ 'pcap=s',   'fetch the remote PCAP via Virani and write it to this file' ],
		[ 'virani=s', 'Virani remote to use' ],
		[ 'buffer=s', 'seconds to pad the start and end time with', { default => 60 } ],
	);
} ## end sub opt_spec

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->{id} ) && !defined( $opt->{event} ) ) {
		$self->usage_error('either --id or --event is required for fetching a event');
	}

	if ( $opt->{buffer} !~ /^\d+$/ ) {
		$self->usage_error( '--buffer is set to "' . $opt->{buffer} . '" which is non-numeric' );
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $lilith   = $self->lilith;
	my $event_id = $opt->{event};
	my $table    = $opt->{t};

	my %search_args = (
		table   => $table,
		debug   => $self->app->global_options->debug,
		no_time => 1,
		limit   => 1,
	);
	# id is one of search()'s numeric items, which take an array ref
	$search_args{id}       = [ $opt->{id} ] if defined( $opt->{id} );
	$search_args{event_id} = $event_id      if defined($event_id);

	my $returned = $lilith->search(%search_args);

	if ( !defined( $returned->[0] ) ) {
		print "{}\n";
		exit 42;
	}

	if (   !$opt->{raw}
		&& defined( $returned->[0] )
		&& defined( $returned->[0]{raw} ) )
	{
		$returned->[0]{raw} = decode_json( $returned->[0]{raw} );
	}

	$self->print_json( $returned->[0], $opt->{pretty} );

	if ( $opt->{pcap} ) {
		if ( $table ne 'suricata' ) {
			die '--pcap is only supported for Suricata';
		}

		print "\n";

		my $remote_arg = $opt->{virani};
		if ( !defined( $opt->{virani} ) ) {
			$remote_arg = $returned->[0]{instance};
		}

		my $filter = 'host ' . $returned->[0]{src_ip} . ' and host ' . $returned->[0]{dest_ip};
		if (   defined( $returned->[0]{src_port} )
			&& defined( $returned->[0]{dest_port} )
			&& $returned->[0]{dest_port} =~ /^\d+$/
			&& $returned->[0]{src_port}  =~ /^\d+$/ )
		{
			$filter
				= $filter . ' and ( port ' . $returned->[0]{src_port} . ' or port ' . $returned->[0]{dest_port} . ' ) ';
		}

		my $start_obj;
		eval { $start_obj = Time::Piece::Guess->guess_to_object( $returned->[0]{flow_start}, 1 ); };
		if ( $@ || !defined($start_obj) ) {
			die( 'Failed to parse the start stamp,"' . $returned->[0]{flow_start} . '",' );
		}
		$start_obj = $start_obj - $opt->{buffer};

		my $end_obj;
		eval { $end_obj = Time::Piece::Guess->guess_to_object( $returned->[0]{timestamp}, 1 ); };
		if ( $@ || !defined($end_obj) ) {
			die( 'Failed to parse the timestamp,"' . $returned->[0]{timestamp} . '",' );
		}
		$end_obj = $end_obj + $opt->{buffer};

		system(
			'virani',          '-r', $remote_arg,     '-w', $opt->{pcap}, '-s',
			$start_obj->epoch, '-e', $end_obj->epoch, '-f', $filter
		);
	} ## end if ( $opt->{pcap} )

	return;
} ## end sub execute

1;
