package Lilith::Web;

use Mojo::Base 'Mojolicious';
use Mojo::File   qw(curfile);
use TOML         qw(from_toml);
use File::Slurp  qw(read_file);
use File::Temp   ();
use Mojo::IOLoop ();
use Lilith       ();

# When run from a checkout, share/ lives three directories up from
# lib/Lilith/Web.pm and takes priority so an installed copy of the dist
# does not shadow the local templates.
my $SHARE_DIR = curfile->dirname->dirname->dirname->child('share')->to_string;
unless ( -d $SHARE_DIR ) {
	# File::ShareDir is optional — only available once the dist is installed.
	eval {
		require File::ShareDir;
		$SHARE_DIR = File::ShareDir::dist_dir('Lilith');
	};
}
die "Cannot locate Lilith share directory\n" unless defined($SHARE_DIR) && -d $SHARE_DIR;

=head1 NAME

Lilith::Web - Mojolicious web frontend for Lilith.

=head1 SYNOPSIS

    # Start via mojo_lilith script
    mojo_lilith daemon

    # Or directly
    LILITH_CONFIG=/usr/local/etc/lilith.toml mojo_lilith daemon -l http://*:8080

=head1 DESCRIPTION

Mojolicious application providing a web UI for searching Suricata, Sagan, and
CAPE alerts stored in the Lilith PostgreSQL database.

The config file path is read from the C<LILITH_CONFIG> environment variable,
defaulting to C</usr/local/etc/lilith.toml>.

=cut

sub startup {
	my $self = shift;

	my $config_file = $ENV{LILITH_CONFIG} // '/usr/local/etc/lilith.toml';

	die "Config file '$config_file' does not exist\n"
		unless -f $config_file;

	my $toml_raw = read_file($config_file)
		or die 'Failed to read "' . $config_file . '"';

	my ( $toml, $err ) = from_toml($toml_raw);
	die "Error parsing toml '$config_file': $err\n" unless $toml;

	my $lilith = Lilith->new(
		dsn                        => $toml->{dsn},
		user                       => $toml->{user},
		pass                       => $toml->{pass},
		escalation_type_namespaces =>
			( ref $toml->{escalation_type_namespaces} eq 'ARRAY' ? $toml->{escalation_type_namespaces} : [] ),
	);

	$self->helper( lilith => sub { $lilith } );

	# Whether the escalation system is available in the web UI. Off by
	# default as the escalation endpoints can push data at outside services
	# and change escalation target config.
	$self->helper( escalation_enable => sub { $toml->{escalation_enable} ? 1 : 0 } );

	# Whether escalation targets may be created/edited/deleted/tested from the
	# web UI. Off by default and separate from escalation_enable: viewing the
	# configured targets is read only, while editing them changes where alerts
	# are sent and can push test data at outside services. The /escalation view
	# and its read endpoints are gated by escalation_enable; the /escalation/edit
	# page and the mutating target endpoints additionally require this.
	$self->helper( escalation_manage_enable => sub { $toml->{escalation_manage_enable} ? 1 : 0 } );

	# Whether auto escalation rules may be created/edited/deleted from the web
	# UI. Off by default and separate from escalation_enable: a saved+enabled
	# rule escalates automatically on the timer with no human in the loop, so
	# editing it is more sensitive than the manual escalate button. The
	# /auto_escalation page and its read/preview endpoints are gated by
	# escalation_enable; only the mutating endpoints additionally require this.
	$self->helper( auto_escalation_manage_enable => sub { $toml->{auto_escalation_manage_enable} ? 1 : 0 } );

	my $dnstracer_flags = [];
	if ( ref $toml->{dnstracer_flags} eq 'ARRAY' ) {
		$dnstracer_flags = $toml->{dnstracer_flags};
	}
	$self->helper( dnstracer_flags  => sub { $dnstracer_flags } );
	$self->helper( dnstracer_enable => sub { $toml->{dnstracer_enable}       ? 1                           : 0 } );
	$self->helper( dns_bg_timeout   => sub { defined $toml->{dns_bg_timeout} ? $toml->{dns_bg_timeout} + 0 : 3 } );

	# Optional in-memory cache for /api/domaininfo results. Enabled with
	# domaininfo_cache; entries are considered fresh for domaininfo_cache_ttl
	# seconds (default 300). The store is per worker process.
	my %domaininfo_cache;
	$self->helper( domaininfo_cache         => sub { \%domaininfo_cache } );
	$self->helper( domaininfo_cache_enabled => sub { $toml->{domaininfo_cache} ? 1 : 0 } );
	$self->helper(
		domaininfo_cache_ttl => sub {
			defined $toml->{domaininfo_cache_ttl} ? $toml->{domaininfo_cache_ttl} + 0 : 300;
		}
	);

	# GeoIP / MMDB lookups.  Each database type has its own config key pointing
	# at a MaxMind DB file; when a key is omitted the standard filename under the
	# platform's GeoIP directory is used if it exists.  The web UI's IP info
	# modal merges records from every database that opened.  Databases are opened
	# once at startup so lookups stay cheap.
	my $geoip_dir  = ( $^O eq 'freebsd' ) ? '/usr/local/share/GeoIP' : '/usr/share/GeoIP';
	my @geoip_defs = (
		{ key => 'geoip_ip_city',    file => 'GeoLite2-City.mmdb' },
		{ key => 'geoip_ip_country', file => 'GeoLite2-Country.mmdb' },
		{ key => 'geoip_ip_asn',     file => 'GeoLite2-ASN.mmdb' },
	);
	my @mmdbs;
	for my $def (@geoip_defs) {
		my $configured = ( defined $toml->{ $def->{key} } && !ref $toml->{ $def->{key} } );
		my $path       = $configured ? $toml->{ $def->{key} } : $geoip_dir . '/' . $def->{file};

		# A missing default is normal (the DB simply is not installed); only an
		# explicitly configured path that is absent is worth a warning.
		if ( !-e $path ) {
			warn 'Lilith::Web: configured MMDB "' . $path . '" for ' . $def->{key} . " does not exist\n"
				if $configured;
			next;
		}

		require IP::Geolocation::MMDB;
		my $db = eval { IP::Geolocation::MMDB->new( file => $path ) };
		if ($db) {
			push( @mmdbs, $db );
		} else {
			warn 'Lilith::Web: failed to open MMDB "' . $path . '"' . ( $@ ? ": $@" : "\n" );
		}
	} ## end for my $def (@geoip_defs)
	$self->helper( geoip_mmdbs => sub { \@mmdbs } );

	# Country + top subdivision (state/province) codes plus city name for an IP
	# from a single pass over the databases -- one record_for_address per DB
	# instead of one per field. Country falls back from the physical 'country' to
	# 'registered_country' / 'represented_country' so anycast and hosting IPs
	# (which often carry only a registered country, e.g. Cloudflare) still
	# resolve. City only comes from the City database (registered/represented
	# records carry no city). Results are memoized per request so repeated IPs
	# across many rows only hit the databases once. Returns
	# { country => 'US', subdivision => 'TX', city => 'Austin' } with empty
	# strings for anything unknown.
	$self->helper(
		ip_geo => sub {
			my ( $c, $ip ) = @_;
			my $empty = { country => '', subdivision => '', city => '' };
			return $empty unless defined $ip && $ip =~ /^[0-9a-fA-F:.]+$/;

			my $cache;
			if ( eval { $c->can('stash') } ) {
				$cache = $c->stash->{'_ip_geo_cache'} ||= {};
				return $cache->{$ip} if $cache->{$ip};
			}

			my $country     = '';
			my $subdivision = '';
			my $city        = '';
			for my $db (@mmdbs) {
				my $record = eval { $db->record_for_address($ip) };
				next unless ref $record eq 'HASH';
				if ( $country eq '' ) {
					for my $field (qw( country registered_country represented_country )) {
						my $cc = ref $record->{$field} eq 'HASH' ? $record->{$field}{iso_code} : undef;
						if ( defined $cc && $cc ne '' ) { $country = uc $cc; last; }
					}
				}
				if ( $subdivision eq '' ) {
					my $subs = $record->{subdivisions};
					if ( ref $subs eq 'ARRAY' && ref $subs->[0] eq 'HASH' ) {
						my $code = $subs->[0]{iso_code};
						$subdivision = uc $code if defined $code && $code ne '';
					}
				}
				if ( $city eq '' && ref $record->{city} eq 'HASH' ) {
					my $names = $record->{city}{names};
					my $name  = ref $names eq 'HASH' ? $names->{en} : undef;
					$city = $name if defined $name && $name ne '';
				}
				last if $country ne '' && $subdivision ne '' && $city ne '';
			} ## end for my $db (@mmdbs)

			my $geo = { country => $country, subdivision => $subdivision, city => $city };
			$cache->{$ip} = $geo if $cache;
			return $geo;
		}
	);

	# Thin wrappers kept for template/readability convenience; all share the one
	# ip_geo lookup above.
	$self->helper( ip_country     => sub { $_[0]->ip_geo( $_[1] )->{country} } );
	$self->helper( ip_subdivision => sub { $_[0]->ip_geo( $_[1] )->{subdivision} } );
	$self->helper( ip_city        => sub { $_[0]->ip_geo( $_[1] )->{city} } );

	# Regional-indicator emoji flag for a two-letter country code, e.g. 'US' ->
	# the flag. Returns '' for anything that is not two ASCII letters.
	$self->helper(
		country_flag => sub {
			my ( $c, $cc ) = @_;
			return '' unless defined $cc && $cc =~ /^[A-Za-z]{2}$/;
			return join( '', map { chr( 0x1F1E6 + ( ord( uc $_ ) - ord('A') ) ) } split( //, $cc ) );
		}
	);

	# Remote Virani instances for PCAP retrieval. Each is a [virani.NAME] table
	# with at least a 'url' pointing at a mojo-virani server. The PCAP download
	# feature in the event view is enabled whenever one or more are configured.
	my %virani;
	if ( ref $toml->{virani} eq 'HASH' ) {
		foreach my $name ( keys %{ $toml->{virani} } ) {
			my $cfg = $toml->{virani}{$name};
			next unless ref $cfg eq 'HASH' && defined $cfg->{url} && $cfg->{url} ne '';
			$virani{$name} = $cfg;
		}
	}
	$self->helper( virani_remotes => sub { \%virani } );
	$self->helper( virani_enabled => sub { scalar( keys %virani ) ? 1 : 0 } );

	# Whether the standalone Virani PCAP search (arbitrary filter/time range) may
	# download through the web server. When off, that tool only builds the local
	# virani command. Off by default because it exposes arbitrary captures.
	$self->helper( virani_search_enable => sub { $toml->{virani_search_enable} ? 1 : 0 } );

	# A ready Virani::Client for the named remote, or undef if unknown/unusable.
	$self->helper(
		virani_client_for => sub {
			my ( $c, $name ) = @_;
			my $cfg = ( defined $name && $virani{$name} ) ? $virani{$name} : undef;
			return undef unless $cfg;
			my $client = eval {
				require Virani::Client;
				Virani::Client->new(
					url             => $cfg->{url},
					apikey          => $cfg->{apikey},
					timeout         => ( defined $cfg->{timeout} ? $cfg->{timeout} + 0 : 60 ),
					verify_hostname =>
						( defined $cfg->{verify_hostname} ? ( $cfg->{verify_hostname} ? 1 : 0 ) : 1 ),
				);
			};
			if ($@) {
				warn( 'Lilith: failed to create Virani::Client for "' . $name . '": ' . $@ );
			}
			return $client;
		}
	);

	# Run $fetch_code->($tmpfile) (which fetches a PCAP into that path via some
	# Virani::Client method) and stream the result back as a download named
	# $download_name. The blocking fetch runs in a subprocess so the event loop
	# stays responsive. Shared by the per-event download, the standalone search,
	# and cached-PCAP retrieval.
	$self->helper(
		virani_stream_pcap => sub {
			my ( $c, $fetch_code, $download_name ) = @_;

			my $tmp = File::Temp->new( SUFFIX => '.pcap' );
			$c->render_later;
			Mojo::IOLoop->subprocess(
				sub {
					my $err;
					eval {
						# Virani::Client fetch methods print to STDOUT; discard it.
						local *STDOUT;
						open( STDOUT, '>', \my $ignore ) or 1;
						$fetch_code->( $tmp->filename );
					};
					$err = $@;
					my $bytes;
					if ( !$err && open( my $fh, '<:raw', $tmp->filename ) ) {
						local $/;
						$bytes = <$fh>;
						close($fh);
					}
					return ( $err, $bytes );
				},
				sub {
					my ( $subprocess, $sp_err, $fetch_err, $bytes ) = @_;
					undef $tmp;    # keep the temp file alive until the child has read it
					if ($sp_err) {
						return $c->render( text => 'PCAP subprocess failed: ' . $sp_err, status => 500 );
					}
					if ($fetch_err) {
						( my $why = $fetch_err ) =~ s/\s+\z//;
						return $c->render( text => 'PCAP fetch failed: ' . $why, status => 502 );
					}
					if ( !defined $bytes ) {
						return $c->render( text => 'failed to read fetched PCAP', status => 500 );
					}
					$c->res->headers->content_type('application/vnd.tcpdump.pcap');
					$c->res->headers->content_disposition( 'attachment; filename="' . $download_name . '"' );
					$c->render( data => $bytes );
				},
			);
			return;
		}
	);

	# Referer checking — enforced only when allowed_referers is non-empty in the
	# config.  Each entry is treated as a URL prefix; a request is allowed if its
	# Referer header starts with any of the configured prefixes.
	my @allowed_referers;
	if ( ref $toml->{allowed_referers} eq 'ARRAY' ) {
		@allowed_referers = @{ $toml->{allowed_referers} };
	}
	if (@allowed_referers) {
		$self->hook(
			before_dispatch => sub {
				my $c       = shift;
				my $referer = $c->req->headers->referrer // '';
				for my $allowed (@allowed_referers) {
					return if index( $referer, $allowed ) == 0;
				}
				$c->render(
					json   => { error => 'Forbidden: invalid or missing Referer' },
					status => 403,
				);
			}
		);
	} ## end if (@allowed_referers)

	# Point Mojolicious at share/templates and share/public so the app works
	# both when installed (File::ShareDir path) and when run from the repo.
	unshift @{ $self->renderer->paths }, "$SHARE_DIR/templates";
	unshift @{ $self->static->paths },   "$SHARE_DIR/public";

	my $r = $self->routes;
	$r->get('/')->to( cb => sub { $_[0]->redirect_to('/search') } );
	$r->get('/search')->to('search#index');
	$r->get('/event/:table/:id')->to('event#view');
	$r->get('/event/:table/:id/body/:which/zip')->to('event#body_zip');
	$r->get('/event/:table/:id/pcap')->to('event#pcap');
	$r->get('/api/ipinfo/*ip')->to('api#ipinfo');
	$r->get('/api/domaininfo/*domain')->to('api#domaininfo');
	$r->get('/api/httpsinfo/*domain')->to('api#httpsinfo');
	$r->get('/api/mailinfo/*domain')->to('api#mailinfo');
	$r->get('/api/virani/sets/:remote')->to('api#virani_sets');
	$r->get('/api/virani/pcap')->to('api#virani_pcap');
	$r->get('/api/virani/cached/:remote')->to('api#virani_cached_list');
	$r->get('/api/virani/cached/:remote/pcap/:id')->to('api#virani_cached_pcap');
	$r->get('/api/virani/cached/:remote/meta/:id')->to('api#virani_cached_meta');
	$r->get('/escalation')->to('escalation#index');
	$r->get('/escalation/edit')->to( 'escalation#index', mode => 'edit' );
	$r->get('/api/escalation/types')->to('escalation#types');
	$r->get('/api/escalation/targets')->to('escalation#targets');
	$r->post('/api/escalation/targets')->to('escalation#target_save');
	$r->post('/api/escalation/targets/:id/delete')->to('escalation#target_delete');
	$r->post('/api/escalation/targets/:id/test')->to('escalation#target_test');
	$r->post('/api/escalation/escalate')->to('escalation#escalate');
	$r->get('/api/escalation/history/:table/:id')->to('escalation#history');
	$r->get('/auto_escalation')->to('auto_escalation#index');
	$r->get('/api/auto_escalation/rules')->to('auto_escalation#rules');
	$r->post('/api/auto_escalation/rules')->to('auto_escalation#save');
	$r->post('/api/auto_escalation/rules/:id/delete')->to('auto_escalation#delete');
	$r->post('/api/auto_escalation/rules/:id/toggle')->to('auto_escalation#toggle');
	$r->post('/api/auto_escalation/preview')->to('auto_escalation#preview');
} ## end sub startup

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
