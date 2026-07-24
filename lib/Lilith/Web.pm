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

	# Read tier gate shared by the escalation and auto escalation controllers;
	# returns 1 when the caller may proceed, else renders the 404 and returns 0.
	$self->helper(
		require_escalation_view => sub {
			my $controller = shift;

			if ( !$controller->escalation_enable ) {
				$controller->reply->not_found;
				return 0;
			}

			return 1;
		}
	);

	# Write tier gate shared by the escalation and auto escalation controllers;
	# view must be allowed and the passed management flag explicitly enabled.
	# Renders a 404 (view off) or a 403 with the passed message (management off)
	# and returns 0 on refusal.
	$self->helper(
		require_escalation_manage => sub {
			my ( $controller, $manage_enabled, $disabled_message ) = @_;

			return 0 unless $controller->require_escalation_view;

			if ( !$manage_enabled ) {
				$controller->render( json => { error => $disabled_message }, status => 403 );
				return 0;
			}

			return 1;
		}
	);

	# Render whatever $code->(@code_args) returns as JSON, turning a die (bad
	# column/source, unreachable database, ...) into a 400 with the message.
	# Shared by the dashboard and logs JSON APIs.
	$self->helper(
		render_json_or_400 => sub {
			my ( $controller, $code, @code_args ) = @_;

			my $data = eval { $code->(@code_args) };
			if ($@) {
				( my $why = $@ ) =~ s/\s+\z//;
				return $controller->render( json => { error => $why }, status => 400 );
			}
			return $controller->render( json => $data );
		}
	);

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

	# Allani log store. An [allani] block with a 'dsn' (plus optional user/pass)
	# points at the PostgreSQL database Allani writes its logs to; when present,
	# the read-only /logs page can browse them. The reader is built lazily and
	# cached (it needs Allani installed for Allani::Sources), so a config without
	# the block, or a missing Allani, simply leaves the feature off.
	my $allani_cfg = ( ref $toml->{allani} eq 'HASH' ) ? $toml->{allani} : undef;
	my $allani_reader;
	$self->helper(
		allani_enabled => sub { ( $allani_cfg && defined $allani_cfg->{dsn} && $allani_cfg->{dsn} ne '' ) ? 1 : 0 }
	);
	$self->helper(
		allani => sub {
			return $allani_reader if $allani_reader;
			require Lilith::Allani;
			$allani_reader = Lilith::Allani->new(
				dsn  => $allani_cfg->{dsn},
				user => $allani_cfg->{user},
				pass => $allani_cfg->{pass},
			);
			return $allani_reader;
		}
	);

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

	# CAPE submission. cape_enable turns the feature on; the [cape_servers.NAME]
	# tables are the CAPE boxes samples may be submitted to and cape_slug is the
	# default slug. Off by default, since a submission pushes a file to an outside
	# service; the feature is available only when enabled and at least one server
	# with a url is configured (mirrors the virani gate).
	require Lilith::CapeSubmit;
	my %cape_servers;
	if ( ref $toml->{cape_servers} eq 'HASH' ) {
		foreach my $name ( keys %{ $toml->{cape_servers} } ) {
			my $cfg = $toml->{cape_servers}{$name};
			next unless ref $cfg eq 'HASH' && defined $cfg->{url} && $cfg->{url} ne '';
			$cape_servers{$name} = $cfg;
		}
	}
	my $cape_slug = ( defined $toml->{cape_slug} && $toml->{cape_slug} ne '' ) ? $toml->{cape_slug} : 'lilith';

	# cape_enable comes from TOML, whose parser yields the bare strings
	# 'true'/'false' -- both truthy in Perl -- so coerce it properly rather than
	# with a bare truth test (a plain ? : would leave 'false' enabled).
	my $cape_enabled = Lilith::CapeSubmit::to_bool( $toml->{cape_enable} );
	$self->helper( cape_servers        => sub { \%cape_servers } );
	$self->helper( cape_slug           => sub { $cape_slug } );
	$self->helper( cape_submit_enabled => sub { ( $cape_enabled && scalar keys %cape_servers ) ? 1 : 0 } );

	# CAPE detonation results. The same nergal box a sample is submitted to also
	# serves that task's detonation results (screenshots, lite.json, the report
	# html) under /results/<task_id>, gated on the nergal side by its own
	# results_auth/results_apikey. A cape event carries the instance it detonated
	# on and its task id, so results are fetched from the [cape_servers.NAME]
	# whose NAME matches the event's instance. results_url defaults to the
	# submission url and results_apikey to apikey, so a single-endpoint box needs
	# no extra config. Built independently of cape_enable: fetching results is
	# read-only (it never pushes a sample out), so it stays available even when
	# submission is turned off.
	#
	# An optional web_url points at that box's CAPEv2 web UI (distinct from the
	# nergal endpoint); when set, the event page links out to the full styled
	# report at <web_url>/analysis/<task_id>/. Without it, the page instead offers
	# the report html streamed back through nergal, which renders unstyled since
	# nergal serves only the fixed result files, not the report's static assets.
	my %cape_results;
	if ( ref $toml->{cape_servers} eq 'HASH' ) {
		foreach my $name ( keys %{ $toml->{cape_servers} } ) {
			my $cfg = $toml->{cape_servers}{$name};
			next unless ref $cfg eq 'HASH';
			my $results_url
				= ( defined $cfg->{results_url} && $cfg->{results_url} ne '' ) ? $cfg->{results_url} : $cfg->{url};
			next unless defined $results_url && $results_url ne '';
			$results_url =~ s{/+\z}{};                    # normalise; /results/<task_id> is appended to this
			my $results_apikey = defined $cfg->{results_apikey} ? $cfg->{results_apikey} : $cfg->{apikey};
			my $web_url        = ( defined $cfg->{web_url} && $cfg->{web_url} ne '' ) ? $cfg->{web_url} : undef;
			$web_url =~ s{/+\z}{} if defined $web_url;    # /analysis/<task_id>/ is appended to this
			$cape_results{$name} = {
				url => $results_url,
				apikey => ( defined $results_apikey ? $results_apikey : '' ),
				( defined $web_url ? ( web_url => $web_url ) : () ),
			};
		} ## end foreach my $name ( keys %{ $toml->{cape_servers...}})
	} ## end if ( ref $toml->{cape_servers} eq 'HASH' )
	$self->helper( cape_results         => sub { \%cape_results } );
	$self->helper( cape_results_enabled => sub { scalar keys %cape_results ? 1 : 0 } );
	$self->helper(
		cape_results_for => sub {
			my ( $c, $instance ) = @_;
			return ( defined $instance ) ? $cape_results{$instance} : undef;
		}
	);

	# A sample can exceed Mojolicious's default 16 MiB request cap, which would
	# drop the upload connection (a fetch NetworkError in the browser). Raise it
	# when submission is on; cape_max_upload_size (bytes) overrides the 1 GiB
	# default, matching the mojo_cape_submit receiver's generous limit.
	if ( $cape_enabled && keys %cape_servers ) {
		my $max_upload
			= ( defined $toml->{cape_max_upload_size} && $toml->{cape_max_upload_size} =~ /^[0-9]+$/ )
			? $toml->{cape_max_upload_size} + 0
			: 1073741824;
		$self->max_request_size($max_upload);
	}

	# A ready Lilith::CapeSubmit built from the config, or undef when the feature
	# is off. Cached; it holds only config data so it forks cleanly into the
	# submission subprocess.
	my $cape_submitter;
	$self->helper(
		cape_submitter => sub {
			return undef unless $_[0]->cape_submit_enabled;
			return $cape_submitter if $cape_submitter;
			require Lilith::CapeSubmit;
			$cape_submitter = Lilith::CapeSubmit->new(
				enabled => 1,
				slug    => $cape_slug,
				servers => \%cape_servers,
			);
			return $cape_submitter;
		}
	);

	# Point Mojolicious at share/templates and share/public so the app works
	# both when installed (File::ShareDir path) and when run from the repo.
	unshift @{ $self->renderer->paths }, "$SHARE_DIR/templates";
	unshift @{ $self->static->paths },   "$SHARE_DIR/public";

	my $r = $self->routes;
	$r->get('/')->to( cb => sub { $_[0]->redirect_to('/search') } );
	$r->get('/search')->to('search#index');
	$r->get('/dashboard')->to('dashboard#index');
	$r->get('/api/dashboard/stat')->to('dashboard#stat');
	$r->get('/api/dashboard/top')->to('dashboard#top');
	$r->get('/api/dashboard/timeseries')->to('dashboard#timeseries');
	$r->get('/api/dashboard/countries')->to('dashboard#countries');
	$r->get('/api/dashboard/columns')->to('dashboard#columns');
	$r->get('/api/dashboard/measures')->to('dashboard#measures');
	$r->get('/api/dashboard/layout')->to('dashboard#layout');
	$r->post('/api/dashboard/layout')->to('dashboard#layout_save');
	$r->get('/api/dashboard/boards')->to('dashboard#boards');
	$r->post('/api/dashboard/boards')->to('dashboard#board_create');
	$r->post('/api/dashboard/rename')->to('dashboard#board_rename');
	$r->post('/api/dashboard/delete')->to('dashboard#board_delete');
	$r->post('/api/dashboard/default')->to('dashboard#board_default');
	$r->get('/event/:table/:id')->to('event#view');
	$r->get('/event/:table/:id/body/:which/zip')->to('event#body_zip');
	$r->get('/event/:table/:id/pcap')->to('event#pcap');
	$r->get('/event/cape/:id/cape_results')->to('event#cape_results');
	$r->get('/event/cape/:id/cape_result/*subpath')->to('event#cape_result');
	$r->get('/logs')->to('logs#index');
	$r->get('/api/logs/stat')->to('logs#stat');
	$r->get('/api/logs/top')->to('logs#top');
	$r->get('/api/logs/timeseries')->to('logs#timeseries');
	$r->get('/api/logs/countries')->to('logs#countries');
	$r->get('/api/logs/columns')->to('logs#columns');
	$r->get('/api/logs/measures')->to('logs#measures');
	$r->get('/logs/:source/:id')->to('logs#view');
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
	$r->get('/cape_submit')->to('cape_submit#index');
	$r->post('/api/cape_submit/submit')->to('cape_submit#submit');
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
