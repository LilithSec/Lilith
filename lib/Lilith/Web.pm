package Lilith::Web;

use Mojo::Base 'Mojolicious';
use Mojo::File     qw(curfile);
use TOML::Tiny     qw(from_toml);
use File::Slurp    qw(read_file);
use File::Temp     ();
use Mojo::IOLoop   ();
use Mojo::JSON     ();
use Lilith         ();
use Lilith::Shodan ();
use Lilith::CVEDB  ();

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

# Mojolicious calls this once per worker at boot. It reads the TOML config and
# turns it into the app: the Lilith object every controller reaches through the
# 'lilith' helper, the optional features (Virani remotes, the Allani log store,
# GeoIP databases, CAPE servers) each built only when their config is present,
# the referer check when allowed_referers is set, and the routes.
#
# Everything expensive to build and safe to share -- database connection
# details, opened MMDB handles, the per-feature helper closures -- is built here
# rather than per request, so a request does no setup work. Anything a feature
# needs but has not got simply leaves that feature switched off, which is why so
# much of this is conditional rather than fatal.
#
# Args: none beyond the app object Mojolicious passes.
#
# Returns: nothing meaningful. Called for its effect on the app: helpers,
# hooks, and routes. Dies when the config file is missing, unreadable, or not
# parseable as TOML, since none of the above can be built without it.
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

	# The alert tables a page may offer, in display order, as
	# [ { key => 'suricata', label => 'Suricata' }, ... ]. Single-sourced here so
	# a new table means one edit rather than one per template: the navbar's Go to
	# Event picker, the search and dashboard table selects, and the auto
	# escalation rule scoping all render from this (see partials/_table_options).
	my @alert_tables = (
		{ key => 'suricata', label => 'Suricata' },
		{ key => 'sagan',    label => 'Sagan' },
		{ key => 'cape',     label => 'CAPE' },
		{ key => 'baphomet', label => 'Baphomet' },
	);
	$self->helper( alert_tables => sub { \@alert_tables } );

	# Whether a request-supplied table name is one of the alert tables above.
	# Derived from the same list so a new table needs no second edit; the
	# controllers all validate through this rather than each keeping its own
	# regex of the table names. Tolerant of undef, which is simply not valid.
	my %is_alert_table = map { $_->{key} => 1 } @alert_tables;
	$self->helper( valid_alert_table => sub { defined( $_[1] ) && $is_alert_table{ $_[1] } ? 1 : 0 } );

	# The columns each alert table may be ordered by, as a table => [columns]
	# hash ref, derived from %Lilith::alert_columns rather than hand-kept in the
	# search page's JavaScript -- so adding a column to a table offers it for
	# sorting without a second edit, and cannot drift from what Lilith::search
	# will actually accept.
	#
	# The table's own default sort column leads the list (the picker takes the
	# first entry as the default), followed by the row id, then the rest. raw is
	# left out: it is the whole EVE record as jsonb, which is not something to
	# sort by.
	my %order_by_columns;
	foreach my $alert_table ( keys %Lilith::alert_columns ) {
		my $default = $alert_table eq 'cape' ? 'stop' : 'timestamp';
		$order_by_columns{$alert_table}
			= [ $default, 'id', grep { $_ ne 'raw' && $_ ne $default } @{ $Lilith::alert_columns{$alert_table} } ];
	}
	$self->helper( order_by_columns => sub { \%order_by_columns } );

	# The alert classifications offered by the search page's classification
	# pickers, as an array ref sorted case insensitively for display. Taken from
	# %Lilith::class_map rather than listed again in the template, so the picker
	# cannot drift from the classifications the rest of Lilith knows about.
	#
	# The blank key is dropped: it exists in the map only to give records with no
	# classification a short label, and is not something to pick from a list.
	my @classifications = sort { lc($a) cmp lc($b) } grep { $_ ne '' } keys %Lilith::class_map;
	$self->helper( classifications => sub { \@classifications } );

	# The Subjects view of a Baphomet record: every subject var it carries, with
	# the value it was seen as and the score it stands at. Baphomet reports those
	# in three separate keys -- subject_vars is everything captured,
	# subject_vars_scores what each is holding, subjects_crossed only the vars
	# that reached a threshold -- and none on its own says what a reader wants to
	# know, so they are stitched back together here for the search results column
	# and the event page field alike.
	#
	# Args:
	#
	#   - $raw :: the record's decoded raw EVE record as a hash ref. Tolerant of
	#     undef or a non-hash, neither of which has anything to combine.
	#
	# Returns: a hash ref keyed by var name, each value a hash ref of:
	#
	#   - val :: the captured value, as subject_vars held it -- a plain string, or
	#     a { hostname => ..., ip => [ ... ] } hash ref where a usedns rule
	#     resolved it. Absent for a var that somehow only shows up scored.
	#   - score :: the var's score, always present. From subject_vars_scores,
	#     falling back to the crossing score, and 0 for a var holding neither --
	#     which is what a var with nothing held actually stands at. A var whose
	#     value resolved to several addresses scores each of them separately
	#     against the one threshold, so the highest of them is the var's score.
	#   - crossed :: 1 for a var that reached its threshold, absent otherwise. The
	#     score alone no longer says so, and on a multi var record which var
	#     tripped the rule is the whole point.
	#
	# The hash is empty for a record with no subject vars at all, which is the
	# caller's cue to render nothing rather than an empty object.
	#
	#     $c->baphomet_subjects( { subject_vars        => { SRC => '1.2.3.4', USER => 'root' },
	#                              subject_vars_scores => { SRC => 9.5, USER => 3 },
	#                              subjects_crossed    => { SRC => 9.5 } } );
	#     # { SRC  => { val => '1.2.3.4', score => 9.5, crossed => 1 },
	#     #   USER => { val => 'root',    score => 3 } }
	$self->helper(
		baphomet_subjects => sub {
			my ( $c, $raw ) = @_;

			return {} unless ref($raw) eq 'HASH';

			my $vars    = ref( $raw->{subject_vars} ) eq 'HASH'        ? $raw->{subject_vars}        : {};
			my $scores  = ref( $raw->{subject_vars_scores} ) eq 'HASH' ? $raw->{subject_vars_scores} : {};
			my $crossed = ref( $raw->{subjects_crossed} ) eq 'HASH'    ? $raw->{subjects_crossed}    : {};

			my %subjects;
			foreach my $var ( keys %{$vars}, keys %{$scores}, keys %{$crossed} ) {
				next if $subjects{$var};

				# a resolved var holds a value => score hash rather than the one
				# number, its addresses having raced the same threshold
				my $score = exists $scores->{$var} ? $scores->{$var} : $crossed->{$var};
				if ( ref($score) eq 'HASH' ) {
					($score) = sort { $b <=> $a } grep { defined($_) && !ref($_) } values %{$score};
				}

				$subjects{$var} = {
					( exists $vars->{$var}    ? ( val     => $vars->{$var} ) : () ),
					( exists $crossed->{$var} ? ( crossed => 1 )             : () ),
					score => ( defined($score) && !ref($score) ) ? $score : 0,
				};
			} ## end foreach my $var ( keys %{$vars}, keys %{$scores...})

			return \%subjects;
		}
	);

	# The one line render of the above, for the search results Subjects column:
	# var=value (score) per subject, sorted by var name. A nested table in that
	# cell reads as a box drawn around nothing and makes the row as tall as its
	# subject count, so the column stays one line and the event page card is where
	# the same map gets a table.
	#
	# Args:
	#
	#   - $raw :: the record's decoded raw EVE record as a hash ref, as
	#     baphomet_subjects takes it.
	#
	# Returns: the rendered line, or '' for a record with no subject vars -- which
	# the column renders as an empty cell rather than special casing.
	#
	# A var that crossed its threshold is marked with a leading ! -- every var
	# carries a score now, so nothing else on the line says which one tripped the
	# rule.
	#
	# A var a usedns rule resolved shows its hostname, falling back to the first
	# address it resolved to, since the whole { hostname, ip } structure does not
	# belong on one line. A var that appears with no value to show renders as its
	# name and score alone.
	#
	#     $c->baphomet_subjects_line( { subject_vars        => { SRC => '1.2.3.4', USER => 'root' },
	#                                   subject_vars_scores => { SRC => 9.5, USER => 3 },
	#                                   subjects_crossed    => { SRC => 9.5 } } );
	#     # '!SRC=1.2.3.4 (9.5), USER=root (3)'
	$self->helper(
		baphomet_subjects_line => sub {
			my ( $c, $raw ) = @_;

			my $subjects = $c->baphomet_subjects($raw);

			my @rendered;
			foreach my $var ( sort keys %{$subjects} ) {
				my $value = $subjects->{$var}{val};
				if ( ref($value) eq 'HASH' ) {
					$value
						= defined( $value->{hostname} )  ? $value->{hostname}
						: ref( $value->{ip} ) eq 'ARRAY' ? $value->{ip}[0]
						:                                  undef;
				} elsif ( ref($value) eq 'ARRAY' ) {
					$value = join( ', ', @{$value} );
				}

				my $subject = $subjects->{$var}{crossed} ? '!' . $var : $var;
				$subject .= '=' . $value if ( defined($value) && !ref($value) );
				push( @rendered, $subject . ' (' . $subjects->{$var}{score} . ')' );
			} ## end foreach my $var ( sort keys %{$subjects} )

			return join( ', ', @rendered );
		}
	);

	# The active filter chips shown above a page's results: one chip per filter
	# value the current request carries, each holding the URL that drops just
	# that value, plus the URL that drops the lot. Lets a page say what it is
	# filtering on without the reader having to open a collapsed panel and read
	# thirty inputs.
	#
	# The URLs are built from the request rather than by JavaScript, so a chip
	# is an ordinary link: it works with the back button, it opens in a new tab,
	# and it still works with JavaScript off.
	#
	# Args:
	#
	#   - $filter_fields :: Array ref of the filters the page offers, in the
	#     order their chips should appear. Each is a hash ref:
	#       - name :: the query parameter, e.g. 'src_ip'. Required.
	#       - label :: what to call it on the chip, e.g. 'Src IP'. Required.
	#       - values :: array ref of the values actually in force, for a filter
	#         the query string does not spell out -- a default the controller
	#         applies on its own. Optional; without it every_param is used.
	#     Other keys are ignored, so a page can pass the same list it builds its
	#     form from.
	#
	#   - $forced :: Hash ref of parameters to set on every URL built here, for
	#     a page whose controller would otherwise put its default straight back.
	#     Optional.
	#
	# Returns: a hash ref
	#
	#     {
	#       chips => [
	#         { label => 'Src IP', value => '1.2.3.4', url => <Mojo::URL> },
	#         ...
	#       ],
	#       clear_url => <Mojo::URL>,
	#     }
	#
	# One chip per value, so a filter holding three values gets three chips and
	# removing one leaves the other two. chips is empty when nothing is filtered,
	# which is the caller's cue to render no row at all. Every URL drops offset
	# and partial: the page someone was on will not line up with a differently
	# sized result set, and a chip must never link to a bare results fragment.
	#
	#     my $active = $c->filter_chips( [ { name => 'src_ip', label => 'Src IP' } ] );
	#     # on /search?table=sagan&src_ip=1.2.3.4&offset=100 that gives one chip
	#     # labelled 'Src IP' for '1.2.3.4', whose url is /search?table=sagan
	#
	# And with a controller-applied default to account for -- the search page
	# excludes one classification unless told a search was submitted, so it
	# names the values in force and forces search=1 onto the URLs, without
	# which dropping that chip would put the default straight back:
	#
	#     my $active = $c->filter_chips(
	#         [ { name => 'class_not', label => 'Not class', values => \@class_not } ],
	#         { search => 1 },
	#     );
	$self->helper(
		filter_chips => sub {
			my ( $c, $filter_fields, $forced ) = @_;

			my %base = ( %{ $forced // {} }, offset => undef, partial => undef );

			my @chips;
			foreach my $filter_field ( @{$filter_fields} ) {
				my $name = $filter_field->{name};
				my @values
					= $filter_field->{values}
					? @{ $filter_field->{values} }
					: @{ $c->every_param($name) };
				@values = grep { defined($_) && $_ ne '' } @values;

				foreach my $index ( 0 .. $#values ) {
					my @kept = @values;
					splice( @kept, $index, 1 );
					push(
						@chips,
						{
							label => $filter_field->{label},
							value => $values[$index],

							# an empty list clears the parameter outright
							url => $c->url_with->query( { %base, $name => \@kept } ),
						}
					);
				} ## end foreach my $index ( 0 .. $#values )
			} ## end foreach my $filter_field ( @{$filter_fields} )

			return {
				chips     => \@chips,
				clear_url => $c->url_with->query( { %base, map { $_->{name} => undef } @{$filter_fields} } ),
			};
		}
	);

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

	# Render an error message as { error => ... } JSON with the given status
	# (default 400), first stripping the trailing whitespace a die message
	# carries. The one place the error-response shape lives; every controller
	# error path renders through this rather than hand-rolling the trim.
	$self->helper(
		render_error => sub {
			my ( $controller, $error, $status ) = @_;

			( my $why = defined($error) ? $error : '' ) =~ s/\s+\z//;
			return $controller->render( json => { error => $why }, status => ( $status // 400 ) );
		}
	);

	# Render whatever $code->(@code_args) returns as JSON, turning a die (bad
	# column/source, unreachable database, ...) into a 400 with the message.
	# Shared by the dashboard and logs JSON APIs.
	$self->helper(
		render_json_or_400 => sub {
			my ( $controller, $code, @code_args ) = @_;

			my $data = eval { $code->(@code_args) };
			return $controller->render_error($@) if $@;
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

	# Shodan enrichment for the IP info modal, off unless enable_shodan is set --
	# it makes the server tell a third party which addresses are being looked at.
	#
	# The key is what picks the tier rather than a config of its own: with
	# shodan_api_key set the full host API is used (open ports with their
	# banners, TLS certificates, per-service CVEs), and without one the free
	# keyless InternetDB summary is (ports, CPEs, tags, CVE ids).
	# The answers are cached in the shodan_cache table (schema version 15) for
	# shodan_cache_ttl seconds, a month by default and 0 for no caching at all.
	# Unlike the domaininfo cache this is in the database rather than in the
	# worker, since the point is to spare the API a lookup every worker and every
	# restart would otherwise repeat. A month is long because what Shodan knows
	# about a host changes on the order of its own crawl interval, not of a shift.
	$self->helper( shodan_enable  => sub { $toml->{enable_shodan}          ? 1                       : 0 } );
	$self->helper( shodan_api_key => sub { defined $toml->{shodan_api_key} ? $toml->{shodan_api_key} : '' } );
	$self->helper(
		shodan_cache_ttl => sub {
			defined $toml->{shodan_cache_ttl} && $toml->{shodan_cache_ttl} =~ /^[0-9]+$/
				? $toml->{shodan_cache_ttl} + 0
				: 2592000;
		}
	);

	# Whether host lookups ask for every banner ever crawled rather than only
	# the current ones (see Lilith::Shodan::fetch). Normalized to 1/0 so the
	# helper hands out a plain number rather than the parser's boolean object.
	my $shodan_history = $toml->{shodan_history} ? 1 : 0;
	$self->helper( shodan_history => sub { $shodan_history } );

	# Which tier the configured key selects, and so which rows of the cache may
	# be read: the keyless summary and the keyed host API differ in depth, and a
	# row written by the lesser must not stand in for the greater. The rule lives
	# in Lilith::Shodan because the shodan_cache command has to apply the same one.
	$self->helper( shodan_source => sub { Lilith::Shodan::source( $_[0]->shodan_api_key ) } );

	# The Bootstrap class for one Shodan tag on a results table IP cell. Only the
	# tags that change what an alert means are colored; everything else Shodan
	# tags a host with is descriptive (cloud, cdn, starttls, ...) and stays grey.
	#
	# The IP info modal keeps its own copy of this map in lilith-lookup.js,
	# because it renders in the browser from JSON rather than here. The two are
	# meant to agree; change both.
	my %shodan_tag_class = (
		compromised  => 'bg-danger',
		malware      => 'bg-danger',
		c2           => 'bg-danger',
		doublepulsar => 'bg-danger',
		(
			map { $_ => 'bg-warning text-dark' }
				qw( honeypot scanner tor vpn proxy ics self-signed eol-os eol-product database )
		),
	);
	$self->helper(
		shodan_tag_class => sub {
			my ( $c, $tag ) = @_;
			return ( defined $tag && $shodan_tag_class{$tag} ) ? $shodan_tag_class{$tag} : 'bg-secondary';
		}
	);

	# What the cache holds for the addresses in a page of results, as
	# { ip => { ports => [...], tags => [...], vulns => 12, max_cvss => 9.8 } },
	# for the badges on the results tables' IP cells.
	#
	# Reads the cache and nothing else. A results page can carry a hundred
	# addresses, and looking any of them up live would mean a hundred Shodan
	# calls behind a page load -- so an address with no cached entry simply gets
	# no badges, and gets them once someone opens its IP info modal. That is also
	# why this is one query for the whole page rather than one per cell.
	#
	# Args:
	#
	#   - $rows :: the result rows, as the search controller has them. Their
	#     src_ip and dest_ip are read; anything else is ignored.
	#
	# Returns: a hash ref keyed by address, holding only the addresses that had
	# a fresh entry. Empty when the feature or the cache is off, when there is
	# nothing to look up, or when the cache cannot be read -- which is logged and
	# otherwise costs only the badges.
	#
	#     my $badges = $c->shodan_badges( $results );
	#     # $badges->{'192.0.2.10'}{vulns} is 12
	$self->helper(
		shodan_badges => sub {
			my ( $c, $rows ) = @_;

			return {} unless $c->shodan_enable;
			my $ttl = $c->shodan_cache_ttl;
			return {} unless $ttl > 0;
			return {} unless ref $rows eq 'ARRAY' && @{$rows};

			# Deduped, and filtered to what may be handed to Postgres as an inet
			# -- one unparseable value would otherwise fail the whole statement
			# and cost every cell on the page its badges.
			my %seen;
			my @ips = grep { !$seen{$_}++ }
				grep { defined($_) && /^[0-9a-fA-F:.]+$/ }
				map { ( $_->{src_ip}, $_->{dest_ip} ) } @{$rows};
			return {} unless @ips;

			my $badges
				= eval { $c->lilith->shodan_cache_badges( ips => \@ips, source => $c->shodan_source, ttl => $ttl ) };
			if ($@) {
				( my $why = $@ ) =~ s/\s+\z//;
				$c->app->log->warn( 'shodan badge lookup failed: ' . $why );
				return {};
			}

			return $badges;
		}
	);

	# The rows on a page whose rule names a CVE an end's cached Shodan entry
	# lists it as vulnerable to -- an exploit thrown at a host Shodan says is
	# actually vulnerable to it, the strongest triage signal this data can
	# give, and worth more than either half shown side by side. Both ends are
	# compared: src and dest are the triggering packet's direction, not
	# attacker and victim, so which end the vulnerable host lands on is up to
	# the rule that fired.
	#
	# The comparison is done here at render time and costs no query of its own:
	# the cache side rides the vuln_ids the shodan_badges helper already fetched
	# for the page, and the rule side comes out of each row's raw -- decoded
	# only for rows where some end has cached CVEs at all, which on most pages
	# is few of them.
	#
	# Args:
	#
	#   - $table :: the table the rows are from. Only suricata rules carry CVE
	#     metadata, so anything else returns empty.
	#
	#   - $rows :: the result rows, as the search controller has them. Each
	#     row's id, src_ip, dest_ip, and raw are read. raw may be the JSON
	#     string the row was fetched with or already decoded -- the event view
	#     holds it decoded.
	#
	#   - $badges :: what the shodan_badges helper returned for these rows.
	#
	# Returns: a hash ref keyed by row id, each value a hash of the ends that
	# matched, each holding its matched ids sorted. Only rows with a match are
	# present, and only the ends that matched, so existence is the badge test
	# at both levels. Empty whenever there is nothing to compare.
	#
	#     my $matches = $c->cve_matches( 'suricata', $results, $badges );
	#     # $matches->{5012}{dest} is [ 'CVE-2021-44228' ]
	$self->helper(
		cve_matches => sub {
			my ( $c, $table, $rows, $badges ) = @_;

			return {} unless defined $table        && $table eq 'suricata';
			return {} unless ref $rows eq 'ARRAY'  && @{$rows};
			return {} unless ref $badges eq 'HASH' && keys %{$badges};

			my %matches;
			my %vuln_set;    # ip => { cve => 1 }; the badge entries are per
							 # address and shared across rows, so each set is
							 # built once however many rows name the address
			foreach my $row ( @{$rows} ) {
				next unless ref $row eq 'HASH' && defined $row->{id};

				# which ends have cached CVEs at all; raw is only worth
				# decoding when one does
				my %end_ip;
				for my $end (qw(src dest)) {
					my $ip    = $row->{ $end . '_ip' };
					my $entry = defined $ip ? $badges->{$ip} : undef;
					next
						unless ref $entry eq 'HASH' && ref $entry->{vuln_ids} eq 'ARRAY' && @{ $entry->{vuln_ids} };
					$end_ip{$end} = $ip;
					$vuln_set{$ip} ||= { map { $_ => 1 } @{ $entry->{vuln_ids} } };
				}
				next unless %end_ip;

				my $raw = $row->{raw};
				if ( defined $raw && !ref $raw ) {
					$raw = eval { Mojo::JSON::from_json($raw) };
				}
				my $rule_cves = Lilith::CVEDB::rule_cves($raw);
				next unless @{$rule_cves};

				for my $end ( keys %end_ip ) {
					my $vulnerable = $vuln_set{ $end_ip{$end} };
					my @matched    = grep { $vulnerable->{$_} } @{$rule_cves};
					$matches{ $row->{id} }{$end} = \@matched if @matched;
				}
			} ## end foreach my $row ( @{$rows} )

			return \%matches;
		}
	);

	# The deployment's own networks, for the dashboard's src/dest_locality
	# dimensions: an address inside any of these counts as Internal. Optional;
	# with none configured Lilith::Stats falls back to the unroutable ranges,
	# so the dimension is useful before it is tuned. An entry outside the
	# address/CIDR character set is dropped with a warning rather than taking
	# every dashboard query down with it.
	my @local_networks;
	if ( ref $toml->{local_networks} eq 'ARRAY' ) {
		for my $network ( @{ $toml->{local_networks} } ) {
			if ( defined $network && !ref $network && $network =~ m{\A[0-9a-fA-F:.]+(?:/[0-9]{1,3})?\z} ) {
				push( @local_networks, $network );
			} else {
				$self->log->warn( 'local_networks entry "'
						. ( defined $network && !ref $network ? $network : '' )
						. '" is not an address or CIDR; ignored' );
			}
		}
	} ## end if ( ref $toml->{local_networks} eq 'ARRAY')
	$self->helper( local_networks => sub { \@local_networks } );

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

	# The rows of a countries panel, aggregated from a top-source-IPs result:
	# each address resolved through ip_country, unknowns pooled under '??',
	# sorted busiest first with ties alphabetical, capped at 15. Shared by the
	# dashboard and logs panels so the two cannot disagree on the shape.
	#
	# Args:
	#
	#   - $ips :: the top() result to aggregate -- an array ref of
	#     { value => <address>, count => ... } rows.
	#
	# Returns: the response body for a countries endpoint whose GeoIP is
	# configured: { enabled => 1, rows => [ { country, count }, ... ] }. The
	# enabled => 0 case never gets here, having no addresses to aggregate.
	#
	#     $c->countries_from_top( $ips );
	#     # { enabled => 1, rows => [ { country => 'US', count => 40 }, ... ] }
	$self->helper(
		countries_from_top => sub {
			my ( $c, $ips ) = @_;

			my %by_country;
			for my $row ( @{$ips} ) {
				my $cc = $c->ip_country( $row->{value} );
				$cc = '??' unless defined $cc && $cc ne '';
				$by_country{$cc} += $row->{count};
			}

			my @rows = map { { country => $_, count => $by_country{$_} } }
				sort { $by_country{$b} <=> $by_country{$a} || $a cmp $b } keys %by_country;
			@rows = @rows[ 0 .. 14 ] if @rows > 15;

			return { enabled => 1, rows => \@rows };
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
	my %cape_servers;
	if ( ref $toml->{cape_servers} eq 'HASH' ) {
		foreach my $name ( keys %{ $toml->{cape_servers} } ) {
			my $cfg = $toml->{cape_servers}{$name};
			next unless ref $cfg eq 'HASH' && defined $cfg->{url} && $cfg->{url} ne '';
			$cape_servers{$name} = $cfg;
		}
	}
	my $cape_slug = ( defined $toml->{cape_slug} && $toml->{cape_slug} ne '' ) ? $toml->{cape_slug} : 'lilith';

	# normalized to 1/0 so the helpers hand out a plain number rather than the
	# parser's boolean object
	my $cape_enabled = $toml->{cape_enable} ? 1 : 0;
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
	$r->get('/api/search/values')->to('search#filter_values');
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
