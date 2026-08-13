package Lilith;

use 5.006;
use strict;
use warnings;
use POE                  qw(Wheel::FollowTail);
use JSON                 qw( decode_json encode_json );
use Sys::Hostname        qw( hostname );
use DBI                  ();
use Digest::SHA          qw(sha256_base64);
use Socket               qw( AF_INET AF_INET6 inet_pton );
use Sys::Syslog          qw( closelog openlog syslog );
use POSIX                qw( strftime );
use Time::Piece::Guess   ();
use Lilith::Schema       ();
use Lilith::Escalate     ();
use Lilith::AutoEscalate ();
use Lilith::DBUtil       qw( column_exists local_networks_frag );

=head1 NAME

Lilith - Work with Suricata/Sagan EVE logs and PostgreSQL.

=head1 VERSION

Version 3.0.0

=cut

our $VERSION = '3.0.0';

# Column order for each alert table, the single source of truth shared by
# parse_eve() (which returns a hash keyed by these names) and run() (which
# builds the INSERT and its bind list from them), so the two cannot drift.
our %alert_columns = (
	suricata => [
		qw(
			instance host timestamp flow_id event_id in_iface
			src_ip src_port dest_ip dest_port proto app_proto
			flow_pkts_toserver flow_bytes_toserver
			flow_pkts_toclient flow_bytes_toclient flow_start
			classification signature gid sid rev raw
		)
	],
	sagan => [
		qw(
			instance instance_host timestamp event_id flow_id in_iface
			src_ip src_port dest_ip dest_port proto facility host
			level priority program xff stream
			classification signature gid sid rev raw
		)
	],
	cape => [
		qw(
			instance target instance_host task start stop malscore
			subbed_from_ip subbed_from_host pkg md5 sha1 sha256 slug
			url url_hostname proto src_ip src_port dest_ip dest_port size raw
		)
	],
	baphomet => [
		qw(
			instance host timestamp event_id event_type kur path score
			signature severity classification gid sid rev
			src_ip src_port dest_ip dest_port username
			ban_time recidive country raw
		)
	],
);

# The alert classifications Suricata and Sagan emit, mapped to the short labels
# used where a full classification will not fit -- extend output, SNMP, and the
# like. Also the single source of truth for the classifications the web UI
# offers in its search filters (see the classifications helper in Lilith::Web),
# so a new classification means one edit here rather than one per consumer.
#
# The empty-string key is deliberate: a record whose classification is missing
# or empty still needs a label, and gets 'blankC'. Anything offering these for a
# human to pick from should skip it.
our %class_map = (
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
	'Unsuccessful Admin Privilege'                                => '!SucAdmPG',
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
	# Baphomet's category wordings not already covered above: its own log-side
	# classtypes, plus case variants where its classtype table capitalizes
	# differently than the Sagan/Suricata wording already listed
	'Access to a potentially vulnerable web application' => 'PotVulWebApp',
	'Traffic the Sensor Blocked'                         => 'Blocked',
	'Brute Force Attack'                                 => 'BruteForce',
	'Correlated Attack'                                  => 'CorrAtk',
	'Malware Activity Detected'                          => 'MalAct',
	'Network Event'                                      => 'NetEvent',
	'System Error'                                       => 'SysErr',
	'System Event'                                       => 'SysEvent',
	'Unsuccessful Administrator Privilege Gain'          => '!SucAdmPG',
	''                                                   => 'blankC',
);

# The event types Baphomet emits in its EVE (eve_type "baphomet"); a record with
# any other event_type is not ingested. baphomet_event_ignore (per instance)
# narrows this further.
my %BAPHOMET_EVENT_TYPES = map { $_ => 1 } qw( found banish noted alert sighting sighted );

# The known alert table types; anything naming a table must be one of these.
my %KNOWN_TABLE_TYPES = map { $_ => 1 } qw( suricata sagan cape baphomet );

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

    $lilith->run(
                files=>\%files,
               );

=head1 FUNCTIONS

=head2 new

Initiates it.

    my $lilith=Lilith->new(
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
	my ( $class, %opts ) = @_;

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user} = 'lilith';
	}

	foreach my $ignore_option (
		qw(sid_ignore class_ignore suricata_sid_ignore suricata_class_ignore sagan_sid_ignore sagan_class_ignore))
	{
		if ( !defined( $opts{$ignore_option} ) ) {
			$opts{$ignore_option} = [];
		}
	}

	foreach my $array_option (qw(baphomet_event_ignore escalation_type_namespaces)) {
		if ( ref( $opts{$array_option} ) ne 'ARRAY' ) {
			$opts{$array_option} = [];
		}
	}

	my $self = {
		escalation_type_namespaces => $opts{escalation_type_namespaces},
		sid_ignore                 => $opts{sid_ignore},
		suricata_sid_ignore        => $opts{suricata_sid_ignore},
		sagan_sid_ignore           => $opts{sagan_sid_ignore},
		class_ignore               => $opts{class_ignore},
		suricata_class_ignore      => $opts{suricata_class_ignore},
		sagan_class_ignore         => $opts{sagan_class_ignore},
		baphomet_event_ignore      => $opts{baphomet_event_ignore},
		dsn                        => $opts{dsn},
		user                       => $opts{user},
		pass                       => $opts{pass},
		debug                      => $opts{debug},
		# a copy so an instance cannot mutate the package default out from under
		# the other consumers of %Lilith::class_map
		class_map      => {%class_map},
		lc_class_map   => {},
		snmp_class_map => {},
	};
	bless $self, $class;

	my @keys = keys( %{ $self->{class_map} } );
	foreach my $key (@keys) {
		my $lc_key = lc($key);
		$self->{lc_class_map}{$lc_key}   = $self->{class_map}{$key};
		$self->{snmp_class_map}{$lc_key} = $self->{class_map}{$key};
		$self->{snmp_class_map}{$lc_key} =~ s/^\!/not\_/;
		$self->{snmp_class_map}{$lc_key} =~ s/\ /\_/g;
	}

	# O(1) lookup of the baphomet event types to skip on ingest
	$self->{baphomet_event_ignore_map} = { map { $_ => 1 } @{ $self->{baphomet_event_ignore} } };

	return $self;
} ## end sub new

=head2 parse_eve

Parse a decoded EVE record into a row hash for its alert table. Returns a hash
ref keyed by column name (the same keys as C<@{ $Lilith::alert_columns{$type} }>),
or undef if the record is not an C<alert> event and so should be skipped.

    my $row = $lilith->parse_eve(
        type     => 'suricata',
        json     => $decoded,
        instance => 'foo-pie',
        host     => 'sensor1',
        raw      => $raw_line,
    );

Arguments.

    - type :: 'suricata', 'sagan', 'cape', or 'baphomet'. Required.

    - json :: The decoded EVE record, a hash ref. Required.

    - instance :: Instance name recorded on the row. For baphomet it falls back
      to the record's C<kur> when not given.

    - host :: Host the instance runs on. Stored as C<host> for Suricata and as
      C<instance_host> for Sagan and CAPE. For baphomet the C<host> column is
      the record's own C<hostname>, falling back to this argument.

    - raw :: The raw EVE line, stored verbatim in the C<raw> column.

For Suricata and Sagan an C<event_id> is derived as the SHA256 (base64) of
instance + host + timestamp + flow_id + in_iface. L<App::Lilu> uses the same
recipe, so a sensor running Lilu and Lilith itself compute the same handle for
a given event. Baphomet has no flow identity, so its C<event_id> uses a
different recipe; see L</_parse_baphomet>.

=cut

sub parse_eve {
	my ( $self, %opts ) = @_;

	my $json = $opts{json};

	# every parser needs a decoded record to work from
	if ( !defined($json) || ref($json) ne 'HASH' ) {
		return undef;
	}

	my $type     = $opts{type};
	my $instance = $opts{instance};
	my $host     = $opts{host};

	# Baphomet has its own event_type vocabulary (found/banish/noted/alert/
	# sighting/sighted) and row shape, so it is dispatched on the configured type
	# before the suricata/sagan/cape 'alert'-only guard below -- which would
	# otherwise drop every Baphomet record.
	if ( defined($type) && $type eq 'baphomet' ) {
		return $self->_parse_baphomet( $json, \%opts );
	}

	# for the suricata/sagan/cape sources only alert events are stored;
	# anything else is skipped
	if ( !defined( $json->{event_type} ) || $json->{event_type} ne 'alert' ) {
		return undef;
	}

	# stable per-event handle; undef parts stringify to '' just as before
	my $event_id
		= sha256_base64( ( defined($instance) ? $instance : '' )
			. ( defined($host)                ? $host              : '' )
			. ( defined( $json->{timestamp} ) ? $json->{timestamp} : '' )
			. ( defined( $json->{flow_id} )   ? $json->{flow_id}   : '' )
			. ( defined( $json->{in_iface} )  ? $json->{in_iface}  : '' ) );

	if ( defined($type) && $type eq 'suricata' ) {
		return {
			instance            => $instance,
			host                => $host,
			timestamp           => $json->{timestamp},
			flow_id             => $json->{flow_id},
			event_id            => $event_id,
			in_iface            => $json->{in_iface},
			src_ip              => $json->{src_ip},
			src_port            => $json->{src_port},
			dest_ip             => $json->{dest_ip},
			dest_port           => $json->{dest_port},
			proto               => $json->{proto},
			app_proto           => $json->{app_proto},
			flow_pkts_toserver  => $json->{flow}{pkts_toserver},
			flow_bytes_toserver => $json->{flow}{bytes_toserver},
			flow_pkts_toclient  => $json->{flow}{pkts_toclient},
			flow_bytes_toclient => $json->{flow}{bytes_toclient},
			flow_start          => $json->{flow}{start},
			classification      => $json->{alert}{category},
			signature           => $json->{alert}{signature},
			gid                 => $json->{alert}{gid},
			sid                 => $json->{alert}{signature_id},
			rev                 => $json->{alert}{rev},
			raw                 => $opts{raw},
		};
	} elsif ( defined($type) && $type eq 'sagan' ) {
		return {
			instance       => $instance,
			instance_host  => $host,
			timestamp      => $json->{timestamp},
			event_id       => $event_id,
			flow_id        => $json->{flow_id},
			in_iface       => $json->{in_iface},
			src_ip         => $json->{src_ip},
			src_port       => $json->{src_port},
			dest_ip        => $json->{dest_ip},
			dest_port      => $json->{dest_port},
			proto          => $json->{proto},
			facility       => $json->{facility},
			host           => $json->{host},
			level          => $json->{level},
			priority       => $json->{priority},
			program        => $json->{program},
			xff            => $json->{xff},
			stream         => $json->{stream},
			classification => $json->{alert}{category},
			signature      => $json->{alert}{signature},
			gid            => $json->{alert}{gid},
			sid            => $json->{alert}{signature_id},
			rev            => $json->{alert}{rev},
			raw            => $opts{raw},
		};
	} elsif ( defined($type) && $type eq 'cape' ) {
		return $self->_parse_cape( $json, $instance, $host, $opts{raw} );
	}

	return undef;
} ## end sub parse_eve

# Pull a CAPEv2 detonation record apart into its cape_alerts row. Kept out of
# parse_eve only because the field-by-field fallbacks (cape_submit vs the
# sample-origin block vs row) are long. Faithful to the original run() body.
#
# A sample reaches CAPE either as a Suricata extract (suricata_extract_submit)
# or as a Lilith upload (lilith_cape_submit); the two are peers, only one is
# present, and cape_submit is always added on top by mojo_cape_submit. Both
# origin blocks are read the same way, so lilith_cape_submit is folded into the
# same fallbacks suricata_extract_submit already had.
#
# Args:
#
#   - $json :: the decoded CAPE record as a hash ref. Read for the origin
#     blocks (cape_submit, suricata_extract_submit, lilith_cape_submit), the
#     'row' block CAPE itself writes (id, started_on, completed_on, package,
#     target), fileinfo, http, malscore, and the flow tuple.
#   - $instance :: the instance name to record on the row, as configured for
#     this [eves.*].
#   - $host :: the host the instance runs on, stored as instance_host.
#   - $raw :: the original undecoded EVE line, stored verbatim in the raw jsonb
#     column.
#
# Returns: a hash ref keyed by cape_alerts column name, ready for
# insert_alert. Any field the record did not carry is undef, which the insert
# binds as SQL NULL. Never returns undef -- a record reaching here is already
# known to be a cape one.
#
#     my $row = $self->_parse_cape( $json, 'cape', 'sensor1', $line );
#     my $id  = $self->insert_alert( type => 'cape', row => $row );
sub _parse_cape {
	my ( $self, $json, $instance, $host, $raw ) = @_;

	my $ces = ref( $json->{cape_submit} ) eq 'HASH'             ? $json->{cape_submit}             : {};
	my $ses = ref( $json->{suricata_extract_submit} ) eq 'HASH' ? $json->{suricata_extract_submit} : {};
	my $lcs = ref( $json->{lilith_cape_submit} ) eq 'HASH'      ? $json->{lilith_cape_submit}      : {};

	# the submitted sample's name: most specific source first, then basename. A
	# Lilith upload carries the upload name as lilith_cape_submit.filename.
	my $target;
	if ( defined( $ces->{name} ) ) {
		$target = $ces->{name};
	} elsif ( defined( $ses->{name} ) ) {
		$target = $ses->{name};
	} elsif ( defined( $lcs->{filename} ) ) {
		$target = $lcs->{filename};
	} else {
		$target = $json->{row}{target};
	}
	if ( defined($target) ) {
		$target =~ s/^.*\///;
	}

	# hashes: cape_submit first, else whichever origin block is present
	my $md5    = $ces->{md5}    // $ses->{md5}    // $lcs->{md5};
	my $sha1   = $ces->{sha1}   // $ses->{sha1}   // $lcs->{sha1};
	my $sha256 = $ces->{sha256} // $ses->{sha256} // $lcs->{sha256};

	# slug preference is the other way round: the origin block first, as
	# cape_submit does not carry one
	my $slug = $ses->{slug} // $lcs->{slug} // $ces->{slug};

	my $size;
	if ( defined( $ces->{size} ) ) {
		$size = $ces->{size};
	} elsif ( defined( $json->{fileinfo} ) && defined( $json->{fileinfo}{size} ) ) {
		$size = $json->{fileinfo}{size};
	}

	return {
		instance         => $instance,
		target           => $target,
		instance_host    => $host,
		task             => $json->{row}{id},
		start            => $json->{row}{started_on},
		stop             => $json->{row}{completed_on},
		malscore         => $json->{malscore},
		subbed_from_ip   => $ces->{remote_ip},
		subbed_from_host => $ses->{host} // $lcs->{host},
		pkg              => $json->{row}{package},
		md5              => $md5,
		sha1             => $sha1,
		sha256           => $sha256,
		slug             => $slug,
		url              => ( defined( $json->{http} ) ? $json->{http}{url}      : undef ),
		url_hostname     => ( defined( $json->{http} ) ? $json->{http}{hostname} : undef ),
		proto            => $json->{proto},
		src_ip           => $json->{src_ip},
		src_port         => $json->{src_port},
		dest_ip          => $json->{dest_ip},
		dest_port        => $json->{dest_port},
		size             => $size,
		raw              => $raw,
	};
} ## end sub _parse_cape

# Pull a Baphomet judgment record (top-level eve_type "baphomet") apart into a
# baphomet_alerts row. Kept out of parse_eve for the same reason as _parse_cape:
# the shape has nothing in common with an IDS alert.
#
# The flow columns come from Baphomet's promoted vars -- src_ip, src_port,
# dest_ip, dest_port, and user (stored as username; "user" is reserved in
# Postgres and column names are interpolated unquoted into SQL elsewhere).
# src_ip falls back to the first entry of banishing, so a banish whose rule
# promoted no src_ip -- a subnet ban's CIDR, a resolved name's first address --
# still lands in the top talker / escalation / %INET machinery. As with the
# suricata/sagan/cape sources, only the scalar fields worth filtering, sorting,
# or grouping by are promoted to columns. The nested detail (subject_vars,
# subjects_crossed, banishing, attack, rule, found, marks_set, tracked, ...)
# stays in raw and is reached with raw->'...'.
#
# The promoted vars are lifted from rule-named capture vars, so a misauthored
# rule can put a non-IP or non-numeric value in them; those are stored as NULL
# rather than letting the inet/integer bind fail and lose the whole row.
#
# Baphomet has no flow identity, so event_id is derived rather than read: the
# base64 SHA256 of hostname + kur + timestamp + event_type + rule name +
# offender, where offender is the src_ip (after the banishing fallback), or a
# stable render of subject_vars when there is no ip -- so a subject-only
# verdict (a sighted on a username, say) still gets a distinct handle. The
# rule name comes out of the record even though rule itself is not a column.
#
# Args:
#
#   - $json :: the decoded EVE record as a hash ref, whose eve_type the caller
#     has already established is "baphomet". The keys read are event_type,
#     kur, hostname, timestamp, msg, category, severity, score, gid, sid, rev,
#     path, src_ip, src_port, dest_ip, dest_port, user, banishing,
#     subject_vars, ban_time, recidive, country, and the rule block.
#   - $opts :: a hash ref of what the record cannot supply on its own:
#       - instance :: the instance name to record, as configured for this
#         [eves.*]. Falls back to the record's kur when undef.
#       - host :: the host the instance runs on, used only when the record
#         carries no hostname of its own.
#       - raw :: the original undecoded EVE line, stored verbatim in the raw
#         jsonb column.
#
# Returns: a hash ref keyed by baphomet_alerts column name, ready for
# insert_alert. A field the record did not carry is undef, which the insert
# binds as SQL NULL.
#
# Returns undef instead, meaning "do not store this", for an event_type outside
# the six Baphomet emits (found, banish, noted, alert, sighting, sighted) or one
# this instance lists in baphomet_event_ignore.
#
#     my $row = $self->_parse_baphomet( $json,
#         { instance => 'baphomet', host => 'gate1', raw => $line } );
#     my $id = $self->insert_alert( type => 'baphomet', row => $row );
#
#     # an event type Baphomet does not emit is skipped rather than stored
#     $self->_parse_baphomet( { event_type => 'muttering' }, {} );
#     # undef
sub _parse_baphomet {
	my ( $self, $json, $opts ) = @_;

	my $event_type = $json->{event_type};
	return undef unless defined($event_type) && $BAPHOMET_EVENT_TYPES{$event_type};
	return undef if $self->{baphomet_event_ignore_map}{$event_type};

	# instance is the configured name, falling back to the record's kur; host is
	# the record's own hostname, falling back to the sensor host the caller passed
	my $instance = defined( $opts->{instance} ) ? $opts->{instance} : $json->{kur};
	my $host     = defined( $json->{hostname} ) ? $json->{hostname} : $opts->{host};

	# the flow source, falling back to what was banished when it is missing or
	# not an address (a usedns rule's src_ip var can carry a hostname);
	# banishing may carry a CIDR (subnet ban), which the inet column holds fine
	my $src_ip = _baphomet_inet( $json->{src_ip} ) ? $json->{src_ip} : undef;
	if ( !defined($src_ip) && ref( $json->{banishing} ) eq 'ARRAY' && _baphomet_inet( $json->{banishing}[0] ) ) {
		$src_ip = $json->{banishing}[0];
	}
	my $dest_ip = _baphomet_inet( $json->{dest_ip} ) ? $json->{dest_ip} : undef;

	# offender is the ip when present, else the subjects render; it keeps the
	# derived event_id stable and distinct for a subject-only verdict
	my $rule_name = ref( $json->{rule} ) eq 'HASH' ? $json->{rule}{name} : undef;
	my $offender  = defined($src_ip)               ? $src_ip             : _baphomet_subjects( $json->{subject_vars} );

	my $event_id
		= sha256_base64( ( defined($host) ? $host : '' )
			. ( defined( $json->{kur} )       ? $json->{kur}       : '' )
			. ( defined( $json->{timestamp} ) ? $json->{timestamp} : '' )
			. ( defined($event_type)          ? $event_type        : '' )
			. ( defined($rule_name)           ? $rule_name         : '' )
			. ( defined($offender)            ? $offender          : '' ) );

	return {
		instance       => $instance,
		host           => $host,
		timestamp      => $json->{timestamp},
		event_id       => $event_id,
		event_type     => $event_type,
		kur            => $json->{kur},
		path           => $json->{path},
		score          => $json->{score},
		signature      => $json->{msg},
		severity       => $json->{severity},
		classification => $json->{category},
		gid            => _baphomet_number( $json->{gid} ),
		sid            => _baphomet_number( $json->{sid} ),
		rev            => _baphomet_number( $json->{rev} ),
		src_ip         => $src_ip,
		src_port       => _baphomet_number( $json->{src_port} ),
		dest_ip        => $dest_ip,
		dest_port      => _baphomet_number( $json->{dest_port} ),
		username       => $json->{user},
		ban_time       => $json->{ban_time},
		recidive       => _baphomet_bool( $json->{recidive} ),
		country        => $json->{country},
		raw            => $opts->{raw},
	};
} ## end sub _parse_baphomet

# Check that a value is storable in a Postgres inet column: an IPv4 or IPv6
# address, optionally with a /prefix (a subnet ban's CIDR). Baphomet's promoted
# src_ip/dest_ip are lifted from rule-named capture vars, so a misauthored rule
# can put anything there; a value failing this is stored as NULL rather than
# letting the insert die and lose the row. Plain function, not a method.
#
# Args:
#
#   - $value :: the candidate value; undef, a ref, or a non-address string all
#     fail.
#
# Returns: 1 when the value parses as an address or CIDR, 0 otherwise.
#
#     $src_ip = undef unless _baphomet_inet($src_ip);
#
#     _baphomet_inet('203.0.113.66');    # 1
#     _baphomet_inet('65.49.1.0/24');    # 1
#     _baphomet_inet('bad.example.com'); # 0
sub _baphomet_inet {
	my ($value) = @_;

	return 0 if !defined($value) || ref($value);

	my ( $address, $prefix ) = split( m{/}, $value, 2 );
	return 0 unless defined($address) && $address ne '';

	my $family = $address =~ /:/ ? AF_INET6 : AF_INET;
	if ( defined($prefix) ) {
		return 0 unless $prefix =~ /^[0-9]{1,3}$/ && $prefix <= ( $family == AF_INET6 ? 128 : 32 );
	}

	return defined( inet_pton( $family, $address ) ) ? 1 : 0;
} ## end sub _baphomet_inet

# Coerce a Baphomet numeric field (the promoted src_port/dest_port and the
# gid/sid/rev trio) for an integer column. Baphomet emits these as integers or
# null, but the ports are lifted from rule-named capture vars and ride through
# unchanged when non-numeric, so anything else becomes NULL rather than a
# failed bind. Plain function, not a method.
#
# Args:
#
#   - $value :: the decoded JSON value; expected a non-negative integer, but
#     tolerant of undef or any string.
#
# Returns: the value as a number when it is all digits, undef otherwise.
#
#     src_port => _baphomet_number( $json->{src_port} ),
sub _baphomet_number {
	my ($value) = @_;

	return undef if !defined($value) || ref($value) || $value !~ /^[0-9]+$/;
	return $value + 0;
}

# Render a record's subject_vars compactly and stably for the event_id hash:
# each var as var=value sorted by var name, joined with commas, a
# usedns-resolved value ({hostname, ip[]}) contributing its hostname. Only for
# the hash input -- never stored or displayed. Plain function, not a method.
#
# Args:
#
#   - $subject_vars :: the record's subject_vars hash ref (var name => captured
#     value, or => { hostname => ..., ip => [...] } where usedns resolved).
#     Tolerant of undef or a non-hash.
#
# Returns: the rendered string, '' when there is nothing to render.
#
#     _baphomet_subjects( { SRC => '1.2.3.4', USER => 'admin' } );
#     # 'SRC=1.2.3.4,USER=admin'
#
#     _baphomet_subjects( { SRC => { hostname => 'bad.example.com',
#                                    ip => ['192.0.2.72'] } } );
#     # 'SRC=bad.example.com'
sub _baphomet_subjects {
	my ($subject_vars) = @_;

	return '' unless ref($subject_vars) eq 'HASH';

	my @rendered;
	foreach my $var ( sort keys %{$subject_vars} ) {
		my $value = $subject_vars->{$var};
		if ( ref($value) eq 'HASH' ) {
			$value = $value->{hostname};
		}
		push( @rendered, $var . '=' . ( defined($value) && !ref($value) ? $value : '' ) );
	}

	return join( ',', @rendered );
} ## end sub _baphomet_subjects

# Coerce a Baphomet JSON boolean (a JSON::PP::Boolean, which stringifies to ''
# for false and would not bind as a Postgres boolean) to 1/0, leaving undef as
# SQL NULL. Plain function, not a method.
#
# Args:
#
#   - $value :: the decoded JSON value, normally a JSON::PP::Boolean object but
#     tolerant of a plain 0/1 or undef.
#
# Returns: 1 for true, 0 for false, undef when the field was absent -- so a
# record that never mentioned the flag stores NULL rather than false.
#
#     recidive => _baphomet_bool( $json->{recidive} ),
sub _baphomet_bool {
	my ($value) = @_;
	return undef unless defined $value;
	return $value ? 1 : 0;
}

=head2 insert_alert

Insert one parsed alert row into its table and return the new C<id>.

    my $id = $lilith->insert_alert(
        type => 'suricata',
        row  => $row,          # as returned by parse_eve
    );

Arguments.

    - type :: 'suricata', 'sagan', 'cape', or 'baphomet'. Required.

    - row :: Hash ref keyed by column name, the same keys as
      C<@{ $Lilith::alert_columns{$type} }>. Missing columns insert as NULL;
      keys outside the column set are ignored. Required.

The column list and INSERT are built from C<%alert_columns> so callers (the
local EVE tailer in L</run> and L<Lilith::Receiver>) cannot drift from the
schema. Dies on DB failure.

=cut

sub insert_alert {
	my ( $self, %opts ) = @_;

	my $type = $opts{type};
	die 'no type given'          unless defined $type;
	die "unknown type '$type'"   unless $alert_columns{$type};
	die 'row must be a hash ref' unless ref $opts{row} eq 'HASH';
	my $row = $opts{row};

	my $table
		= $type eq 'suricata' ? 'suricata_alerts'
		: $type eq 'sagan'    ? 'sagan_alerts'
		: $type eq 'cape'     ? 'cape_alerts'
		:                       'baphomet_alerts';
	my @cols = @{ $alert_columns{$type} };

	# RaiseError so a failed connect or INSERT actually dies; both run() and
	# the receiver depend on this sub dying rather than quietly returning undef
	my $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass}, { RaiseError => 1 } );
	my $sql
		= 'insert into '
		. $table . ' ( '
		. join( ', ', @cols )
		. ' ) VALUES ( '
		. join( ', ', ('?') x scalar(@cols) )
		. ' ) returning id;';
	my $sth = $dbh->prepare($sql);
	$sth->execute( map { $row->{$_} } @cols );
	my ($id) = $sth->fetchrow_array;

	return $id;
} ## end sub insert_alert

=head2 receiver_apikey_auth

Look up a receiver API key by its bearer token and verify the client IP is
permitted. Returns the key row (hash ref) on success, or undef when the key is
unknown, disabled, or the IP is not contained by one of the key's
C<allowed_ips>. The instance restriction is checked separately with
L</receiver_apikey_instance_ok> once the pushed row's instance is known.

    my $key = $lilith->receiver_apikey_auth( apikey => $token, ip => $client_ip );

The IP containment runs in the database (C<< inet <<= any(cidr[]) >>) so subnet
entries and IPv6 are handled correctly. A key with no C<allowed_ips> is not
restricted by IP. On a successful lookup the key's C<last_used> is stamped on a
best-effort basis.

=cut

sub receiver_apikey_auth {
	my ( $self, %opts ) = @_;

	return undef unless defined $opts{apikey} && $opts{apikey} ne '';

	# Only bind a syntactically plausible IP; anything else binds as NULL so a
	# key with an IP restriction fails closed instead of erroring on the cast.
	my $ip = ( defined $opts{ip} && $opts{ip} =~ /\A[0-9a-fA-F:.]+\z/ ) ? $opts{ip} : undef;

	my $dbh = $self->_escalation_dbh;
	my $sth
		= $dbh->prepare( 'select * from receiver_apikeys'
			. ' where key_sha256 = ? and enabled'
			. '   and ( allowed_ips is null or array_length(allowed_ips, 1) is null'
			. '         or ?::inet <<= any(allowed_ips) );' );
	$sth->execute( sha256_base64( $opts{apikey} ), $ip );
	my $row = $sth->fetchrow_hashref;

	return undef unless $row;

	# best-effort usage stamp; never fail auth over it
	eval { $dbh->do( 'update receiver_apikeys set last_used = now() where id = ?;', undef, $row->{id} ); };

	return $row;
} ## end sub receiver_apikey_auth

=head2 receiver_apikey_instance_ok

Whether a key row (as returned by L</receiver_apikey_auth>) permits writing the
given instance. A key with no C<allowed_instances> permits any instance;
otherwise the instance must match one of the patterns, where C<*> and C<?> are
shell-style wildcards (C<foo-*> matches every instance beginning C<foo->). A
pattern with no wildcards is an exact match.

    if ( $lilith->receiver_apikey_instance_ok( $key, $instance ) ) { ... }

=cut

sub receiver_apikey_instance_ok {
	my ( $self, $key, $instance ) = @_;

	my $allowed = ref $key eq 'HASH' ? $key->{allowed_instances} : undef;
	return 1 if ref $allowed ne 'ARRAY' || !@{$allowed};

	return 0 unless defined $instance;

	foreach my $pattern ( @{$allowed} ) {
		next unless defined $pattern;
		return 1 if $instance =~ $self->_instance_regex($pattern);
	}

	return 0;
} ## end sub receiver_apikey_instance_ok

# Compile a shell-style instance pattern ('*' and '?' wildcards) into an
# anchored regex. Everything else matches literally, so a pattern with no
# wildcards is an exact match -- the same behavior a plain instance name had
# before wildcards were supported. Anchoring is what keeps 'foo' from matching
# 'barfoo'.
#
# Args:
#
#   - $pattern :: the instance pattern off a receiver key's allowed_instances,
#     e.g. 'foo-pie' for an exact match or 'foo-*' for every instance whose
#     name begins 'foo-'. '?' stands for exactly one character.
#
# Returns: a compiled Regexp anchored at both ends, ready to match an
# instance name against.
#
#     my $re = $self->_instance_regex('foo-*');
#     'foo-pie' =~ $re;    # true
#     'barfoo'  =~ $re;    # false
sub _instance_regex {
	my ( $self, $pattern ) = @_;

	my $re = quotemeta $pattern;
	$re =~ s/\\\*/.*/g;
	$re =~ s/\\\?/./g;

	return qr/\A$re\z/;
}

=head2 receiver_apikey_create

Create a receiver API key. Generates the bearer token, stores only its SHA-256,
and returns C<< { id => $id, apikey => $token } >>. The plaintext token is
returned only here and is not recoverable afterwards.

    my $new = $lilith->receiver_apikey_create(
        name              => 'sensor1',
        allowed_ips       => [ '10.0.0.0/8', '192.168.1.5/32' ],  # optional
        allowed_instances => [ 'foo-*' ],                         # optional
        description       => '...',                               # optional
        enabled           => 1,                                   # default 1
    );

C<allowed_ips> / C<allowed_instances> are array refs; omit or pass an empty ref
to leave that axis unrestricted. Invalid CIDR values are rejected by the
database.

=cut

sub receiver_apikey_create {
	my ( $self, %opts ) = @_;

	die('"name" is required') if !defined $opts{name} || $opts{name} eq '';

	my $enabled   = ( !defined $opts{enabled} || $opts{enabled} ) ? 1 : 0;
	my $ips       = $self->_receiver_array_or_null( $opts{allowed_ips} );
	my $instances = $self->_receiver_array_or_null( $opts{allowed_instances} );

	my $token = $self->_receiver_key_generate;

	my $dbh = $self->_escalation_dbh;
	my $sth
		= $dbh->prepare( 'insert into receiver_apikeys'
			. ' ( name, key_sha256, enabled, allowed_ips, allowed_instances, description )'
			. ' VALUES ( ?, ?, ?, ?, ?, ? ) RETURNING id;' );
	$sth->execute( $opts{name}, sha256_base64($token), $enabled, $ips, $instances, $opts{description} );

	my ($id) = $sth->fetchrow_array;

	return { id => $id, apikey => $token };
} ## end sub receiver_apikey_create

=head2 receiver_apikey_get

Fetch one receiver API key row by numeric id. Dies if the id is missing,
non-numeric, or unknown. The row carries only C<key_sha256>, never the token.

    my $key = $lilith->receiver_apikey_get($id);

=cut

sub receiver_apikey_get {
	my ( $self, $id ) = @_;

	die('receiver api key id is required and must be numeric')
		if !defined $id || $id !~ /^[0-9]+$/;

	my $dbh = $self->_escalation_dbh;
	my $sth = $dbh->prepare('select * from receiver_apikeys where id = ?;');
	$sth->execute($id);

	my $row = $sth->fetchrow_hashref;
	die( 'no receiver api key with the id "' . $id . '"' ) if !$row;

	return $row;
} ## end sub receiver_apikey_get

=head2 receiver_apikeys

Return an array ref of every receiver API key row, ordered by name. Rows carry
only C<key_sha256>, never the token.

    my $keys = $lilith->receiver_apikeys;

=cut

sub receiver_apikeys {
	my ($self) = @_;

	my $dbh = $self->_escalation_dbh;

	return $dbh->selectall_arrayref( 'select * from receiver_apikeys order by name;', { Slice => {} } );
}

=head2 receiver_apikey_update

Update a receiver API key's metadata and restrictions. The token itself is never
changed; rotate a key by deleting and recreating it.

    $lilith->receiver_apikey_update(
        id                => $id,
        enabled           => 0,
        allowed_ips       => [ '10.0.0.0/8' ],  # replaces; [] clears (any)
        allowed_instances => [ 'foo-*' ],       # replaces; [] clears (any)
    );

Only the keys present in C<%opts> are changed; C<allowed_ips> /
C<allowed_instances> are replaced when supplied (an empty array ref clears the
restriction).

=cut

sub receiver_apikey_update {
	my ( $self, %opts ) = @_;

	my $existing = $self->receiver_apikey_get( $opts{id} );

	my $name        = defined( $opts{name} ) && $opts{name} ne '' ? $opts{name} : $existing->{name};
	my $enabled     = exists $opts{enabled}     ? ( $opts{enabled} ? 1 : 0 )    : ( $existing->{enabled} ? 1 : 0 );
	my $description = exists $opts{description} ? $opts{description}            : $existing->{description};

	my $ips
		= exists $opts{allowed_ips}
		? $self->_receiver_array_or_null( $opts{allowed_ips} )
		: $self->_receiver_array_or_null( $existing->{allowed_ips} );
	my $instances
		= exists $opts{allowed_instances}
		? $self->_receiver_array_or_null( $opts{allowed_instances} )
		: $self->_receiver_array_or_null( $existing->{allowed_instances} );

	my $dbh = $self->_escalation_dbh;
	my $sth = $dbh->prepare( 'update receiver_apikeys set name = ?, enabled = ?, allowed_ips = ?,'
			. ' allowed_instances = ?, description = ?, updated = now() where id = ?;' );
	$sth->execute( $name, $enabled, $ips, $instances, $description, $opts{id} );

	return 1;
} ## end sub receiver_apikey_update

=head2 receiver_apikey_delete

Delete a receiver API key by numeric id.

    $lilith->receiver_apikey_delete($id);

=cut

sub receiver_apikey_delete {
	my ( $self, $id ) = @_;

	die('receiver api key id is required and must be numeric')
		if !defined $id || $id !~ /^[0-9]+$/;

	my $dbh = $self->_escalation_dbh;
	$dbh->prepare('delete from receiver_apikeys where id = ?;')->execute($id);

	return 1;
} ## end sub receiver_apikey_delete

# Generate a fresh bearer token: 32 random bytes as 64 hex characters.
#
# Crypt::URandom is loaded at call time rather than up top because minting a
# key is a rare administrative act, while this module is loaded by every daemon
# and CLI run.
#
# Args: none.
#
# Returns: the token as a 64 character lowercase hex string. Only the caller
# ever sees it in the clear -- receiver_apikey_create stores the SHA-256 and
# hands the plaintext back once.
#
#     my $token = $self->_receiver_key_generate;
#     # '3f9c...' , 64 hex characters
sub _receiver_key_generate {
	my ($self) = @_;

	require Crypt::URandom;
	return unpack( 'H*', Crypt::URandom::urandom(32) );
}

# Turn an array ref into a Postgres array literal for binding, or undef (=> SQL
# NULL, meaning unrestricted) for an empty/undef list. Shared by the cidr[] and
# varchar[] receiver columns -- both take the same {"a","b"} text form.
#
# Args:
#
#   - $list :: array ref of scope entries, or undef. For allowed_ips these are
#     hosts or CIDR subnets ('10.0.0.0/8'); for allowed_instances, names or
#     globs ('foo-*').
#
# Returns: the Postgres array literal as a string, or undef for an empty or
# missing list. undef binds as SQL NULL, which on both columns means
# unrestricted rather than "matches nothing" -- so clearing a scope widens the
# key rather than locking it out.
#
#     $self->_receiver_array_or_null( [ '10.0.0.0/8' ] );    # '{"10.0.0.0/8"}'
#     $self->_receiver_array_or_null( [] );                  # undef
sub _receiver_array_or_null {
	my ( $self, $list ) = @_;

	return undef if ref $list ne 'ARRAY' || !@{$list};

	return $self->_pg_text_array($list);
}

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

    - type :: Either 'suricata', 'sagan', 'cape', or 'baphomet',
              depending on the type it is.

    - eve :: Path to the EVE file to read.

    - instance :: Instance name. If not specified the key
                  is used.

=cut

sub run {
	my ( $self, %opts ) = @_;

	# verify the DB is reachable before starting the tailers; RaiseError so a
	# failed connect actually reaches the eval instead of returning undef
	eval { DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass}, { RaiseError => 1 } ); };
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
		} elsif ( !$KNOWN_TABLE_TYPES{ $item->{type} } ) {
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

					eval {
						my $row = $self->parse_eve(
							type     => $_[HEAP]{type},
							json     => $json,
							instance => $_[HEAP]{instance},
							host     => $_[HEAP]{host},
							raw      => $_[ARG0],
						);
						if ( defined($row) ) {
							$self->insert_alert( type => $_[HEAP]{type}, row => $row );
						}
					};
					if ($@) {
						warn( 'SQL INSERT issue... ' . $@ );
						openlog( 'lilith', undef, 'daemon' );
						syslog( 'LOG_ERR', 'SQL INSERT issue... ' . $@ );
						closelog;
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
	} elsif ( $opts{go_back_minutes} !~ /^[0-9]+$/ ) {

		# interpolated into the interval below, so it must really be a number
		die( '"' . $opts{go_back_minutes} . '" for go_back_minutes is not numeric' );
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

	# The suricata and sagan sides only differ by table and by which column
	# holds the local hostname (sagan records it as instance_host), so both the
	# fetch and the aggregation below run through the same loop.
	my %daemon_source = (
		suricata => [ 'suricata_alerts', 'host' ],
		sagan    => [ 'sagan_alerts',    'instance_host' ],
	);
	my %found_rows_by_daemon = ( suricata => [], sagan => [] );
	eval {
		my $dbh;
		eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
		if ($@) {
			die( 'DBI->connect_cached failure.. ' . $@ );
		}

		my $hostname = hostname;

		foreach my $daemon ( 'suricata', 'sagan' ) {
			my ( $alert_table, $host_column ) = @{ $daemon_source{$daemon} };

			my $sql
				= 'select * from '
				. $alert_table
				. " where timestamp >= CURRENT_TIMESTAMP - interval '"
				. $opts{go_back_minutes}
				. " minutes' and "
				. $host_column . " ='"
				. $hostname . "';";

			if ( $self->{debug} ) {
				warn( 'SQL search "' . $sql . '"' );
			}
			my $sth = $dbh->prepare($sql);
			$sth->execute();
			$found_rows_by_daemon{$daemon} = $sth->fetchall_arrayref( {} );
		} ## end foreach my $daemon ( 'suricata', 'sagan' )
	};
	if ($@) {
		$to_return->{error}       = 1;
		$to_return->{errorString} = $@;
	}

	foreach my $daemon ( 'suricata', 'sagan' ) {
		my $totals_key    = $daemon . '_totals';
		my $instances_key = $daemon . '_instances';
		foreach my $row ( @{ $found_rows_by_daemon{$daemon} } ) {
			$to_return->{data}{totals}{total}++;
			$to_return->{data}{$totals_key}{total}++;
			my $snmp_class = $self->get_short_class_snmp( $row->{classification} );
			if ( !defined( $to_return->{data}{totals}{$snmp_class} ) ) {
				$to_return->{data}{totals}{$snmp_class} = 1;
			} else {
				$to_return->{data}{totals}{$snmp_class}++;
			}
			if ( !defined( $to_return->{data}{$totals_key}{$snmp_class} ) ) {
				$to_return->{data}{$totals_key}{$snmp_class} = 1;
			} else {
				$to_return->{data}{$totals_key}{$snmp_class}++;
			}
			if ( !defined( $to_return->{data}{$instances_key}{ $row->{instance} } ) ) {
				$to_return->{data}{$instances_key}{ $row->{instance} } = { total => 0 };
			}
			$to_return->{data}{$instances_key}{ $row->{instance} }{total}++;
			if ( !defined( $to_return->{data}{$instances_key}{ $row->{instance} }{$snmp_class} ) ) {
				$to_return->{data}{$instances_key}{ $row->{instance} }{$snmp_class} = 1;
			} else {
				$to_return->{data}{$instances_key}{ $row->{instance} }{$snmp_class}++;
			}
		} ## end foreach my $row ( @{ $found_rows_by_daemon{$daemon...}})
	} ## end foreach my $daemon ( 'suricata', 'sagan' )

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

Searches the specified table and returns an array of found rows. This is a wrapper around
Lilith::Schema. If you are looking for something more complex, read L<DBIx::Class>,
L<SQL::Abstract::Classic>, and L<Lilith::Schema>.

    - table :: 'suricata', 'cape', 'sagan', or 'baphomet' depending on the
               desired table to use. Will die if something other is specified.
               The table name used is based on what was passed to new(if not
               the default).
      Default :: suricata

    - go_back_minutes :: How far back to search in minutes.
      Default :: 1440

    - no_time :: If true, apply no time window at all, ignoring both
                 go_back_minutes and start/end. Meant for lookups by id,
                 where the row may be arbitrarily old or (for cape) have
                 a NULL stop.
      Default :: undef

    - limit :: Limit on how many to return.
      Default :: undef

    - offset :: Offset for when using limit.
      Default :: undef

    - order_by :: Column to order by. Must be a column of the table being
                  searched or it will die.
      Default :: timestamp
      Cape Default :: id

Search items for columns the table being searched does not have are silently
ignored, so suricata-shaped filters like sid or port do not error a cape or
baphomet search.

    - order_dir :: Direction to order.
      Default :: ASC

Below are the address items. A '!' prefix negates one, but unlike the string
items a '%' does not make it a LIKE: these columns are inet, which LIKE does
not apply to, so a '%' is matched as part of the value.

    - src_ip
    - dest_ip
    - subbed_from_ip

    # will become "and src_ip = '192.168.1.2'"
    src_ip => '192.168.1.2',

Below are a list of numeric items. The value taken is an array and anything
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

Below are a list of string items. A '!' prefix negates one and a '%' makes it
a LIKE.

    - host
    - instance_host
    - instance
    - class
    - signature
    - app_proto
    - proto
    - in_iface
    - event_id
    - md5
    - sha1
    - sha256
    - url
    - url_hostname
    - slug
    - pkg
    - subbed_from_host
    - event_type
    - target
    - username

    # will become "and host = 'foo.bar'"
    host => 'foo.bar',

    # will become "and class != 'foo'"
    class => '!foo',

    # will become "and instance like '%foo'"
    instance => '%foo',

    # will become "and instance not like '%foo'"
    instance => '!%foo',

Any string or address item may also be given an array, which reads as "any
of these, none of those": positive items are ORed together while negated
items are ANDed.

    # will become "and class in ( 'foo', 'bar' )"
    class => ['foo', 'bar'],

    # will become "and ( class in ( 'foo', 'bar' ) or class like 'derp%' )"
    class => ['foo', 'bar', 'derp%'],

    # will become "and class != 'foo' and class not like 'derp%'"
    class => ['!foo', '!derp%'],

    # will become "and ( instance like 'nibbles0%' or instance = 'inari-pie' )"
    instance => ['nibbles0%', 'inari-pie'],

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

Next are the locality filters, which read the alert's own addresses against
the deployment's C<local_networks> CIDR list (the web layer passes the
config's; with none given, the unroutable ranges stand in):

    - src_locality / dest_locality :: which side of your own networks that
      end sits on, 'internal' or 'external' -- the search-filter form of the
      dashboard dimensions of the same names, by the same list. '!' negates;
      anything else dies. An alert naming no address on that end matches
      neither.

    # alerts whose destination is one of your own machines
    dest_locality => 'internal',

Below are the Shodan enrichment filters, for the suricata, sagan, and baphomet
tables (cape is skipped -- its addresses describe the submitter). Each filters
on what the C<shodan_cache> table (schema version 15) holds for that end of the
alert, the same data the results badges and the dashboard's enrichment
dimensions read, and like the dimensions they match whatever the cache
currently holds -- running C<lilith shodan_cache> on a timer is what keeps
that current. An end with no cached entry never matches a positive filter.

    - shodan_src_tag / shodan_dest_tag :: Shodan's tags for the host. A '!'
      prefix negates; positives read "any of these", negations "none of
      those". No LIKE.
    - shodan_src_known / shodan_dest_known :: the cache state for the host,
      one of 'known' (crawled and on Shodan), 'unknown' (crawled, nothing
      there), or 'unchecked' (never looked up). '!' negates; anything else
      dies.
    - shodan_src_cvss / shodan_dest_cvss :: the worst CVSS of the host's
      CVEs, with the CVEDB cache standing in where Shodan sent no scores --
      the same value the results badges color by. Takes the numeric
      comparison operators; several terms AND together.

    # alerts whose source is tagged tor or vpn
    shodan_src_tag => [ 'tor', 'vpn' ],

    # alerts whose source has a critical CVE
    shodan_src_cvss => ['>=9'],

    # alerts against destinations Shodan has never crawled
    shodan_dest_known => 'unchecked',

Last are the rule CVE filters, for suricata only (elsewhere they are skipped
like any other filter naming a column the table lacks):

    - cve :: the CVE ids the rule that fired names, from the cves generated
      column (schema version 16). Values are normalized before matching, so
      'cve_2021_44228' finds what 'CVE-2021-44228' does; anything that does
      not normalize to an id dies. '!' negates, and a rule naming no ids
      counts as not naming any given one.

    # alerts whose rule names Log4Shell
    cve => 'CVE-2021-44228',

    - shodan_src_cve_match / shodan_dest_cve_match :: where the rule's ids
      and that end's cached CVEs stand against each other -- the same four
      states as the dashboard dimensions of the same names, so a slice of
      either chart is answerable as a list of alerts. One filter per end
      because src and dest are the triggering packet's direction, not
      attacker and victim. One or more of 'matched' (the rule names a CVE
      that end is cached as vulnerable to), 'unmatched' (the rule names CVEs,
      the cached entry carries none of them), 'no-cve' (the rule names none),
      and 'unchecked' (the rule names CVEs, that end was never looked up).
      '!' negates; anything else dies. Needs both the shodan_cache table and
      the cves column (schema version 16).

    # the exploit-against-a-vulnerable-host alerts, whichever end it sits on
    shodan_src_cve_match  => 'matched',
    shodan_dest_cve_match => 'matched',

=cut

# Validate and normalize a search start/end time to a canonical
# 'YYYY-MM-DD HH:MM:SS' string (a server-local wall clock, bound as a value and
# cast by the DB in its session timezone). Accepts anything Time::Piece::Guess
# parses -- including a datetime-local 'YYYY-MM-DDTHH:MM' value. Dies on garbage.
# Plain function, not a method.
#
# Args:
#
#   - $label :: which bound is being parsed, used only in the error message.
#     'start' or 'end'.
#   - $str :: the time as the user wrote it. Anything Time::Piece::Guess
#     handles, e.g. '2026-08-05 13:00:00', '2026-08-05T13:00' from a
#     datetime-local input, or '2026-08-05'.
#
# Returns: the time as a 'YYYY-MM-DD HH:MM:SS' string. Dies with '"$str" for
# $label is not a parseable time' when it cannot be read.
#
#     _parse_search_time( 'start', '2026-08-05T13:00' );
#     # '2026-08-05 13:00:00'
sub _parse_search_time {
	my ( $label, $str ) = @_;
	my $t = eval { Time::Piece::Guess->guess_to_object( $str, 1 ) };
	die( '"' . $str . '" for ' . $label . " is not a parseable time\n" ) unless defined $t;
	return $t->strftime('%Y-%m-%d %H:%M:%S');
}

# Build the WHERE clauses for a text column filter, which may have been given
# one value or several. Several values read as "any of these, none of those":
# the positive ones are ORed together, so more values widen the search, while
# each negated one is ANDed, so it removes rows regardless of what else
# matched. Plain function, not a method.
#
# Args:
#
#   - $column :: the column to filter on, e.g. 'instance' or 'classification'.
#     Used as the key of every clause returned, so it must be a real column of
#     the table being searched -- the caller checks that.
#
#   - $values :: the value or values as the user wrote them, either a scalar
#     ('nibbles0%') or an array ref ( [ 'nibbles0%', '!inari-pie' ] ). A leading
#     '!' negates the value it is on. undef and empty string values are skipped,
#     so a blank field adds nothing rather than matching nothing.
#
#   - $allow_like :: whether a value containing '%' is a LIKE rather than a
#     literal. False for inet columns, which LIKE does not apply to.
#
# Returns: the clauses as a list, ready to push onto the '-and' of the search
# hash. Empty when every value was blank. At most one clause covers all the
# positive values -- an '=', an '-in', or an '-or' of those with the LIKEs --
# followed by one clause per negated value.
#
#     push( @{ $search->{'-and'} }, _string_filter_clauses( 'instance', [ 'nibbles0%', 'inari-pie' ], 1 ) );
#     # ( { instance => { '-or' => ... } } ), i.e.
#     # "and ( instance = 'inari-pie' or instance like 'nibbles0%' )"
sub _string_filter_clauses {
	my ( $column, $values, $allow_like ) = @_;

	my @values = ref($values) eq 'ARRAY' ? @{$values} : ($values);

	my @in;          # plain positives, which collapse into one '=' or '-in'
	my @positive;    # positives needing an operator of their own, i.e. the LIKEs
	my @negative;

	foreach my $value (@values) {
		next if !defined($value) || $value eq '';

		if ( $value =~ s/^\!// ) {
			push( @negative, { ( $allow_like && $value =~ /\%/ ) ? ( '-not_like' => $value ) : ( '!=' => $value ) } );
		} elsif ( $allow_like && $value =~ /\%/ ) {
			push( @positive, { 'like' => $value } );
		} else {
			push( @in, $value );
		}
	} ## end foreach my $value (@values)

	if ( defined( $in[0] ) && !defined( $in[1] ) ) {
		unshift( @positive, { '=' => $in[0] } );
	} elsif ( defined( $in[1] ) ) {
		unshift( @positive, { '-in' => \@in } );
	}

	my @clauses;
	if ( defined( $positive[0] ) && !defined( $positive[1] ) ) {
		push( @clauses, { $column => $positive[0] } );
	} elsif ( defined( $positive[1] ) ) {
		push(
			@clauses,
			{
				'-or' => [
					map {
						{ $column => $_ }
					} @positive
				]
			}
		);
	} ## end elsif ( defined( $positive[1] ) )
	foreach my $item (@negative) {
		push( @clauses, { $column => $item } );
	}

	return @clauses;
} ## end sub _string_filter_clauses

# Flatten a filter's submitted value or values into the non-blank list, the
# shared first step of the enrichment filters below: a filter may arrive as a
# scalar or an array ref, and blanks mean "left empty" rather than "match
# empty". Plain function, not a method.
#
# Args:
#
#   - $values :: the value or values as the caller passed the filter -- a
#     scalar, an array ref, or undef.
#
# Returns: the values as a list, undefs and empty strings dropped. Empty when
# there was nothing.
#
#     _filter_values( [ 'tor', '', undef ] );   # ( 'tor' )
sub _filter_values {
	my $values = shift;

	my @values = ref $values eq 'ARRAY' ? @{$values} : ($values);
	return grep { defined($_) && $_ ne '' } @values;
}

# Turn a fixed-vocabulary filter's values into search clauses, the assembly the
# known and cve_match filters share: strip a leading '!' as negation, die on a
# value outside the vocabulary, OR the positives together (a single one stays a
# bare clause), and AND each negation in as the complement of its clause. Plain
# function, not a method.
#
# Args:
#
#   - $filter_name :: the filter as the caller names it, e.g.
#     'shodan_src_known'; used in the death.
#   - $values :: array ref of the submitted values, already through
#     _filter_values.
#   - $sql_for :: hash ref mapping each vocabulary word to the SQL boolean
#     implementing it.
#   - $allowed :: the vocabulary as prose for the death, e.g. 'known, unknown,
#     or unchecked'.
#
# Returns: the clauses as a list, ready to push onto the search's -and --
# literal-SQL refs, plus a -or hash when several positives were given. Empty
# when $values is. Dies naming the filter and the vocabulary for a value
# outside it.
#
#     push( @clauses, _vocab_clauses( 'shodan_src_known', \@values,
#         \%known_sql, 'known, unknown, or unchecked' ) );
sub _vocab_clauses {
	my ( $filter_name, $values, $sql_for, $allowed ) = @_;

	my ( @positive, @negative );
	for my $value ( @{$values} ) {
		my $negated = $value =~ s/^\!//;
		if ( !$sql_for->{$value} ) {
			die( '"' . $value . '" for ' . $filter_name . ' is not one of ' . $allowed );
		}
		if   ($negated) { push( @negative, $value ); }
		else            { push( @positive, $value ); }
	}

	my @clauses;
	if ( @positive == 1 ) {
		push( @clauses, \[ $sql_for->{ $positive[0] } ] );
	} elsif (@positive) {
		push( @clauses, { '-or' => [ map { \[ $sql_for->{$_} ] } @positive ] } );
	}
	push( @clauses, map { \[ 'not (' . $sql_for->{$_} . ')' ] } @negative );
	return @clauses;
} ## end sub _vocab_clauses

# Dies if the passed table name is not one of the known alert table types. The
# short type picks both the DBIx::Class result class and the real table name, so
# this is the gate that keeps a request parameter from reaching either.
#
# Args:
#
#   - $table :: the short table type -- 'suricata', 'sagan', 'cape', or
#     'baphomet'. Unlike Lilith::Stats::_table there is no defaulting here;
#     callers that want one apply it themselves.
#
# Returns: the table type as a string, unchanged, so it can be used inline.
# Dies with '"$table" is not a known table type' otherwise, naming 'undef' when
# nothing was passed.
#
#     $self->_validate_table( $opts{table} ) if defined( $opts{table} );
sub _validate_table {
	my ( $self, $table ) = @_;

	if ( !defined($table) || !$KNOWN_TABLE_TYPES{$table} ) {
		die( '"' . ( defined($table) ? $table : 'undef' ) . '" is not a known table type' );
	}

	return $table;
}

# The column a table is windowed on in time terms. CAPE has no ingest
# timestamp; its analysis 'stop' time is the closest analogue, so it stands in
# everywhere a window or a time value is wanted. The one place this fact lives.
#
# Args:
#
#   - $table :: the short table type, already validated.
#
# Returns: the column name as a string -- 'stop' for cape, 'timestamp' for
# everything else.
#
#     my $time_column = $self->_time_column('cape');    # 'stop'
sub _time_column {
	my ( $self, $table ) = @_;

	return $table eq 'cape' ? 'stop' : 'timestamp';
}

sub search {
	my ( $self, %opts ) = @_;

	if ( defined( $opts{table} ) ) {
		$self->_validate_table( $opts{table} );
	} else {
		$opts{table} = 'suricata';
	}
	my $table            = 'SuricataAlert';
	my $default_order_by = 'timestamp';
	if ( $opts{table} eq 'sagan' ) {
		$table = 'SaganAlert';
	} elsif ( $opts{table} eq 'cape' ) {
		$table            = 'CapeAlert';
		$default_order_by = 'id';
	} elsif ( $opts{table} eq 'baphomet' ) {
		$table = 'BaphometAlert';
	}

	if ( !defined( $opts{order_by} ) ) {
		$opts{order_by} = $default_order_by;
	}

	# the columns the selected table really has; used to vet order_by and to
	# skip filters on columns the table lacks, such as the web UI's
	# suricata-shaped filters reaching a cape or baphomet search, which would
	# otherwise die with a "column does not exist" error
	my %table_has_column = map { $_ => 1 } ( @{ $alert_columns{ $opts{table} } }, qw(id escalations auto_escalated) );

	# order_by is concatenated into the ORDER BY clause below, so it must be
	# checked against the table's real column names rather than passed through
	if ( !$table_has_column{ $opts{order_by} } ) {
		die( '"' . $opts{order_by} . '" for order_by is not a column of the ' . $opts{table} . ' table' );
	}

	if ( !defined( $opts{go_back_minutes} ) ) {
		$opts{go_back_minutes} = '1440';
	} else {
		if ( $opts{go_back_minutes} !~ /^[0-9]+$/ ) {
			die( '"' . $opts{go_back_minutes} . '" for go_back_minutes is not numeric' );
		}
	}

	if ( defined( $opts{order_dir} ) && $opts{order_dir} ne 'ASC' && $opts{order_dir} ne 'DESC' ) {
		die( '"' . $opts{order_dir} . '" for order_dir must by either ASC or DESC' );
	} elsif ( !defined( $opts{order_dir} ) ) {
		$opts{order_dir} = 'ASC';
	}

	my $go_back_column = $self->_time_column( $opts{table} );

	my $schema = Lilith::Schema->connect( $self->{dsn}, $self->{user}, $self->{pass}, );

	# Time window on the type's time column. An explicit start and/or end (any
	# Time::Piece::Guess-parseable time, e.g. a datetime-local value) gives a
	# bounded range, bound as values and read in the DB session's timezone
	# (server-local); with neither, fall back to the now-relative go_back_minutes.
	my %time_cond;
	if ( defined( $opts{start} ) && $opts{start} ne '' ) {
		$time_cond{'>='} = _parse_search_time( 'start', $opts{start} );
	}
	if ( defined( $opts{end} ) && $opts{end} ne '' ) {
		$time_cond{'<='} = _parse_search_time( 'end', $opts{end} );
	}

	my $search;
	if ( $opts{no_time} ) {

		# no time window at all; used for lookups by id, where the row wanted
		# may be arbitrarily old or (for cape) have a NULL stop
		$search = {};
	} elsif (%time_cond) {
		$search = { $go_back_column => \%time_cond };
	} else {
		my $go_back_time = 'CURRENT_TIMESTAMP - interval \'' . $opts{go_back_minutes} . ' minutes\'';
		$search = { $go_back_column => { '>=', \$go_back_time } };
	}

	#
	# add address items
	#

	# These are inet columns, so unlike the string items below a '%' is not a
	# LIKE -- it is matched as part of the value.
	my @addresses = ( 'src_ip', 'dest_ip', 'subbed_from_ip' );

	foreach my $item (@addresses) {
		if ( defined( $opts{$item} ) && $table_has_column{$item} ) {
			my @clauses = _string_filter_clauses( $item, $opts{$item}, 0 );
			if ( defined( $clauses[0] ) ) {
				$search->{'-and'} = [] if !defined( $search->{'-and'} );
				push( @{ $search->{'-and'} }, @clauses );
			}
		}
	}

	#
	# add numeric items
	#

	my @numeric = ( 'src_port', 'dest_port', 'gid', 'sid', 'rev', 'id', 'size', 'malscore', 'task' );

	foreach my $item (@numeric) {
		if ( defined( $opts{$item} ) && $table_has_column{$item} ) {
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
					$arg =~ s/^\>//;
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
		} ## end if ( defined( $opts{$item} ) && $table_has_column...)
	} ## end foreach my $item (@numeric)

	#
	# more complex items
	#

	if (   defined( $opts{ip} )
		&& ( ref( $opts{ip} ) eq 'ARRAY' || $opts{ip} ne '' )
		&& $table_has_column{src_ip}
		&& $table_has_column{dest_ip} )
	{
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
	} ## end if ( defined( $opts{ip} ) && ( ref( $opts{...})))

	if (   defined( $opts{port} )
		&& ( ref( $opts{port} ) eq 'ARRAY' || $opts{port} ne '' )
		&& $table_has_column{src_port}
		&& $table_has_column{dest_port} )
	{
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
				push(
					@negative,
					{
						'-and' =>
							[ { src_port => { $equality => $number } }, { dest_port => { $equality => $number } } ]
					}
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
	} ## end if ( defined( $opts{port} ) && ( ref( $opts...)))

	#
	# handle string items
	#

	# cape has no classification column, so any class filter -- including the
	# web UI's default "Generic Protocol Command Decode" exclusion -- does not
	# apply to it and would otherwise produce a "column does not exist" error.
	if ( defined( $opts{class} ) && $table_has_column{classification} ) {
		my @clauses = _string_filter_clauses( 'classification', $opts{class}, 1 );
		if ( defined( $clauses[0] ) ) {
			$search->{'-and'} = [] if !defined( $search->{'-and'} );
			push( @{ $search->{'-and'} }, @clauses );
		}
	}

	my @strings = (
		'host',         'instance_host', 'instance', 'signature',
		'app_proto',    'proto',         'in_iface', 'event_id',
		'md5',          'sha1',          'sha256',   'url',
		'url_hostname', 'slug',          'pkg',      'subbed_from_host',
		'event_type',   'username',      'target'
	);
	foreach my $item (@strings) {
		if ( defined( $opts{$item} ) && $table_has_column{$item} ) {
			my @clauses = _string_filter_clauses( $item, $opts{$item}, 1 );
			if ( defined( $clauses[0] ) ) {
				$search->{'-and'} = [] if !defined( $search->{'-and'} );
				push( @{ $search->{'-and'} }, @clauses );
			}
		}
	}

	# src_locality / dest_locality, as the POD above lays out: which side of
	# the deployment's own networks the end sits on, per the caller's
	# local_networks list (with none, the unroutable ranges -- see
	# Lilith::DBUtil::local_networks_frag, which the dashboard dimensions
	# share). Fixed vocabulary; anything else dies rather than silently
	# matching nothing. An alert naming no address on that end matches
	# neither, so external is null-guarded rather than a bare negation.
	for my $side (qw(src dest)) {
		my $locality_filter = $side . '_locality';
		my $ip_column       = $side . '_ip';
		next unless defined( $opts{$locality_filter} ) && $table_has_column{$ip_column};

		my @locality_values = _filter_values( $opts{$locality_filter} );
		next unless @locality_values;

		my $inside       = local_networks_frag( 'me.' . $ip_column, $opts{local_networks} );
		my %locality_sql = (
			internal => $inside,
			external => '(me.' . $ip_column . ' is not null and not (' . $inside . '))',
		);

		$search->{'-and'} = [] if !defined( $search->{'-and'} );
		push(
			@{ $search->{'-and'} },
			_vocab_clauses( $locality_filter, \@locality_values, \%locality_sql, 'internal or external' )
		);
	} ## end for my $side (qw(src dest))

	#
	# Shodan enrichment filters
	#

	# The schema facts the enrichment filters gate on, probed lazily and at
	# most once per call however many filters ask -- a clear death beats what
	# the driver would say about a missing table or column when the database is
	# still on an older schema.
	my ( $has_shodan_cache, $has_cves_column );
	my $shodan_cache_present = sub {
		$has_shodan_cache
			= ( $schema->storage->dbh->selectrow_array(q{select to_regclass('shodan_cache')}) ? 1 : 0 )
			if !defined $has_shodan_cache;
		return $has_shodan_cache;
	};
	my $cves_column_present = sub {
		$has_cves_column = column_exists( $schema->storage->dbh, 'suricata_alerts', 'cves' )
			if !defined $has_cves_column;
		return $has_cves_column;
	};

	# These filter on what the shodan_cache table says about an alert's ends
	# rather than on the alert itself, each as an EXISTS against the end's
	# address -- the search-filter form of the dashboard's enrichment
	# dimensions, and like them they match whatever the cache currently holds,
	# with no freshness gate of their own: the cache prunes itself on every
	# write, and the `lilith shodan_cache` timer is what keeps it current.
	# cape is skipped for the same reason Lilith::Stats offers it no
	# enrichment dimensions: a detonation's addresses describe the submitter.
	if ( $opts{table} =~ /^(?:suricata|sagan|baphomet)$/ ) {
		my @shodan_clauses;
		my $shodan_max_cvss;

		for my $side (qw(src dest)) {
			my $ip_column = $side . '_ip';
			next unless $table_has_column{$ip_column};

			# tag: which of Shodan's tags the end's entry carries. The
			# positives are one overlap test, so they read "any of these";
			# the negations are one NOT of the same, "none of those".
			my @tag_values = _filter_values( $opts{ 'shodan_' . $side . '_tag' } );
			if (@tag_values) {
				my ( @tag_positive, @tag_negative );
				for my $value (@tag_values) {
					if ( $value =~ s/^\!// ) { push( @tag_negative, $value ) if $value ne ''; }
					else                     { push( @tag_positive, $value ); }
				}
				my $tag_exists
					= 'exists (select 1 from shodan_cache where shodan_cache.ip = me.'
					. $ip_column
					. ' and shodan_cache.tags && ?::varchar[])';
				push( @shodan_clauses, \[ $tag_exists, $self->_pg_text_array( \@tag_positive ) ] )
					if @tag_positive;
				push( @shodan_clauses, \[ 'not ' . $tag_exists, $self->_pg_text_array( \@tag_negative ) ] )
					if @tag_negative;
			} ## end if (@tag_values)

			# known: what state the cache is in for the end. 'known' is
			# crawled and on Shodan, 'unknown' is crawled with nothing there,
			# 'unchecked' is never looked up -- the same three states the
			# dashboard's known dimension buckets by. Positives are ORed,
			# negations ANDed as complements, and anything else dies rather
			# than silently matching nothing.
			my %known_sql = (
				known => 'exists (select 1 from shodan_cache where shodan_cache.ip = me.'
					. $ip_column
					. ' and shodan_cache.found)',
				unknown => 'exists (select 1 from shodan_cache where shodan_cache.ip = me.'
					. $ip_column
					. ' and not shodan_cache.found)',
				unchecked => 'not exists (select 1 from shodan_cache where shodan_cache.ip = me.'
					. $ip_column . ')',
			);
			my @known_values = _filter_values( $opts{ 'shodan_' . $side . '_known' } );
			push(
				@shodan_clauses,
				_vocab_clauses(
					'shodan_' . $side . '_known',
					\@known_values, \%known_sql, 'known, unknown, or unchecked'
				)
			) if @known_values;

			# cvss: comparisons against the worst score of the end's CVEs,
			# the CVEDB cache standing in where Shodan sent no scores -- the
			# same expression the results badges color by, so the filter
			# matches what the badge shows. The terms AND together inside one
			# row test, the same as the other numeric filters, so '>=7, <9'
			# reads "worst is in the High band". An end with no cache row
			# never matches.
			my @cvss_values = _filter_values( $opts{ 'shodan_' . $side . '_cvss' } );
			if (@cvss_values) {
				$shodan_max_cvss = $self->_shodan_max_cvss_expr( $schema->storage->dbh )
					if !defined($shodan_max_cvss);

				my ( @cvss_terms, @cvss_binds );
				for my $value (@cvss_values) {
					$value =~ s/[\ \t]//g;

					my $equality;
					my $number;
					if ( $value =~ /^([0-9]+(?:\.[0-9]+)?)$/ ) {
						( $equality, $number ) = ( '=', $1 );
					} elsif ( $value =~ /^\<\=([0-9]+(?:\.[0-9]+)?)$/ ) {
						( $equality, $number ) = ( '<=', $1 );
					} elsif ( $value =~ /^\<([0-9]+(?:\.[0-9]+)?)$/ ) {
						( $equality, $number ) = ( '<', $1 );
					} elsif ( $value =~ /^\>\=([0-9]+(?:\.[0-9]+)?)$/ ) {
						( $equality, $number ) = ( '>=', $1 );
					} elsif ( $value =~ /^\>([0-9]+(?:\.[0-9]+)?)$/ ) {
						( $equality, $number ) = ( '>', $1 );
					} elsif ( $value =~ /^\!([0-9]+(?:\.[0-9]+)?)$/ ) {
						( $equality, $number ) = ( '!=', $1 );
					} else {
						die(      '"'
								. $value
								. '" does not appear to be a valid item for a numeric search for shodan_'
								. $side
								. '_cvss' );
					}
					push( @cvss_terms, '(' . $shodan_max_cvss . ') ' . $equality . ' ?' );
					push( @cvss_binds, $number );
				} ## end for my $value (@cvss_values)

				push(
					@shodan_clauses,
					\[
						'exists (select 1 from shodan_cache where shodan_cache.ip = me.'
							. $ip_column . ' and '
							. join( ' and ', @cvss_terms ) . ')',
						@cvss_binds
					]
				);
			} ## end if (@cvss_values)
		} ## end for my $side (qw(src dest))

		if (@shodan_clauses) {
			die("the shodan_* search filters need the shodan_cache table (schema version 15)\n")
				unless $shodan_cache_present->();

			$search->{'-and'} = [] if !defined( $search->{'-and'} );
			push( @{ $search->{'-and'} }, @shodan_clauses );
		}
	} ## end if ( $opts{table} =~ /^(?:suricata|sagan|baphomet)$/)

	# cve: the ids the rule that fired names, out of the cves generated column
	# -- schema version 16 and suricata only, any other table skipping it the
	# same way it skips filters on columns it lacks. Values are normalized to
	# the canonical form first, so 'cve_2021_44228' finds what 'CVE-2021-44228'
	# does, and anything that does not normalize to an id dies rather than
	# silently matching nothing. Positives are one overlap test; a negated id
	# must be absent, with a rule naming no ids at all counting as absent.
	if ( defined( $opts{cve} ) && $opts{table} eq 'suricata' ) {
		my @cve_values = _filter_values( $opts{cve} );

		require Lilith::CVEDB;
		my ( @cve_positive, @cve_negative );
		for my $value (@cve_values) {
			my $negated = $value =~ s/^\!//;
			$value = uc($value);
			$value =~ tr/_/-/;
			$value = 'CVE-' . $value if $value =~ /^[0-9]{4}-[0-9]{4,}$/;
			die( '"' . $value . '" for cve is not a CVE id' ) unless Lilith::CVEDB::is_cve_id($value);
			if   ($negated) { push( @cve_negative, $value ); }
			else            { push( @cve_positive, $value ); }
		}

		if ( @cve_positive || @cve_negative ) {
			die("the cve search filter needs the suricata_alerts cves column (schema version 16)\n")
				unless $cves_column_present->();

			$search->{'-and'} = [] if !defined( $search->{'-and'} );
			push( @{ $search->{'-and'} }, \[ 'me.cves && ?::text[]', $self->_pg_text_array( \@cve_positive ) ] )
				if @cve_positive;

			# coalesce so a rule naming no ids at all counts as not naming it
			push(
				@{ $search->{'-and'} },
				\[ 'not coalesce(me.cves && ?::text[], false)', $self->_pg_text_array( \@cve_negative ) ]
			) if @cve_negative;
		} ## end if ( @cve_positive || @cve_negative )
	} ## end if ( defined( $opts{cve} ) && $opts{table}...)

	# shodan_src_cve_match / shodan_dest_cve_match, as the POD above lays out.
	# Fixed vocabulary; anything else dies rather than silently matching
	# nothing. suricata only, like cve, and for the same reason.
	for my $side (qw(src dest)) {
		my $match_filter = 'shodan_' . $side . '_cve_match';
		next unless defined( $opts{$match_filter} ) && $opts{table} eq 'suricata';

		my @match_values = _filter_values( $opts{$match_filter} );
		my $ip_column    = $side . '_ip';

		my $overlap_exists
			= 'exists (select 1 from shodan_cache where shodan_cache.ip = me.'
			. $ip_column
			. ' and me.cves && (shodan_cache.vulns)::text[])';
		my $row_exists = 'exists (select 1 from shodan_cache where shodan_cache.ip = me.' . $ip_column . ')';
		my %match_sql  = (
			'matched'   => $overlap_exists,
			'unmatched' => '(me.cves is not null and ' . $row_exists . ' and not ' . $overlap_exists . ')',
			'no-cve'    => 'me.cves is null',

			# the address null test keeps this the dimension's bucket: an
			# alert naming no address on this end is left out there, not
			# counted as never-looked-up
			'unchecked' => '(me.cves is not null and me.'
				. $ip_column
				. ' is not null and not '
				. $row_exists . ')',
		);

		my @match_clauses
			= _vocab_clauses( $match_filter, \@match_values, \%match_sql, 'matched, unmatched, no-cve, or unchecked' );
		next unless @match_clauses;

		die( 'the ' . $match_filter . " search filter needs the suricata_alerts cves column (schema version 16)\n" )
			unless $cves_column_present->();
		die( 'the ' . $match_filter . " search filter needs the shodan_cache table (schema version 15)\n" )
			unless $shodan_cache_present->();

		$search->{'-and'} = [] if !defined( $search->{'-and'} );
		push( @{ $search->{'-and'} }, @match_clauses );
	} ## end for my $side (qw(src dest))

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

Returns an array ref of the names of the available escalation types,
including any found under the additional namespaces passed to new.

    my $types = $lilith->escalation_types;

=cut

sub escalation_types {
	my ($self) = @_;

	return Lilith::Escalate->types( $self->{escalation_type_namespaces} );
}

=head2 escalation_type_info

Returns a hash ref describing an escalation type; its name, description,
and config fields. Dies if the type can not be resolved.

    my $info = $lilith->escalation_type_info('Webhook');

=cut

sub escalation_type_info {
	my ( $self, $type ) = @_;

	return Lilith::Escalate->type_info( $type, $self->{escalation_type_namespaces} );
}

=head2 escalation_targets

Returns an array ref of every escalation target, sorted by name, with
the config decoded into a hash ref.

    my $targets = $lilith->escalation_targets;

=cut

sub escalation_targets {
	my ($self) = @_;

	my $dbh = $self->_escalation_dbh;

	my $targets = $dbh->selectall_arrayref( 'select * from escalation_targets order by name;', { Slice => {} } );
	$_->{config} = $self->_decode_jsonb_hash( $_->{config} ) foreach @{$targets};

	return $targets;
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

	$row->{config} = $self->_decode_jsonb_hash( $row->{config} );

	return $row;
} ## end sub escalation_target_get

=head2 escalation_target_create

Creates a new escalation target and returns its ID. The type must
resolve to an escalation type module and the config must pass that
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

Updates an escalation target. Any of name, type, config, description,
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

	my $name        = defined( $opts{name} ) && $opts{name} ne '' ? $opts{name}        : $existing->{name};
	my $type        = defined( $opts{type} ) && $opts{type} ne '' ? $opts{type}        : $existing->{type};
	my $config      = ref( $opts{config} ) eq 'HASH'              ? $opts{config}      : $existing->{config};
	my $description = exists( $opts{description} )                ? $opts{description} : $existing->{description};
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

Deletes an escalation target by ID. Past escalations to it are kept,
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

Escalates an event to one or more escalation targets, recording each
attempt in the escalations table along with the payload the type
actually sent. Attempts refused before a send (a unknown or disabled
target) are recorded as failed too, with target_id null when there is
no valid target row to reference; the target's name is snapshotted
into target_name when known so history stays readable after a target
is deleted. Each recorded escalation ID is also appended to the alert
row's escalations array, in the same transaction as the insert, so
anything reading the alert tables can see whether/how many times a
alert has been escalated without querying the escalations table.
Returns an array ref with one hash ref per target, each having the
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
	$self->_validate_table( $opts{table} );

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

	# skip the time window entirely when fetching a specific event by ID; the
	# row may be arbitrarily old or (for cape) have a NULL stop
	my $found = $self->search(
		table   => $opts{table},
		id      => [ $opts{id} ],
		no_time => 1,
		limit   => 1,
	);
	my $event = $found->[0];
	if ( !$event ) {
		die( 'no event with the id "' . $opts{id} . '" found in the ' . $opts{table} . ' table' );
	}

	my $dbh = $self->_escalation_dbh;

	my $alert_table = $opts{table} . '_alerts';

	# Records one escalation attempt: inserts the escalations row and appends
	# its ID to the alert row's escalations array in one transaction, so the
	# two can not drift. Committed before any send happens so an alert row
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
			$insert->execute(
				$opts{table},   $event->{id},        $event->{event_id},
				$row_target_id, $target_name,        $status,
				$opts{note},    $opts{requested_by}, $error
			);
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
	}; ## end $record = sub

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
			my $escalation_id = $record->( ( $target ? $target_id : undef ), ( $target ? $target->{name} : undef ),
				'failed', $error );
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
				config       => $self->_decode_jsonb_hash( $target->{config} ),
				note         => $opts{note},
				requested_by => $opts{requested_by},
				target_name  => $target->{name},
			);
		};
		my $error  = $@     ? $@       : undef;
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
	} ## end foreach my $target_id ( @{ $opts{target_ids} } )

	return \@results;
} ## end sub escalate

=head2 escalation_test

Sends a synthetic test event to an escalation target without recording
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

Returns the escalations recorded for an event as an array ref of hash
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
	$self->_validate_table( $opts{table} );

	if ( !defined( $opts{id} ) || $opts{id} !~ /^[0-9]+$/ ) {
		die('"id" is required and must be numeric');
	}

	my $dbh = $self->_escalation_dbh;

	my $escalations = $dbh->selectall_arrayref(
		'select e.*, t.name as target_current_name, t.type as target_type from escalations e'
			. ' left join escalation_targets t on e.target_id = t.id'
			. ' where e.table_name = ? and e.alert_id = ? order by e.timestamp desc, e.id desc;',
		{ Slice => {} }, $opts{table}, $opts{id}
	);
	foreach my $row ( @{$escalations} ) {
		if ( !defined( $row->{target_name} ) ) {
			$row->{target_name} = $row->{target_current_name};
		}
		delete( $row->{target_current_name} );
	}

	return $escalations;
} ## end sub escalations_for

=head2 auto_escalations

Returns an array ref of every auto escalation rule, ordered by priority
then name, with each row's C<rule> decoded to a hash ref and C<tables>
to an array ref.

    my $rules = $lilith->auto_escalations;

=cut

sub auto_escalations {
	my ($self) = @_;

	my $dbh = $self->_escalation_dbh;

	my $rules
		= $dbh->selectall_arrayref( 'select * from auto_escalations order by priority asc, name asc;',
			{ Slice => {} } );
	foreach my $row ( @{$rules} ) {
		$row->{rule}   = $self->_decode_jsonb_hash( $row->{rule} );
		$row->{tables} = $self->_auto_decode_tables( $row->{tables} );
	}

	return $rules;
} ## end sub auto_escalations

=head2 auto_escalation_get

Fetches a single auto escalation rule by ID, with C<rule> decoded to a
hash ref and C<tables> to an array ref. Dies if the ID is not numeric or
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

	$row->{rule}   = $self->_decode_jsonb_hash( $row->{rule} );
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
	my $stop    = $opts{stop_on_match}                             ? 1 : 0;

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare(
			  'insert into auto_escalations ( name, enabled, priority, tables, rule, stop_on_match, description )'
			. ' VALUES ( ?, ?, ?, ?::varchar[], ?, ?, ? ) RETURNING id;' );
	$sth->execute(
		$opts{name}, $enabled, $priority,
		$self->_pg_text_array($tables),
		encode_json( $opts{rule} ),
		$stop, $opts{description}
	);

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
	my $rule = ref( $opts{rule} ) eq 'HASH'                ? $opts{rule} : $existing->{rule};
	Lilith::AutoEscalate->check_rule($rule);

	my $tables = exists( $opts{tables} ) ? $self->_auto_check_tables( $opts{tables} ) : $existing->{tables};

	my $priority = defined( $opts{priority} ) ? $opts{priority} : $existing->{priority};
	if ( $priority !~ /^-?[0-9]+$/ ) {
		die('"priority" must be an integer');
	}

	my $stop
		= exists( $opts{stop_on_match} ) ? ( $opts{stop_on_match} ? 1 : 0 ) : ( $existing->{stop_on_match} ? 1 : 0 );
	my $enabled     = exists( $opts{enabled} )     ? ( $opts{enabled} ? 1 : 0 ) : ( $existing->{enabled} ? 1 : 0 );
	my $description = exists( $opts{description} ) ? $opts{description}         : $existing->{description};

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

=head2 auto_escalation_preview

Evaluates a single, possibly unsaved, rule against recent alerts and
returns which would match, B<without> escalating anything and B<without>
stamping any alert as considered. This backs the web UI's dry run: it
looks at all alerts in the window (not just ones auto_escalate has yet
to consider) so a rule can be tried against history.

The C<rule> is validated with L<Lilith::AutoEscalate>'s check_rule.
C<table> selects the alert table (default suricata), C<go_back_minutes>
the window (default 60), and C<limit> caps how many recent alerts are
fetched (default 500). Returns a hash ref with C<table>,
C<go_back_minutes>, C<scanned>, C<matched>, the resolved C<targets> and
any C<unknown_targets> the rule's actions name, and C<matches> (an array
ref of light weight per alert summaries).

    my $preview = $lilith->auto_escalation_preview(
                                                   rule            => $rule,
                                                   table           => 'cape',
                                                   go_back_minutes => 60,
                                                  );

=cut

sub auto_escalation_preview {
	my ( $self, %opts ) = @_;

	if ( ref( $opts{rule} ) ne 'HASH' ) {
		die('"rule" is required and must be a hash ref');
	}
	Lilith::AutoEscalate->check_rule( $opts{rule} );

	my $table = defined( $opts{table} ) ? $opts{table} : 'suricata';
	$self->_validate_table($table);

	my $minutes = defined( $opts{go_back_minutes} ) ? $opts{go_back_minutes} : 60;
	if ( $minutes !~ /^[0-9]+$/ ) {
		die( '"' . $minutes . '" for go_back_minutes is not numeric' );
	}

	my $limit = defined( $opts{limit} ) ? $opts{limit} : 500;
	if ( $limit !~ /^[0-9]+$/ ) {
		die('"limit" must be numeric');
	}

	# order_by is left to search(), whose per-table default is exactly the
	# newest-first column wanted here
	my $events = $self->search(
		table           => $table,
		go_back_minutes => $minutes,
		limit           => $limit,
		order_dir       => 'DESC',
	);

	my $matches = Lilith::AutoEscalate->evaluate(
		rules  => [ { id => 0, name => 'preview', priority => 0, stop_on_match => 0, rule => $opts{rule} } ],
		events => $events,
	);

	# resolve the rule's escalate_to tokens for display, flagging any that
	# do not name a known target
	my %target_id;
	my %target_name;
	foreach my $target ( @{ $self->escalation_targets } ) {
		$target_id{ $target->{name} } = $target->{id};
		$target_name{ $target->{id} } = $target->{name};
	}
	my @wanted;
	foreach my $action ( @{ $opts{rule}{actions} } ) {
		push( @wanted, @{ $action->{escalate_to} } );
	}
	my @targets;
	my @unknown;
	my %seen;
	foreach my $token (@wanted) {
		next if $seen{$token}++;
		if ( $token =~ /^[0-9]+$/ ) {
			defined( $target_name{$token} ) ? push( @targets, $token ) : push( @unknown, $token );
		} elsif ( defined( $target_id{$token} ) ) {
			push( @targets, $token );
		} else {
			push( @unknown, $token );
		}
	} ## end foreach my $token (@wanted)

	my @results;
	foreach my $match ( @{$matches} ) {
		my $event = $match->{event};
		push(
			@results,
			{
				id             => $event->{id},
				event_id       => $event->{event_id},
				timestamp      => $event->{ $self->_time_column($table) },
				signature      => $event->{signature},
				classification => $event->{classification},
				src_ip         => $event->{src_ip},
				dest_ip        => $event->{dest_ip},
				malscore       => $event->{malscore},
			}
		);
	} ## end foreach my $match ( @{$matches} )

	return {
		table           => $table,
		go_back_minutes => $minutes + 0,
		scanned         => scalar( @{$events} ),
		matched         => scalar(@results),
		targets         => \@targets,
		unknown_targets => \@unknown,
		matches         => \@results,
	};
} ## end sub auto_escalation_preview

=head2 auto_escalate

Evaluates the enabled auto escalation rules against recently ingested
alerts and, for each match, escalates the alert to the rule's targets
via escalate(). Each scanned alert is stamped with a auto_escalated
time so it is considered exactly once, regardless of whether a rule
matched.

The C<table> option limits processing to a single table type; when
omitted all four (suricata/sagan/cape/baphomet) are processed. baphomet is
scanned so a rule scoped to it can fire, but is not in the rule-tables default,
so a rule that names no tables never escalates baphomet.
C<go_back_minutes> bounds how far back to look for alerts that have not
yet been considered (default 5). With C<dry_run> set, no escalation is
sent and nothing is stamped; the returned summary shows what would have
happened. C<requested_by> is prefixed onto the rule name when recording
each escalation (default "auto").

Returns an array ref with one summary hash ref per table processed, each
having the keys C<table>, C<scanned>, C<rules>, C<matched>, C<dry_run>,
and C<escalations> (an array ref of per-match details).

    my $summaries = $lilith->auto_escalate(
                                            go_back_minutes => 5,
                                            dry_run         => 1,
                                           );

=cut

sub auto_escalate {
	my ( $self, %opts ) = @_;

	# baphomet is scanned alongside the others so a rule scoped to it can fire;
	# it is not in the rule-tables default, so an existing rule that named no
	# tables (defaulting to suricata/sagan/cape) never escalates baphomet.
	my @tables = defined( $opts{table} ) ? ( $opts{table} ) : ( 'suricata', 'sagan', 'cape', 'baphomet' );
	foreach my $table (@tables) {
		$self->_validate_table($table);
	}

	my $minutes = defined( $opts{go_back_minutes} ) ? $opts{go_back_minutes} : 5;
	if ( $minutes !~ /^[0-9]+$/ ) {
		die( '"' . $minutes . '" for go_back_minutes is not numeric' );
	}

	my $dry = $opts{dry_run}                                              ? 1                   : 0;
	my $by  = defined( $opts{requested_by} ) && $opts{requested_by} ne '' ? $opts{requested_by} : 'auto';

	my $dbh = $self->_escalation_dbh;

	# name -> id map so escalate_to can use target names
	my %target_id = map { $_->{name} => $_->{id} }
		@{ $dbh->selectall_arrayref( 'select id, name from escalation_targets;', { Slice => {} } ) };

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

# Processes a single table for auto_escalate: load the enabled rules scoped to
# it, gather the alerts in the window that have not been considered yet, run the
# two through Lilith::AutoEscalate, and escalate each match to the targets its
# rule names. Split out of auto_escalate so that method is just the loop over
# tables. See auto_escalate for what the options mean to a caller.
#
# Every scanned alert is stamped considered at the end (unless this is a dry
# run), matched or not, so the next run does not weigh it again. That happens
# even when there are no rules or no alerts, which is why the early return marks
# too.
#
# Args:
#
#   - dbh :: the DBI handle to work on, so every table in one auto_escalate run
#     shares a connection.
#   - table :: the short table type being scanned -- 'suricata', 'sagan',
#     'cape', or 'baphomet'.
#   - minutes :: how far back to gather alerts, in minutes. Only bounds the
#     scan; the per-alert auto_escalated stamp is what prevents a second look.
#   - dry_run :: when true, work out what would be escalated, send nothing, and
#     leave the alerts unstamped so a real run still sees them.
#   - requested_by :: who to record as having asked, e.g. 'auto'. The matching
#     rule's name is appended, giving 'auto:high malscore' in the audit trail.
#   - target_id :: hash ref of target name to target ID, so a rule may name its
#     targets rather than number them. Built once by auto_escalate.
#
# Returns: a summary hash ref for this table:
#
#     {
#       table   => 'suricata',
#       scanned => 41,           # alerts considered this run
#       rules   => 3,            # enabled rules scoped to this table
#       matched => 2,            # rule/alert pairs that matched
#       dry_run => 0,
#       escalations => [         # one entry per match, empty when none
#         {
#           rule_id   => 7,
#           rule_name => 'high malscore',
#           alert_id  => 1234,
#           target_ids      => [ 3 ],    # resolved, deduped
#           unknown_targets => [],       # names that resolved to nothing
#           status    => 'escalated',    # or dry-run, no-targets, error
#           results   => [ ... ],        # as escalate returns, when sent
#           error     => '...',          # only when status is error
#         },
#       ],
#     }
#
#     my $summary = $self->_auto_escalate_table(
#         dbh          => $dbh,
#         table        => 'suricata',
#         minutes      => 60,
#         dry_run      => 0,
#         requested_by => 'auto',
#         target_id    => { 'soc-hook' => 3 },
#     );
sub _auto_escalate_table {
	my ( $self, %opts ) = @_;

	my $dbh         = $opts{dbh};
	my $table       = $opts{table};
	my $alert_table = $table . '_alerts';
	my $time_column = $self->_time_column($table);

	# enabled rules scoped to this table
	my $rules
		= $dbh->selectall_arrayref(
			'select * from auto_escalations where enabled = true and ? = ANY(tables) order by priority asc, id asc;',
			{ Slice => {} }, $table );
	$_->{rule} = $self->_decode_jsonb_hash( $_->{rule} ) foreach @{$rules};

	# candidate alerts: not yet considered, within the window
	my $events = $dbh->selectall_arrayref(
		'select * from '
			. $alert_table
			. ' where auto_escalated is null and '
			. $time_column
			. ' >= CURRENT_TIMESTAMP - interval \''
			. ( $opts{minutes} + 0 )
			. ' minutes\' order by id asc;',
		{ Slice => {} }
	);

	my $summary = {
		table       => $table,
		scanned     => scalar( @{$events} ),
		rules       => scalar( @{$rules} ),
		matched     => 0,
		dry_run     => $opts{dry_run},
		escalations => [],
	};

	if ( !@{$rules} || !@{$events} ) {
		$self->_auto_mark( $events, $dbh, $alert_table ) if !$opts{dry_run};
		return $summary;
	}

	my $matches = Lilith::AutoEscalate->evaluate( rules => $rules, events => $events );

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
						'update auto_escalations set last_matched = now(), match_count = match_count + 1 where id = ?;'
					);
				$usth->execute( $rule->{id} );
			} ## end else [ if ($@) ]
		} ## end else [ if ( !@ids ) ]

		push( @{ $summary->{escalations} }, $entry );
	} ## end foreach my $match ( @{$matches} )

	$self->_auto_mark( $events, $dbh, $alert_table ) if !$opts{dry_run};

	return $summary;
} ## end sub _auto_escalate_table

# Stamps every scanned alert with auto_escalated = now() so it is not
# reconsidered on the next run. One update over an id array rather than a
# statement per alert, since a busy window can hold thousands.
#
# Args:
#
#   - $events :: array ref of the alert rows just scanned, each a hash ref with
#     at least an 'id'. Matched or not -- being looked at is what counts.
#   - $dbh :: the DBI handle to run the update on.
#   - $alert_table :: the real table name to update, e.g. 'suricata_alerts'.
#     Built by the caller from the short type, never from user input.
#
# Returns: 1 once the update has run, or undef when $events was empty and there
# was nothing to stamp.
#
#     $self->_auto_mark( \@events, $dbh, 'suricata_alerts' );
sub _auto_mark {
	my ( $self, $events, $dbh, $alert_table ) = @_;

	return if !@{$events};

	my @ids = map { $_->{id} } @{$events};

	my $sth = $dbh->prepare( 'update ' . $alert_table . ' set auto_escalated = now() where id = ANY(?::bigint[]);' );
	$sth->execute( $self->_pg_text_array( \@ids ) );

	return 1;
} ## end sub _auto_mark

# Decodes a jsonb column into a hash ref. DBD::Pg may hand jsonb back already
# inflated or as JSON text depending on how the row was fetched; both are
# accepted so callers need not care which. Used for every jsonb-holding column
# read in here: an auto escalation's rule, an escalation target's config, and
# the shodan/cvedb caches' raw responses.
#
# Args:
#
#   - $value :: the column as read from the database -- a hash ref (already
#     inflated), a JSON string, or undef.
#
# Returns: the decoded hash ref. Undecodable or missing JSON returns an empty
# hash ref rather than dying, so one corrupt row cannot stop a whole run; a
# rule with no match tree simply never fires, and a target with a corrupt
# config fails at send time with a missing-field error from its type instead
# of taking down whatever listed it.
#
#     my $rule = $self->_decode_jsonb_hash( $row->{rule} );
sub _decode_jsonb_hash {
	my ( $self, $value ) = @_;

	return $value if ref($value) eq 'HASH';

	my $decoded;
	if ( defined($value) ) {
		eval { $decoded = decode_json($value); };
	}

	return ref($decoded) eq 'HASH' ? $decoded : {};
} ## end sub _decode_jsonb_hash

# Decodes a tables column into an array ref, accepting either a expanded array
# ref (DBD::Pg default) or a raw PostgreSQL array literal. The literal form is
# parsed by hand rather than with a JSON decode: Postgres writes {a,b} with
# optional double quotes, which is not JSON.
#
# Args:
#
#   - $tables :: the tables column as read from the database -- an array ref
#     (already expanded), a literal such as '{suricata,sagan}' or
#     '{"suricata","sagan"}', or undef.
#
# Returns: an array ref of short table type names, e.g. [ 'suricata', 'sagan' ].
# undef, an empty literal, or anything unrecognised gives an empty array ref;
# _auto_check_tables is what turns that into the default set.
#
#     $self->_auto_decode_tables('{suricata,cape}');    # [ 'suricata', 'cape' ]
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
	} ## end if ( defined($tables) && !ref($tables) )

	return [];
} ## end sub _auto_decode_tables

# validates a tables list against the known table types, returning a de-duped
# array ref. baphomet is a valid table a rule may name, but it is deliberately
# left out of the default (suricata/sagan/cape) returned when none are given, so
# escalating baphomet stays opt-in: a rule must name it explicitly.
#
# Args:
#
#   - $tables :: array ref of short table type names a rule is scoped to, or
#     undef/[] for none given.
#
# Returns: an array ref of checked table types with duplicates removed and the
# caller's order kept. An empty or missing list returns the default
# [ 'suricata', 'sagan', 'cape' ]. Dies with '"$table" is not a known table
# type; valid: suricata, sagan, cape, baphomet' on the first bad entry.
#
#     $self->_auto_check_tables( [ 'cape', 'cape' ] );    # [ 'cape' ]
#     $self->_auto_check_tables(undef);    # [ 'suricata', 'sagan', 'cape' ]
sub _auto_check_tables {
	my ( $self, $tables ) = @_;

	if ( ref($tables) ne 'ARRAY' || !@{$tables} ) {
		return [ 'suricata', 'sagan', 'cape' ];
	}

	my %seen;
	my @out;
	foreach my $table ( @{$tables} ) {
		if ( !defined($table) || !$KNOWN_TABLE_TYPES{$table} ) {
			die(      '"'
					. ( defined($table) ? $table : 'undef' )
					. '" is not a known table type; valid: suricata, sagan, cape, baphomet' );
		}
		push( @out, $table ) if !$seen{$table}++;
	}

	return \@out;
} ## end sub _auto_check_tables

# Builds a PostgreSQL array literal from an array ref, quoting each element.
# Every element is quoted whether it needs it or not, and embedded quotes and
# backslashes are escaped, so a value carrying a comma or a brace cannot break
# out of its element. The result is bound as a single value and cast on the
# Postgres side, e.g. ?::bigint[].
#
# Args:
#
#   - $list :: array ref of elements to render. Any scalar type -- callers pass
#     row IDs, CIDR strings, and instance globs through the same routine. An
#     undef element becomes an empty string rather than NULL.
#
# Returns: the array literal as a string, always braced, e.g. '{"1","2"}'. An
# empty list gives '{}', which casts to an empty array rather than NULL.
#
#     $self->_pg_text_array( [ 1, 2 ] );    # '{"1","2"}'
#     $sth->execute( $self->_pg_text_array( \@ids ) );
sub _pg_text_array {
	my ( $self, $list ) = @_;

	my @items = map {
		my $item = defined($_) ? $_ : '';
		$item =~ s/(["\\])/\\$1/g;
		'"' . $item . '"';
	} @{$list};

	return '{' . join( ',', @items ) . '}';
} ## end sub _pg_text_array

# A raw DBI handle on this object's connection details, for the parts that talk
# to the database directly rather than through DBIx::Class -- escalation, auto
# escalation, the receiver keys, and the dashboards. Named for escalation
# because that is what first needed it; it has since become the general handle
# for the hand written SQL in here. Shared through connect_cached so the ingest
# daemon does not open a connection per statement.
#
# Args: none.
#
# Returns: a DBI database handle with RaiseError set, so a failed statement
# dies rather than returning undef. Dies with 'DBI->connect_cached failure... '
# and the DBI error when the database cannot be reached.
#
#     my $dbh = $self->_escalation_dbh;
#     $dbh->prepare('delete from receiver_apikeys where id = ?;')->execute($id);
sub _escalation_dbh {
	my ($self) = @_;

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass}, { RaiseError => 1 } ); };
	if ( $@ || !$dbh ) {
		die( 'DBI->connect_cached failure... ' . $@ );
	}

	return $dbh;
} ## end sub _escalation_dbh

=head2 stats

    my $stats = $lilith->stats;

Returns a L<Lilith::Stats> object built from this object's connection details,
for the dashboard's aggregation queries.

=cut

sub stats {
	my ($self) = @_;
	require Lilith::Stats;
	return Lilith::Stats->new( lilith => $self );
}

=head2 dashboard_get

    my $board = $lilith->dashboard_get( name => 'default' );
    my $board = $lilith->dashboard_get;    # the default board

Returns a saved dashboard board as
C<< { name, layout, settings, is_default } >>, where C<layout> is the decoded
JSON array of widget placements and C<settings> is the decoded JSON hash of that
board's view state (table, go_back_minutes, show_gpcd). Returns C<undef> when no
board of that name exists. With no (or an empty) C<name>, returns the board
flagged C<is_default> -- the one loaded first, which is not necessarily the board
literally named C<default> once another has been set default.

=cut

sub dashboard_get {
	my ( $self, %opts ) = @_;

	my $name = defined $opts{name} && $opts{name} ne '' ? $opts{name} : undef;

	my $dbh = $self->_escalation_dbh;
	my $sth;
	if ( defined $name ) {
		$sth = $dbh->prepare('select name, layout, settings, is_default from dashboards where name = ?');
		$sth->execute($name);
	} else {
		# No name asked -> the board flagged default (loaded first); fall back to
		# the lowest id so a database with no default flagged still returns a board.
		$sth = $dbh->prepare(
			'select name, layout, settings, is_default from dashboards order by is_default desc, id asc limit 1');
		$sth->execute;
	}
	my $row = $sth->fetchrow_hashref;
	return undef unless $row;

	my $layout   = eval { decode_json( $row->{layout} ) };
	my $settings = eval { decode_json( $row->{settings} ) };
	$row->{layout}     = ( ref $layout eq 'ARRAY' )  ? $layout   : [];
	$row->{settings}   = ( ref $settings eq 'HASH' ) ? $settings : {};
	$row->{is_default} = $row->{is_default}          ? 1         : 0;

	return $row;
} ## end sub dashboard_get

=head2 dashboard_save

    $lilith->dashboard_save( name => 'default', layout => \@placements, settings => \%settings );

Upserts a dashboard board by name, storing C<layout> (an array ref of widget
placements) and C<settings> (a hash ref of the board's view state) as JSON.
C<name> defaults to C<default>; a missing C<layout>/C<settings> stores an empty
array/hash.

=cut

sub dashboard_save {
	my ( $self, %opts ) = @_;

	my $name          = defined $opts{name} && $opts{name} ne '' ? $opts{name}     : 'default';
	my $layout        = ( ref $opts{layout} eq 'ARRAY' )         ? $opts{layout}   : [];
	my $settings      = ( ref $opts{settings} eq 'HASH' )        ? $opts{settings} : {};
	my $layout_json   = encode_json($layout);
	my $settings_json = encode_json($settings);

	my $dbh = $self->_escalation_dbh;
	my $sth
		= $dbh->prepare(
			  'insert into dashboards (name, layout, settings, updated) values (?, ?::jsonb, ?::jsonb, now())'
			. ' on conflict (name) do update set layout = excluded.layout,'
			. ' settings = excluded.settings, updated = now()' );
	$sth->execute( $name, $layout_json, $settings_json );

	return 1;
} ## end sub dashboard_save

=head2 dashboard_list

    my $boards = $lilith->dashboard_list;

Returns all dashboard boards as an array ref of
C<< { name, is_default, updated } >>, ordered default-first then by name -- the
list that drives the dashboard picker.

=cut

sub dashboard_list {
	my ($self) = @_;

	my $dbh = $self->_escalation_dbh;
	my $rows
		= $dbh->selectall_arrayref(
			'select name, is_default, updated from dashboards order by is_default desc, name asc',
			{ Slice => {} } );
	for my $row (@$rows) { $row->{is_default} = $row->{is_default} ? 1 : 0; }

	return $rows;
} ## end sub dashboard_list

=head2 dashboard_delete

    $lilith->dashboard_delete( name => 'scratch' );

Deletes the named board, returning the number of rows removed (0 if no such
board). Callers are responsible for refusing to delete the default or last
board; this is the raw delete.

=cut

sub dashboard_delete {
	my ( $self, %opts ) = @_;

	my $name = defined $opts{name} ? $opts{name} : '';
	return 0 unless $name ne '';

	my $dbh = $self->_escalation_dbh;
	return $dbh->do( 'delete from dashboards where name = ?', undef, $name ) + 0;
}

=head2 dashboard_rename

    $lilith->dashboard_rename( name => 'old', to => 'new' );

Renames a board, returning the number of rows changed (0 if the source board
does not exist). A collision with an existing name raises (the unique
constraint), so callers should check first.

=cut

sub dashboard_rename {
	my ( $self, %opts ) = @_;

	my $name = defined $opts{name} ? $opts{name} : '';
	my $to   = defined $opts{to}   ? $opts{to}   : '';
	return 0 unless $name ne '' && $to ne '';

	my $dbh = $self->_escalation_dbh;
	return $dbh->do( 'update dashboards set name = ?, updated = now() where name = ?', undef, $to, $name ) + 0;
} ## end sub dashboard_rename

=head2 dashboard_set_default

    $lilith->dashboard_set_default( name => 'ops' );

Makes the named board the default (the one loaded first). Clears the flag from
every other board and sets it on this one inside a transaction, so there is
always exactly one default. Returns the number of rows set default (0 if no such
board).

=cut

sub dashboard_set_default {
	my ( $self, %opts ) = @_;

	my $name = defined $opts{name} ? $opts{name} : '';
	return 0 unless $name ne '';

	my $dbh = $self->_escalation_dbh;

	my $set = 0;
	$dbh->begin_work;
	eval {
		$dbh->do('update dashboards set is_default = FALSE where is_default');
		$set = $dbh->do( 'update dashboards set is_default = TRUE where name = ?', undef, $name ) + 0;
		$dbh->commit;
		1;
	} or do {
		my $err = $@;
		eval { $dbh->rollback };
		die $err;
	};

	return $set;
} ## end sub dashboard_set_default

=head2 shodan_cache_get

Shodan's last answer for an address, as it arrived, or undef when there is no
usable entry. Backs the web UI's IP info modal; see C<shodan_cache_ttl> in the
config.

Three things count as no entry, and all three return undef: no row at all, a
row older than the TTL, and a row from a different tier than the one now
configured -- the keyless summary and the keyed host API differ in depth, so a
row from the lesser one must not stand in for the greater.

Takes C<ip> (v4 or v6), C<source> (C<api> or C<internetdb>), and C<ttl> in
seconds. Returns the decoded response as a hash ref; an empty hash ref is a
real answer meaning Shodan has never crawled the address, which is why the
undef/empty distinction matters to the caller. Dies only if the database itself
cannot be reached.

    my $raw = $lilith->shodan_cache_get( '192.0.2.10', 'api', 86400 );

=cut

sub shodan_cache_get {
	my ( $self, $ip, $source, $ttl ) = @_;

	return undef unless defined $ip && $ip ne '';
	return undef unless defined $ttl && $ttl =~ /^[0-9]+$/ && $ttl > 0;

	my $dbh = $self->_escalation_dbh;
	my $sth = $dbh->prepare( 'select raw from shodan_cache'
			. ' where ip = ?::inet and source = ? and fetched > now() - (? || \' seconds\')::interval;' );
	$sth->execute( $ip, $source, $ttl );

	my $row = $sth->fetchrow_hashref;
	return undef unless $row;

	# jsonb comes back inflated or as text depending on how the row was
	# fetched, the same as the escalation and auto escalation columns.
	return $self->_decode_jsonb_hash( $row->{raw} );
} ## end sub shodan_cache_get

=head2 shodan_cache_put

Store Shodan's answer for an address, replacing whatever was held for it, and
prune the entries that have since expired.

The response is stored as it arrived rather than in the form the modal renders,
so that changing how it is rendered does not strand every cached row on the old
shape. The columns beside it -- ports, tags, cpes, vulns, max_cvss, hostnames,
last_update, and (schema version 17) os, org, isp, and asn -- are the queryable
projection of that response and are passed in already worked out, since the
caller has just normalized it and would only be doing the same work twice. The
version-17 four are written only where the schema has them, so this keeps
working against a database still on 15 or 16.

Takes:

- C<ip> :: the address the answer is for, v4 or v6. Required.
- C<source> :: which tier answered, C<api> or C<internetdb>. Required.
- C<raw> :: the response as a hash ref, as it arrived. An empty hash ref is
  stored as C<found = false>, which is the point -- an address Shodan has never
  crawled is the lookup most worth not repeating.
- C<info> :: the normalized form, as the web UI's C<_shodan_gather> returns it.
  Only its ports/tags/cpes/vulns/hostnames/last_update are read.
- C<ttl> :: the freshness window in seconds. Rows older than it are deleted on
  the way through, which is the whole of the cache's housekeeping.

Returns 1. Dies if the database cannot be reached or the statement fails.

    $lilith->shodan_cache_put(
        ip => '192.0.2.10', source => 'api',
        raw => $raw, info => $info, ttl => 86400,
    );

=cut

sub shodan_cache_put {
	my ( $self, %opts ) = @_;

	my $ip = defined $opts{ip} ? $opts{ip} : '';
	die('shodan cache: an ip is required') if $ip eq '';

	my $raw  = ref $opts{raw} eq 'HASH'  ? $opts{raw}  : {};
	my $info = ref $opts{info} eq 'HASH' ? $opts{info} : {};

	# The worst score of the vulnerabilities that carry one, which is what a
	# "this host has something serious" read wants and cannot be got from the
	# CVE ids alone. Null when nothing scored -- the keyless tier never does.
	my $max_cvss;
	for my $vuln ( @{ ref $info->{vulns} eq 'ARRAY' ? $info->{vulns} : [] } ) {
		next unless ref $vuln eq 'HASH';
		my $cvss = $vuln->{cvss};
		next unless defined $cvss && $cvss =~ /^[0-9.]+$/;
		$max_cvss = $cvss if !defined($max_cvss) || $cvss > $max_cvss;
	}

	# Shodan reports its own crawl time as a naive stamp in UTC, so it is cast
	# with the zone named rather than left to whatever the server is set to.
	my $last_update = defined $info->{last_update} && $info->{last_update} ne '' ? $info->{last_update} : undef;

	my $dbh = $self->_escalation_dbh;

	# The version-17 columns are probed for rather than assumed, and one probe
	# answers for all four, since they shipped together -- remembered for the
	# life of the object, since a shodan_cache run calls this once per address
	# and the answer changes only when the schema is migrated. The keyless
	# tier's empty strings are stored as NULL, so "the tier sent nothing" and
	# "never refreshed since the upgrade" read the same way.
	my $has_host_columns = $self->{_shodan_cache_host_columns};
	$has_host_columns = $self->{_shodan_cache_host_columns} = column_exists( $dbh, 'shodan_cache', 'os' )
		if !defined $has_host_columns;
	my @host_columns = qw( os org isp asn );
	my @host_values
		= $has_host_columns
		? map { defined $info->{$_} && !ref $info->{$_} && $info->{$_} ne '' ? $info->{$_} : undef } @host_columns
		: ();

	my $sth
		= $dbh->prepare( 'insert into shodan_cache'
			. ' ( ip, source, found, fetched, last_update, ports, tags, cpes, vulns, max_cvss, hostnames'
			. ( $has_host_columns ? ', ' . join( ', ', @host_columns ) : '' )
			. ', raw )'
			. ' values ( ?::inet, ?, ?, now(), (?::timestamp at time zone \'UTC\'), ?::integer[], ?::varchar[],'
			. ' ?::varchar[], ?::varchar[], ?, ?::varchar[]'
			. ( $has_host_columns ? ', ?, ?, ?, ?' : '' )
			. ', ?::jsonb )'
			. ' on conflict (ip) do update set'
			. ' source = excluded.source, found = excluded.found, fetched = excluded.fetched,'
			. ' last_update = excluded.last_update, ports = excluded.ports, tags = excluded.tags,'
			. ' cpes = excluded.cpes, vulns = excluded.vulns, max_cvss = excluded.max_cvss,'
			. ' hostnames = excluded.hostnames'
			. ( $has_host_columns ? join( '', map { ", $_ = excluded.$_" } @host_columns ) : '' )
			. ', raw = excluded.raw;' );
	$sth->execute(
		$ip,
		( defined $opts{source} ? $opts{source} : '' ),
		( keys %{$raw}          ? 1             : 0 ),
		$last_update,
		$self->_pg_text_array( ref $info->{ports} eq 'ARRAY' ? $info->{ports} : [] ),
		$self->_pg_text_array( ref $info->{tags} eq 'ARRAY'  ? $info->{tags}  : [] ),
		$self->_pg_text_array( ref $info->{cpes} eq 'ARRAY'  ? $info->{cpes}  : [] ),
		$self->_pg_text_array(
			[
				map  { $_->{cve} }
				grep { ref eq 'HASH' && defined $_->{cve} } @{ ref $info->{vulns} eq 'ARRAY' ? $info->{vulns} : [] }
			]
		),
		$max_cvss,
		$self->_pg_text_array( ref $info->{hostnames} eq 'ARRAY' ? $info->{hostnames} : [] ),
		@host_values,
		encode_json($raw),
	);

	# A row past the TTL is refetched on its next read, so keeping it buys
	# nothing; clearing them here is cheaper than a cron for a table this size.
	my $ttl = defined $opts{ttl} && $opts{ttl} =~ /^[0-9]+$/ ? $opts{ttl} : 0;
	if ( $ttl > 0 ) {
		$dbh->do( 'delete from shodan_cache where fetched < now() - (? || \' seconds\')::interval;', undef, $ttl );
	}

	return 1;
} ## end sub shodan_cache_put

=head2 alert_ips

The distinct addresses named by the alerts ingested in a window, from every
alert table's C<src_ip> and C<dest_ip>. What C<lilith shodan_cache> works
through.

Distinct across the whole set rather than per table, so an address on five
hundred alerts is one entry -- the caller is about to do something per address
that costs a network round trip.

Takes:

- C<go_back_seconds> :: how far back to read. C<0> means no time bound at all,
  for a first pass over a database that has been running a while. Default 180.
- C<tables> :: array ref of which alert tables to read, from C<suricata>,
  C<sagan>, C<cape>, and C<baphomet>. All four by default.

Returns an array ref of addresses as strings, sorted, with any netmask stripped
so they compare against what C<shodan_cache> stores. Dies on an unknown table
name or a non-numeric window.

    my $ips = $lilith->alert_ips( go_back_seconds => 900 );

=cut

sub alert_ips {
	my ( $self, %opts ) = @_;

	my $seconds = defined $opts{go_back_seconds} ? $opts{go_back_seconds} : 180;
	die( '"' . $seconds . '" for go_back_seconds is not numeric' ) if $seconds !~ /^[0-9]+$/;

	my @tables = ref $opts{tables} eq 'ARRAY' && @{ $opts{tables} } ? @{ $opts{tables} } : keys %KNOWN_TABLE_TYPES;
	for my $table (@tables) {
		die( '"' . $table . '" is not a known table type; valid: suricata, sagan, cape, baphomet' )
			unless $KNOWN_TABLE_TYPES{$table};
	}

	my $dbh = $self->_escalation_dbh;

	my %ips;
	for my $table ( sort @tables ) {
		# CAPE is windowed on its completion time rather than an ingest time,
		# the same as everywhere else that reads it -- and that time can lag,
		# which is the reason to run this with a window wider than its interval.
		my $time_column = $self->_time_column($table);

		# host() strips any netmask, so the values line up with the keys
		# shodan_cache holds. Both columns in one pass over the window.
		my $sql
			= 'select distinct host(ip) as ip from ('
			. ' select src_ip as ip from '
			. $table
			. '_alerts where src_ip is not null'
			. ( $seconds ? ' and ' . $time_column . ' >= now() - (? || \' seconds\')::interval' : '' )
			. ' union all select dest_ip as ip from '
			. $table
			. '_alerts where dest_ip is not null'
			. ( $seconds ? ' and ' . $time_column . ' >= now() - (? || \' seconds\')::interval' : '' )
			. ' ) as both_ends;';

		foreach
			my $row ( @{ $dbh->selectall_arrayref( $sql, { Slice => {} }, $seconds ? ( $seconds, $seconds ) : () ) } )
		{
			$ips{ $row->{ip} } = 1 if defined $row->{ip} && $row->{ip} ne '';
		}
	} ## end for my $table ( sort @tables )

	return [ sort keys %ips ];
} ## end sub alert_ips

=head2 shodan_cache_badges

The cached summary for a set of addresses at once, for the badges the web UI
puts on its results tables' IP cells.

One statement for the whole page rather than one per address: a page of results
can name a hundred addresses, and this runs on every render of it. Nothing is
fetched -- an address with no fresh entry is simply absent from the result, and
its cell gets no badges.

Takes C<ips> (array ref of addresses), C<source> (C<api> or C<internetdb>), and
C<ttl> in seconds. Returns a hash ref keyed by address:

    {
      '192.0.2.10' => {
        ports    => [ 22, 443 ],
        tags     => [ 'cloud' ],
        vulns    => 12,      # how many -- the cell badge shows a count
        vuln_ids => [ 'CVE-2021-44228', ... ],   # which -- for the CVE-match
                                                 # check against a rule's ids
        max_cvss => 9.8,     # undef when nothing anywhere scored them
      },
    }

C<max_cvss> is the worst score Shodan itself sent, and when it sent none --
the keyless tier never does -- the worst score the C<cvedb_cache> table holds
for the row's CVEs, which is what colors the CVE badge on an InternetDB-only
install once C<lilith cvedb_cache> has run.

Addresses with no fresh entry are absent rather than present and empty, so the
caller can tell "nothing cached" from "cached, and Shodan knows nothing". Dies
only if the database itself cannot be reached.

    my $badges = $lilith->shodan_cache_badges(
        ips => [ '192.0.2.10', '192.0.2.11' ], source => 'api', ttl => 2592000 );

=cut

sub shodan_cache_badges {
	my ( $self, %opts ) = @_;

	my $ips = ref $opts{ips} eq 'ARRAY' ? $opts{ips} : [];
	my $ttl = defined $opts{ttl} && $opts{ttl} =~ /^[0-9]+$/ ? $opts{ttl} : 0;
	return {} unless @{$ips} && $ttl > 0;

	my $dbh = $self->_escalation_dbh;

	my $sth
		= $dbh->prepare( 'select host(ip) as ip, ports, tags, '
			. $self->_shodan_max_cvss_expr($dbh)
			. ' as max_cvss'
			. ', vulns, coalesce(array_length(vulns, 1), 0) as vuln_count from shodan_cache'
			. ' where ip = any(?::inet[]) and source = ? and fetched > now() - (? || \' seconds\')::interval;' );
	$sth->execute( $self->_pg_text_array($ips), ( defined $opts{source} ? $opts{source} : '' ), $ttl );

	my %badges;
	while ( my $row = $sth->fetchrow_hashref ) {
		$badges{ $row->{ip} } = {
			ports    => ( ref $row->{ports} eq 'ARRAY' ? $row->{ports} : [] ),
			tags     => ( ref $row->{tags} eq 'ARRAY'  ? $row->{tags}  : [] ),
			vulns    => ( $row->{vuln_count} || 0 ),
			vuln_ids => ( ref $row->{vulns} eq 'ARRAY' ? $row->{vulns} : [] ),
			max_cvss => $row->{max_cvss},
		};
	}

	return \%badges;
} ## end sub shodan_cache_badges

# The SQL expression for the worst CVSS of a shodan_cache row's CVEs. The
# keyless tier stores no scores, so its rows hold a null max_cvss however bad
# their CVEs are; when the cvedb_cache table is present (schema version 16)
# the worst score it holds for the row's CVEs stands in. Checked with
# to_regclass rather than assumed so a database still on an older schema keeps
# working with the bare column.
#
# One definition shared by the badges read and the shodan_*_cvss search
# filters, so a filter matches what the badge it filters on shows.
#
# Args:
#
#   - $dbh :: the handle to probe for cvedb_cache with, from whichever
#     connection the caller is already on.
#
# Returns: the expression as a string, referencing max_cvss and vulns
# unqualified -- so it is only usable where those resolve to shodan_cache.
#
#     my $expr = $self->_shodan_max_cvss_expr($dbh);
sub _shodan_max_cvss_expr {
	my ( $self, $dbh ) = @_;

	my ($has_cvedb) = $dbh->selectrow_array(q{select to_regclass('cvedb_cache')});
	return $has_cvedb
		? 'coalesce(max_cvss, (select max(cvedb.cvss) from unnest(vulns) as vuln_id'
		. ' join cvedb_cache as cvedb on cvedb.cve = vuln_id))'
		: 'max_cvss';
}

=head2 shodan_cache_info

The cached Shodan entries for a handful of addresses, whole: the response as it
arrived plus the row's own bookkeeping. What the event view's per-end summary
renders from -- the badges read (C<shodan_cache_badges>) carries only the
queryable projection, and this is for the one page that wants the rest (OS,
hostnames, per-CVE scores) without a network lookup.

Takes C<ips> (array ref of addresses -- an event has two ends, so this is built
for few rather than a page's hundred), C<source> (C<api> or C<internetdb>), and
C<ttl> in seconds. The same freshness rule as every other cache read: a row
from the other tier or older than the TTL is a miss.

Returns a hash ref keyed by address:

    {
      '192.0.2.10' => {
        found       => 1,      # 0 when Shodan has never crawled it
        age_seconds => 93600,  # since Lilith fetched it, for a "cached 1d ago"
        raw         => {...},  # the response as it arrived; {} when found is 0
      },
    }

Addresses with no fresh entry are absent rather than present and empty, the
same as the badges read. Dies only if the database itself cannot be reached.

    my $info = $lilith->shodan_cache_info(
        ips => [ '192.0.2.10', '192.0.2.11' ], source => 'api', ttl => 2592000 );

=cut

sub shodan_cache_info {
	my ( $self, %opts ) = @_;

	my $ips = ref $opts{ips} eq 'ARRAY' ? $opts{ips} : [];
	my $ttl = defined $opts{ttl} && $opts{ttl} =~ /^[0-9]+$/ ? $opts{ttl} : 0;
	return {} unless @{$ips} && $ttl > 0;

	my $dbh = $self->_escalation_dbh;
	my $sth
		= $dbh->prepare( 'select host(ip) as ip, found,'
			. ' extract(epoch from now() - fetched)::bigint as age_seconds, raw from shodan_cache'
			. ' where ip = any(?::inet[]) and source = ? and fetched > now() - (? || \' seconds\')::interval;' );
	$sth->execute( $self->_pg_text_array($ips), ( defined $opts{source} ? $opts{source} : '' ), $ttl );

	my %info;
	while ( my $row = $sth->fetchrow_hashref ) {
		# jsonb comes back inflated or as text depending on how the row was
		# fetched, the same as shodan_cache_get.
		my $raw = $self->_decode_jsonb_hash( $row->{raw} );
		$info{ $row->{ip} } = {
			found       => ( $row->{found}               ? 1                   : 0 ),
			age_seconds => ( defined $row->{age_seconds} ? $row->{age_seconds} : 0 ),
			raw         => ( ref $raw eq 'HASH'          ? $raw                : {} ),
		};
	} ## end while ( my $row = $sth->fetchrow_hashref )

	return \%info;
} ## end sub shodan_cache_info

=head2 shodan_cache_cves

Every distinct CVE id named by the C<shodan_cache> rows fetched in a window,
sorted. What C<lilith cvedb_cache> works through: a newly cached or freshly
refreshed address is what introduces ids worth checking the CVEDB cache for,
and the window is what keeps a run on a timer from rescanning every row the
table holds to find them.

Takes:

- C<go_back_seconds> :: how far back to read, against each row's C<fetched>
  time. C<0> means no bound at all, for a first pass over a cache that has
  been filling for a while. Default 360 -- twice the C<shodan_cache>
  command's own default window, so a run of this sees everything a run of
  that cached between the two, with room to spare.

Returns an array ref of ids as strings. The ids are returned as stored --
Shodan's are already canonical -- and it is the caller's business to drop
anything L<Lilith::CVEDB>'s C<is_cve_id> rejects before asking the network
about it. Dies on a non-numeric window, or if the database cannot be reached.

    my $cves = $lilith->shodan_cache_cves( go_back_seconds => 1200 );

=cut

sub shodan_cache_cves {
	my ( $self, %opts ) = @_;

	my $seconds = defined $opts{go_back_seconds} ? $opts{go_back_seconds} : 360;
	die( '"' . $seconds . '" for go_back_seconds is not numeric' ) if $seconds !~ /^[0-9]+$/;

	my $dbh  = $self->_escalation_dbh;
	my $rows = $dbh->selectall_arrayref(
		'select distinct unnest(vulns) as cve from shodan_cache'
			. ( $seconds ? ' where fetched >= now() - (? || \' seconds\')::interval' : '' )
			. ' order by cve;',
		{ Slice => {} },
		$seconds ? ($seconds) : ()
	);

	return [ grep { defined($_) && $_ ne '' } map { $_->{cve} } @{$rows} ];
} ## end sub shodan_cache_cves

=head2 cvedb_cache_put

Store CVEDB's answer for a CVE, replacing whatever was held for it.

The response is stored as it arrived rather than in the form the web renders,
for the same reason C<shodan_cache_put> does it that way. The columns beside
it -- cvss, epss, kev, ransomware -- are the queryable projection of that
response and are passed in already worked out.

Unlike C<shodan_cache_put> nothing is pruned on the way through: a stale row
here is still served (CVE detail only firms up), so age is never a reason to
drop one.

Takes:

- C<cve> :: the id the answer is for. Required.
- C<raw> :: the response as a hash ref, as it arrived from
  C<Lilith::CVEDB::fetch>. An empty hash ref is stored as C<found = false>,
  so an id CVEDB has nothing on is not re-asked every run.
- C<info> :: the normalized form, as C<Lilith::CVEDB::normalize> returns it.
  Only its cvss/epss/kev/ransomware are read.

Returns 1. Dies if the database cannot be reached or the statement fails.

    $lilith->cvedb_cache_put( cve => 'CVE-2021-44228', raw => $raw, info => $info );

=cut

sub cvedb_cache_put {
	my ( $self, %opts ) = @_;

	my $cve = defined $opts{cve} ? $opts{cve} : '';
	die('cvedb cache: a cve is required') if $cve eq '';

	my $raw  = ref $opts{raw} eq 'HASH'  ? $opts{raw}  : {};
	my $info = ref $opts{info} eq 'HASH' ? $opts{info} : {};

	my $cvss = ( defined $info->{cvss} && $info->{cvss} =~ /^[0-9.]+$/ ) ? $info->{cvss} + 0 : undef;
	my $epss = ( defined $info->{epss} && $info->{epss} =~ /^[0-9.]+$/ ) ? $info->{epss} + 0 : undef;

	my $dbh = $self->_escalation_dbh;
	my $sth
		= $dbh->prepare( 'insert into cvedb_cache ( cve, found, fetched, cvss, epss, kev, ransomware, raw )'
			. ' values ( ?, ?, now(), ?, ?, ?, ?, ?::jsonb )'
			. ' on conflict (cve) do update set'
			. ' found = excluded.found, fetched = excluded.fetched, cvss = excluded.cvss,'
			. ' epss = excluded.epss, kev = excluded.kev, ransomware = excluded.ransomware, raw = excluded.raw;' );
	$sth->execute(
		$cve, ( keys %{$raw} ? 1 : 0 ),
		$cvss, $epss,
		( $info->{kev}        ? 1 : 0 ),
		( $info->{ransomware} ? 1 : 0 ),
		encode_json($raw),
	);

	return 1;
} ## end sub cvedb_cache_put

=head2 cvedb_cache_annotations

The cached CVEDB summary for a set of CVE ids at once, for annotating
wherever the web UI shows them -- one statement for a whole modal or page.

Served however old the rows are: CVE detail only firms up, so a stale answer
beats an empty chip, and freshness is C<lilith cvedb_cache>'s business rather
than the reader's.

Takes C<cves> (array ref of ids). Returns a hash ref keyed by id:

    {
      'CVE-2021-44228' => {
        cvss       => 9.8,          # undef when never scored
        epss       => 0.94321,      # undef when absent
        kev        => 1,
        ransomware => 1,
        summary    => '...',        # '' when there is none
        found      => 1,            # 0 for a cached "CVEDB has nothing"
      },
    }

Ids with no row at all are absent rather than present and empty, so the
caller can tell "never asked" from "asked, nothing known". Dies only if the
database itself cannot be reached.

    my $notes = $lilith->cvedb_cache_annotations( cves => [ 'CVE-2021-44228' ] );

=cut

sub cvedb_cache_annotations {
	my ( $self, %opts ) = @_;

	my $cves = ref $opts{cves} eq 'ARRAY' ? $opts{cves} : [];
	return {} unless @{$cves};

	my $dbh = $self->_escalation_dbh;
	my $sth
		= $dbh->prepare( 'select cve, found, cvss, epss, kev, ransomware,'
			. ' coalesce(raw->>\'summary\', \'\') as summary'
			. ' from cvedb_cache where cve = any(?::varchar[]);' );
	$sth->execute( $self->_pg_text_array($cves) );

	my %annotations;
	while ( my $row = $sth->fetchrow_hashref ) {
		$annotations{ $row->{cve} } = {
			cvss       => $row->{cvss},
			epss       => $row->{epss},
			kev        => ( $row->{kev}             ? 1               : 0 ),
			ransomware => ( $row->{ransomware}      ? 1               : 0 ),
			summary    => ( defined $row->{summary} ? $row->{summary} : '' ),
			found      => ( $row->{found}           ? 1               : 0 ),
		};
	} ## end while ( my $row = $sth->fetchrow_hashref )

	return \%annotations;
} ## end sub cvedb_cache_annotations

=head2 cvedb_cache_stale

Which of a set of CVE ids are due a CVEDB lookup: the ones with no row at
all, followed by the ones whose row is older than the refresh window, oldest
first. What C<lilith cvedb_cache> uses to decide what a run fetches -- ordered
so that when a run is capped by C<--limit>, what it spends its lookups on is
what the cache knows least about.

Takes:

- C<cves> :: array ref of ids to consider.
- C<ttl> :: the refresh window in seconds. A row older than this is due;
  nothing here deletes it, since a stale row is still served until its
  replacement lands.

Returns an array ref of ids. Dies on a non-numeric C<ttl>, or if the database
cannot be reached.

    my $wanted = $lilith->cvedb_cache_stale( cves => $cves, ttl => 604800 );

=cut

sub cvedb_cache_stale {
	my ( $self, %opts ) = @_;

	my $ttl = defined $opts{ttl} ? $opts{ttl} : '';
	die( '"' . $ttl . '" for ttl is not numeric' ) if $ttl !~ /^[0-9]+$/;

	my $cves = ref $opts{cves} eq 'ARRAY' ? $opts{cves} : [];
	return [] unless @{$cves};

	my $dbh = $self->_escalation_dbh;
	my $sth = $dbh->prepare( 'select cve, extract(epoch from (now() - fetched)) as age'
			. ' from cvedb_cache where cve = any(?::varchar[]);' );
	$sth->execute( $self->_pg_text_array($cves) );

	my %age;
	while ( my $row = $sth->fetchrow_hashref ) {
		$age{ $row->{cve} } = $row->{age};
	}

	my @missing = grep { !exists $age{$_} } @{$cves};
	my @stale   = sort { $age{$b} <=> $age{$a} } grep { exists $age{$_} && $age{$_} > $ttl } @{$cves};

	return [ @missing, @stale ];
} ## end sub cvedb_cache_stale

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


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Lilith
