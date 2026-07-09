# Lilith

Lilith reads in EVE files from Suricata and Sagan into PostgreSQL.

From there that data can then be searched and information on specific
events fetched.

## Intalation

### Debian

```
apt-get install zlib1g-dev cpanminus libdbi-perl libdbix-class-perl \
 libdata-dumper-perl libdigest-sha-perl libfile-slurp-perl libjson-perl \
 libnet-server-perl libpoe-perl libtoml-perl
cpanm Lilith
```

### FreeBSD

```
pkg install p5-App-cpanminus p5-DBI p5-DBIx-Class p5-DBD-Pg \
 p5-Data-Dumper p5-Digest-SHA p5-File-Slurp p5-JSON p5-MIME-Base64 \
 p5-Net-Server p5-POE p5-Sys-Syslog p5-Term-ANSIColor \
 p5-Text-ANSITable p5-Time-Piece p5-TOML
cpanm Lilith
```

### Source

```
perl Makefile.PL
make
make test
make install
```

## Setup

First you need to setup your PostgreSQL server.

```
createuser -D -l -P -R -S lilith
createdb -E UTF8 -O lilith lilith
```

Setup `/usr/local/etc/lilith.toml`

```
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
pass="WhateverYouSetAsApassword"
user="lilith"
# a handy one to ignore for the extend as it is spammy
class_ignore=["Generic Protocol Command Decode"]

# add a suricata instance to monitor
[suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

# add a second suricata instance to monitor
[another-eve]
instance="foo2-pie"
type="suricata"
eve="/var/log/suricata/alert2.json"

# add a sagan eve to monitor
# instance name is 'foo-lae', given there is no value for instance
[foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"
```

Now we just need to setup the tables.

```
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn install
```

If using snmpd.

```
extend lilith /usr/local/bin/lilith extend
```

### Scheduling automatic escalation

If you use auto escalation rules (see the `auto_escalate` and `ae_*`
actions), run `lilith auto_escalate` periodically so new alerts are
evaluated against the rules. Two ready made units ship under `init/`:

```
cp init/lilith-auto-escalate.service init/lilith-auto-escalate.timer \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith-auto-escalate.timer
```

Or, without systemd, install the cron entry:

```
cp init/lilith-auto-escalate.cron /etc/cron.d/lilith-auto-escalate
```

Both run every five minutes with `-m 60`. The `-m` window only bounds how
far back each run scans for alerts it has not considered yet; the
per-alert `auto_escalated` marker is what prevents an alert from being
escalated twice. Use `--dry-run` first (`lilith auto_escalate
--dry-run`) to see what would fire without sending anything.

### Upgrading

```
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn upgrade
```

If from a old unversioned one like below.

```
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn --to_version 1 upgrade
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn upgrade
```

### Config File

The default config file is `/usr/local/etc/lilith.toml`.

| Variable           | Description                                                                                                                                                                                                                         |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `dsn`              | A DSN connection string to be used by [DBI][https://metacpan.org/pod/DBI]. [DBD::Pg][https://metacpan.org/pod/DBD::Pg]                                                                                                              |
| `pass`             | Password to use for the connection.                                                                                                                                                                                                 |
| `user`             | User to use for the connetion.                                                                                                                                                                                                      |
| `class_ignore`     | Array of classes to ignore.                                                                                                                                                                                                         |
| `allowed_referers` | Optional array of URL prefixes permitted as the `Referer` header on web UI requests. When set, any request whose `Referer` does not start with one of the listed prefixes is rejected with a 403. Omit to disable referer checking. |
| `escalation_enable` | Optional boolean. Enables the escalation system in the web UI (the read-only `/escalation` target view, the per-event Escalate button/history, and the read-only `/auto_escalation` rule page with its dry-run preview). Off by default, as these endpoints can push data at outside services. The CLI escalation actions are always available. |
| `escalation_manage_enable` | Optional boolean. Additionally allows creating/editing/deleting/testing escalation targets from the web UI (`/escalation/edit`). Off by default and independent of `escalation_enable`: editing targets changes where alerts are sent and can push test data at outside services, so it is opt-in. With it off the Escalation menu offers only the read-only View; with it on it becomes a View/Edit dropdown and the mutating target endpoints are unlocked. The CLI escalation actions are always available. |
| `auto_escalation_manage_enable` | Optional boolean. Additionally allows creating/editing/deleting auto-escalation rules from the web UI (`/auto_escalation`). Off by default and independent of `escalation_enable`: a saved+enabled rule escalates automatically on the timer, so editing rules from the unauthenticated web UI is opt-in. With it off the page is read-only (view + preview). The `ae_*` CLI actions are always available. |
| `geoip_ip_city`    | Optional path to a GeoLite2/GeoIP2 City `.mmdb`. When present, the web UI's IP info modal shows geolocation data looked up via [IP::Geolocation::MMDB][https://metacpan.org/pod/IP::Geolocation::MMDB]. Defaults to `GeoLite2-City.mmdb` under the platform GeoIP directory (`/usr/local/share/GeoIP` on FreeBSD, `/usr/share/GeoIP` elsewhere) if that file exists. |
| `geoip_ip_country` | Optional path to a Country `.mmdb`. Defaults to `GeoLite2-Country.mmdb` in the platform GeoIP directory if present. |
| `geoip_ip_asn`     | Optional path to an ASN `.mmdb`. Defaults to `GeoLite2-ASN.mmdb` in the platform GeoIP directory if present. Records from every database that opens are merged in the IP info modal. |
| `domaininfo_cache` | Optional boolean. When true, results of the domain info lookup (`/api/domaininfo`) are cached in memory per worker process, so repeat lookups of the same domain are served instantly. Default false (disabled). |
| `domaininfo_cache_ttl` | Optional. How long, in seconds, a cached domain info result is considered fresh. Default `300` (5 minutes). Only used when `domaininfo_cache` is true. |

EVE instances to follow are defined as sub tables under the `eves` table, i.e.
`[eves.NAME]`. Each such sub hash is an instance with the following values.

| Variable | Required | Description                                                             |
|----------|----------|-------------------------------------------------------------------------|
| eve      | yes      | The EVE file to follow.                                                 |
| type     | yes      | `sagan` or `suricata`, depending on which it is.                        |
| instance | no       | The name for the instance. If not specified the sub table name is used. |

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

# a suricata instance to monitor
[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

# a sagan instance; instance name defaults to the sub table name, 'foo-lae'
[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"
```

Note: previously instances were plain top-level tables (e.g. `[suricata-eve]`).
Those are now ignored — nest them under `[eves.NAME]`. `lilith run` will warn
about any stray top-level table it finds.

### Remote Virani instances

Remote [Virani](https://metacpan.org/pod/Virani) instances for PCAP retrieval
are defined as sub tables under the `virani` table, i.e. `[virani.NAME]`. When
one or more are configured, the web event view shows a "Download PCAP" control
for Suricata events; the instance whose name matches the alert's `instance` is
pre-selected, and any configured instance can be chosen.

| Variable        | Required | Description                                                              |
|-----------------|----------|--------------------------------------------------------------------------|
| url             | yes      | URL of the remote `mojo-virani` server.                                  |
| apikey          | no       | API key, if the remote requires one.                                     |
| set             | no       | PCAP set to request; the remote's default is used if omitted.            |
| type            | no       | Filter type: `tcpdump`, `tshark`, or `bpf2tshark`.                       |
| timeout         | no       | Fetch timeout in seconds. Default `60`.                                  |
| verify_hostname | no       | Verify the TLS certificate for HTTPS URLs. Default `true`.               |

```toml
# allow the standalone "Virani" search to download through the web server;
# off by default since it exposes arbitrary captures. When off, that tool only
# builds a local virani command to copy.
virani_search_enable = true

[virani.inari-pie]
url="https://virani.example.net:7000/"
apikey="…"
set="default"
```

When any Virani instance is configured, a **Virani** dropdown appears in the
navbar. **PCAP Search** opens a search for an arbitrary BPF filter and time
range — it always offers a ready-to-copy local `virani` command, and when
`virani_search_enable` is true it also offers a direct download through the web
server. When `virani_search_enable` is true, a **Cached Searches** entry also
appears, listing the most recent (up to 50) cached searches on a remote — start,
end, size, set, filter, and found/success counts — with a per-row download of the
cached PCAP.

The PCAP is fetched for the flow (the event's src/dest IP and ports, over the
flow window widened by 60 seconds on each end) and streamed back as a download.
The "Download PCAP" control lets you pick which set to pull from (the list is
queried live from the selected remote), and a dropdown also offers a ready-made
`virani` command to run on the box holding the PCAPs instead of downloading.
Note: this exposes packet captures to anyone who can reach the web UI — put it
behind `allowed_referers` and/or a reverse proxy with authentication.

### Escalations

The web frontend can escalate events to configured destinations. It is
enabled via the config file.

```toml
escalation_enable = true

# optional; additional namespaces to search for site supplied escalation
# type modules, searched after Lilith::Escalate::Type
escalation_type_namespaces = [ "My::Escalate" ]
```

Escalation targets are stored in SQL (the `escalation_targets` table) and
managed on the **Escalation** page in the navbar. Each target has a name, a
type, and a per-type config; the config form is generated from the type's
own field spec, so newly installed types show up without any UI changes,
and each target has a **Test** button that sends a synthetic event at it.

A type is a module under the `Lilith::Escalate::Type::` namespace (see the
[Lilith::Escalate](https://metacpan.org/pod/Lilith::Escalate) POD for the
small interface a type implements). The dist ships with:

| Type    | Description                                                                        |
|---------|------------------------------------------------------------------------------------|
| Webhook | POSTs the event as JSON to a URL, optionally with a `Authorization: Bearer` key.    |
| Email   | Sends a plain text summary of the event via SMTP (STARTTLS and AUTH supported).     |
| Syslog  | Logs a one line summary of the event to syslog.                                     |

The event view gains a **Escalate** button, which sends the event to one or
more targets along with a note and who requested it, plus a escalation
history section. Every attempt is recorded in the `escalations` table with
its status (`sent`/`failed`), any error, and the raw JSON of what was
actually sent, which the history section can expand per row — including
attempts refused before a send (a unknown or disabled target). The target's
name is snapshotted per attempt, so history remains readable after a target
is deleted. Escalated events are badged with a red **E** in search results.

Each alert table (`suricata_alerts`, `sagan_alerts`, `cape_alerts`) also has
a `escalations bigint[]` column holding the escalation IDs recorded for that
row, appended in the same transaction as the `escalations` insert. Anything
reading the alert tables can therefore trivially see whether a alert has
been escalated and how many times (the array length) without touching the
`escalations` table, and has the IDs in hand when more detail is wanted. The
`escalations` table remains the source of truth.

Escalations are sent from the web server (in a subprocess, so the event
loop is not blocked). Like PCAP retrieval, the endpoints are unauthenticated
— leave `escalation_enable` off unless the UI sits behind `allowed_referers`
and/or a reverse proxy with authentication.

## Options

### SYNOPSIS

Each action is a subcommand. Global options (`--config`, `--debug`,
`--version`) come before the subcommand. Run `lilith commands` to list every
subcommand and `lilith help <command>` for a command's options.

```
lilith [--config <config>] <command> [<options>]

lilith [--config <config>] run [--daemonize] [--user <user>] [--group <group>]

lilith [--config <config>] class_map

lilith [--config <config>] dump_self

lilith [--config <config>] event [-t <table>] --id <row_id> [--raw]
[[--pcap <output file>] [--virani <remote>] [--buffer <buffer seconds>]]

lilith [--config <config>] event [-t <table>] --event <event_id> [--raw]
[[--pcap <output file>] [--virani <remote>] [--buffer <buffer seconds>]]

lilith [--config <config>] extend [-Z] [-m <minutes>]

lilith [--config <config>] get_short_class_snmp_list

lilith [--config <config>] search [--output <return>] [-t <table>]
[-m <minutes>] [--order <clm>] [--limit <int>] [--offset <int>]
[--orderdir <dir>] [--si <src_ip>] [--di <dst_ip>] [--ip <ip>]
[--sp <src_port>] [--dp <dst_port>] [-p <port>] [--host <host>]
[--ih <host>] [-i <instance>] [-c <class>] [-s <sig>] [--if <if>]
[--ap <proto>] [--gid <gid>] [--sid <sid>] [--rev <rev>]
[--subip <subip>] [--subhost <subhost>] [--slug <slug>] [--pkg <pkg>]
[--malscore <malscore>] [--size <size>] [--target <target>]
[--task <task>]
```

Note: prior to 3.x the action was selected with a `-a` flag (`lilith run`).
That flag has been removed in favor of the subcommand form (`lilith run`).

### GLOBAL SWITCHES

These come before the subcommand, e.g. `lilith --config /etc/lilith.toml run`.

#### --config config

The config file to use.

    - Default :: /usr/local/etc/lilith.toml

#### --debug

Enable debug output.

#### --version, -v

Print the version and exit.

### COMMAND SWITCHES

#### -t table

Table to operate on, for the commands that take one.

    - Default :: suricata

=head1 ACTIONS

#### run

Start processing the EVE logs and daemonize.

#### class_map

Print a table of class mapping from long name to the short name used for display in the search results.

#### dump_self

Initiate Lilith and then dump it via Data::Dumper.

#### event

Fetches a event. The table to use can be specified via -t.

##### --id row_id

Fetch event via row ID.

##### --event event_id

Fetch the event via the event ID.

#### --raw

Do not decode the EVE JSON.

##### --pcap file

Fetch the remote PCAP via Virani and write it to the file. Only usable for with Suricata tables.

Default :: undef

##### --virani conf

Virani setting to pass to -r.

Default :: instance name in alert

##### --buffer secs

How many seconds to pad the start and end time with.

Default :: 60


#### extend

Prints a LibreNMS style extend.

##### -Z

Enable Gzip+Base64 LibreNMS style extend compression.

##### -m minutes

How far back to search. For the extend action, 5 minutes
is the default.

##### -d dir

The directory to write it out too.

#### get_short_class_snmp_list

Print a list of shorted class names for use with SNMP.

#### search

Search the DB. The table may be specified via -t.

The common option types for search are as below.

    - Integer :: A comma seperated list of integers to check for. Any number
                 prefixed with a ! will be negated.
    - String :: A string to check for. May be matched using like or negated via
                the proper options.
    - Complex :: A item to match.
    - IP :: An IP.

##### General Search Options

###### --output return

The output type.

    - Values :: table,json
    - Default :: table

###### -m minute

How far back to to in minutes.

    - Default :: 1440

    - Default, extend :: 5

###### --order column

Column to use for sorting by.

    - Default :: timestamp

    - Cape Default :: stop

###### --orderdir direction

Direction to order in.

    - Values :: ASC,DSC
    - Default :: ASC

##### IP Options

###### --si src IP

Source IP.

    - Default :: undef
    - Type :: IP

######  --di dst IP

Destination IP.

    - Default :: undef
    - Type :: IP

######  --ip IP

IP, either dst or src.

    - Default :: undef
    - Type :: complex IP

#####  Port Options

###### --sp src port

Source port.

    - Default :: undef
    - Type :: integer

######  --dp dst port

Destination port.

    - Default :: undef
    - Type :: integer

###### -p port

Port, either dst or src.

    - Default :: undef
    - Type :: complex integer
##### Host Options

    Sagan :: Host is the sending system and instance host is the host the
             instance is running on.

    Suricata :: Host is the system the instance is running on. There is no
                instance host.

###### --host host

Host.

    - Default :: undef
    - Type :: string

##### Instance Options

###### --ih host

Instance host.

    - Default :: undef
    - Type :: string

##### Instance Options

###### -i  instance

Instance.

    - Default :: undef
    - Type :: string

##### Class Options

###### -c class

Classification.

    - Default :: undef
    - Type :: string

##### Signature Options

###### -s sig

Signature.

    - Default :: undef
    - Type :: string

##### In Interface Options

###### --if if

Interface.

    - Default :: undef
    - Type :: string

##### App Proto Options

###### --ap proto

App proto.

    - Default :: undef
    - Type :: string

##### Rule Options

###### --gid gid

GID.

    - Default :: undef
    - Type :: integer

###### --sid sid

SID.

    - Default :: undef
    - Type :: integer

###### --rev rev

Rev.

    - Default :: undef
    - Type :: integer

##### CAPEv2 Options

###### --slug slug

The slug it was submitted with.

    - Default :: undef
    - Type :: string

###### --pkg pkg

The detopnation package used with CAPEv2.

    - Default :: undef
    - Type :: string

###### --malscore malscore

The malscore of the sample.

    - Default :: undef
    - Type :: integer

###### --size size

The size of the sample.

    - Default :: undef
    - Type :: integer

###### --target target

The the detonation target.

    - Default :: undef
    - Type :: string

###### --task task

The task ID of the run.

    - Default :: undef
    - Type :: integer

###### --subip subip

The IP the sample was submitted from.

    - Default :: undef
    - Type :: IP

###### --subhost subhost

The host the sample was submitted from.

    - Default :: undef
    - Type :: string

#### esc

Escalates a event to one or more escalation targets. The table is picked via
`-t` and the event via `--id`. Exits non-zero if any target failed.

    lilith esc --id 42 --to soc-hook,mail-oncall --note 'C2 traffic'

##### --id row_id

The row ID of the event to escalate.

##### --to targets

Comma separated list of escalation targets, each either a target ID or name.

##### --note note

A optional note to record with the escalation.

##### --by who

Who requested the escalation. Defaults to the current user.

##### --output return

`table` or `json`.

#### esc_history

Prints the escalations recorded for a event, newest first, picked via `-t`
and `--id`. With `--output json` the raw payloads are included, decoded
unless `--raw` is given.

#### esc_types

Lists the available escalation types and the config fields each takes, for
use with `--set`. `--output json` prints the full type info.

#### esc_targets

Lists the configured escalation targets. `--output json` includes each
target's config.

#### esc_target_get

Prints a single escalation target as JSON, including its config. Picked via
`--tid <id>` or `--name <name>`.

#### esc_target_create

Creates a escalation target and prints its ID.

    lilith esc_target_create --name soc-hook --type Webhook \
        --set url=https://soc.example/hook --set apikey=xyz

##### --name name

The name for the new target. Required.

##### --type type

The escalation type, as listed by `esc_types`. Required.

##### --set key=value

A config item for the type. May be given multiple times.

##### --desc desc

A optional description.

##### --disable

Create the target disabled.

#### esc_target_update

Updates a escalation target, picked via `--tid` or `--name`; only the items
specified change. `--set` items merge over the current config, and a empty
value (`--set apikey=`) removes that key. When picked via `--tid`, `--name`
renames the target. `--enable` / `--disable` flip the enabled flag.

#### esc_target_delete

Deletes a escalation target, picked via `--tid` or `--name`. Recorded
escalations to it are kept.

#### esc_target_test

Sends a synthetic test event to a escalation target, picked via `--tid` or
`--name`, and prints the payload sent as JSON.

Note: unlike the web UI, the escalation actions are not gated by
`escalation_enable` — that gate exists for the unauthenticated web frontend,
while the CLI already holds the DB credentials from the config file.

## ENVIROMENTAL VARIABLES

### Lilith_table_color

The L<Text::ANSITable> table color to use.

    - Default :: Text::ANSITable::Standard::NoGradation

### Lilith_table_border

The L<Text::ANSITable> border type to use.

    - Default :: ASCII::None

### Lilith_IP_color

Perl boolean for if IPs should be colored or not.

    - Default :: 1

### Lilith_IP_private_color

ANSI color to use for private IPs.

    - Default :: bright_green

### Lilith_IP_remote_color

ANSI color to use for remote IPs.

    - Default :: bright_yellow

### Lilith_IP_local_color

ANSI color to use for local IPs.

    - Default :: bright_red

### Lilith_timesamp_drop_micro

Perl boolean for if microseconds should be dropped or not.

    - Default :: 1

### Lilith_instance_color

If the lilith instance colomn info should be colored.

    - Default :: 1

### Lilith_instance_type_color

Color for the instance name.

    - Default :: bright_blue

### Lilith_instance_slug_color

Color for the insance slug.

    - Default :: bright_magenta

### Lilith_instance_loc_color

Color for the insance loc.

	- Default :: bright_cyan.

