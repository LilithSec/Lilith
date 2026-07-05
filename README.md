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
extend lilith /usr/local/bin/lilith -a extend
```

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
Those are now ignored — nest them under `[eves.NAME]`. `lilith -a run` will warn
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

## Options

### SYNOPSIS

```
lilith [B<-c> <config>] B<-a> run

lilith [B<-c> <config>] B<-a> class_map

lilith [B<-c> <config>] B<-a> dump_self

lilith [B<-c> <config>] B<-a> event [B<-t> <table>] B<--id> <row_id> [B<--raw>]
[[B<--pcap> <output file>] [B<--virani> <remote>] [B<--buffer> <buffer secodns>]]

lilith [B<-c> <config>] B<-a> event [B<-t> <table>] B<--event> <event_id> [B<--raw>]
[[B<--pcap> <output file>] [B<--virani> <remote>] [B<--buffer> <buffer secodns>]

lilith [B<-c> <config>] B<-a> extend [B<-Z>] [B<-m> <minutes>]

lilith [B<-c> <config>] B<-a> get_short_class_snmp_list

lilith [B<-c> <config>] B<-a> search [B<--output> <return>] [B<-t> <table>]
[B<-m> <minutes>] [B<--order> <clm>] [B<--limit> <int>] [B<--offset> <int>]
[B<--orderdir> <dir>] [B<--si> <src_ip>] [B<--di> <<dst_ip>] [B<--ip> <ip>]
[B<--sp> <<src_port>] [B<--dp> <<dst_port>] [B<--port> <<port>] [B<--host> <host>]
[B<--ih> <host>] [B<-i> <instance>] [B<-c> <class>] [B<-s> <sig>] [B<--if> <if>]
[B<--ap> <proto>] [B<--gid> <gid>] [B<--sid> <sid>] [B<--rev> <rev>]
[B<--subip> <subip>] [B<--subhost> <subhost>] [B<--slug> <slug>] [B<--pkg> <pkg>]
[B<--malscore> <malscore>] [B<--size> <size>] [B<--target> <target>]
[B<--task> <task>]
```

### GENERAL SWITCHES

#### -a action

The action to perform.

    - Default :: search

#### -c config

The config file to use.

    - Default :: /usr/local/etc/lilith.toml

#### -t table

Table to operate on.

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

