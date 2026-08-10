# Configuration

The config file is TOML, default `/usr/local/etc/lilith.toml`. The CLI
takes another via `lilith --config <file> <command>`; `mojo_lilith` reads
the `LILITH_CONFIG` env var.

The ingest daemon, the CLI, and the web frontend all read the same file —
most of the web-only settings simply do nothing for the others.

## Top level settings

### The database

| key    | description                                                                 |
|--------|-----------------------------------------------------------------------------|
| `dsn`  | The [DBI](https://metacpan.org/pod/DBI) DSN, e.g. `dbi:Pg:dbname=lilith;host=192.168.1.2`. PostgreSQL only ([DBD::Pg](https://metacpan.org/pod/DBD::Pg)). |
| `user` | User for the connection. Default `lilith`.                                  |
| `pass` | Password for the connection.                                                |

### Extend ignores

These trim noise from the LibreNMS extend (`lilith extend`); they do not
keep anything out of the database.

| key                      | description                                        |
|--------------------------|-----------------------------------------------------|
| `class_ignore`           | Array of classifications to ignore, both types.    |
| `sid_ignore`             | Array of SIDs to ignore, both types.               |
| `suricata_class_ignore`  | Array of classifications to ignore, Suricata only. |
| `suricata_sid_ignore`    | Array of SIDs to ignore, Suricata only.            |
| `sagan_class_ignore`     | Array of classifications to ignore, Sagan only.    |
| `sagan_sid_ignore`       | Array of SIDs to ignore, Sagan only.               |
| `baphomet_event_ignore`  | Array of Baphomet event types to drop on ingest (`found`, `banish`, `noted`, `alert`, `sighting`, `sighted`). Empty by default (ingest all six). |

`Generic Protocol Command Decode` is a handy classification to drop —
it is spammy.

### The web frontend

All optional; all default off / unset. Read [security](security.md)
before turning on any of the enables — the frontend is unauthenticated.

| key                          | description                                     |
|------------------------------|--------------------------------------------------|
| `allowed_referers`           | Array of URL prefixes permitted as the `Referer` header on web requests. When set, a request whose `Referer` does not start with one of them is rejected with a 403. Omit to disable the check. |
| `escalation_enable`          | Boolean. Enables the escalation system in the web UI: the read-only `/escalation` target view, the per-event Escalate button and history, and the read-only `/auto_escalation` rule page with its dry-run preview. Off by default, as these endpoints can push data at outside services. |
| `escalation_manage_enable`   | Boolean. Additionally allows creating/editing/deleting/testing escalation targets from the web UI (`/escalation/edit`). Independent of `escalation_enable` and off by default — editing targets changes where alerts are sent. |
| `auto_escalation_manage_enable` | Boolean. Additionally allows creating/editing/deleting auto escalation rules from the web UI. Off by default — a saved and enabled rule escalates automatically on the timer. With it off the page is read only (view + preview). |
| `escalation_type_namespaces` | Array of extra namespaces to search for site supplied escalation type modules, searched after `Lilith::Escalate::Type`. |
| `virani_search_enable`       | Boolean. Allows the standalone PCAP search to download through the web server, and enables the Cached Searches browser. Off by default since it exposes arbitrary captures; when off the search tool only builds a local `virani` command to copy. |
| `geoip_ip_city`              | Path to a GeoLite2/GeoIP2 City `.mmdb` for the IP info modal. Defaults to `GeoLite2-City.mmdb` under the platform GeoIP dir (`/usr/local/share/GeoIP` on FreeBSD, `/usr/share/GeoIP` elsewhere) if that file exists. |
| `geoip_ip_country`           | Path to a Country `.mmdb`. Same default scheme.  |
| `geoip_ip_asn`               | Path to an ASN `.mmdb`. Same default scheme. Records from every database that opens are merged. |
| `domaininfo_cache`           | Boolean. Cache domain info lookups in memory per worker. Default false. |
| `domaininfo_cache_ttl`       | Seconds a cached domain info result stays fresh. Default `300`. |
| `dnstracer_enable`           | Boolean. Run `dnstracer` as part of a domain info lookup and show its output in the panel. Off by default, and needs the `dnstracer` binary installed. Its own deadline is a fixed 30 seconds. |
| `dnstracer_flags`            | Array of extra flags to pass `dnstracer`, e.g. `["-4"]`. Empty by default. |
| `dns_bg_timeout`             | Seconds the domain info lookup waits on its DNS queries before giving up on the ones still outstanding. Default `3`. |
| `cape_enable`                | Boolean. Enables the `/cape_submit` page and its CAPE navbar button. Off by default — a submission pushes a file to an outside service. Needs at least one `[cape_servers.*]` with a `url`; without one the page stays hidden and 404s. |
| `cape_slug`                  | The default slug submissions are made under. Default `lilith`. |
| `cape_max_upload_size`       | Caps an upload to the `/cape_submit` page, in bytes. Default `1073741824` (1 GiB), which also raises Mojolicious's own 16 MiB request cap so a large sample is not dropped mid-upload. Only applied when submission is on. |

The CLI escalation actions are never gated by the enables above — those
gates exist for the unauthenticated web frontend, while the CLI already
holds the database credentials from this very file.

## EVE instances: `[eves.*]`

Each EVE file to follow is a sub table under `eves`. The sub table name is
the instance name unless `instance` overrides it.

| key        | required | description                                             |
|------------|----------|----------------------------------------------------------|
| `eve`      | yes      | The EVE file to follow.                                  |
| `type`     | yes      | `suricata`, `sagan`, `cape`, or `baphomet`.             |
| `instance` | no       | Instance name; defaults to the sub table name.           |

```toml
[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

# instance name defaults to the sub table name, 'foo-lae'
[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"

# Baphomet's own judgment log
[eves.baphomet-sshd]
type="baphomet"
eve="/var/log/baphomet/eve.json"
```

`cape` is for the EVE-ish logs generated by
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils) from CAPEv2 detonations.

`baphomet` ingests the EVE
[Baphomet](https://github.com/LilithSec/Baphomet) emits about its own verdicts
(`eve_type` `baphomet`; event types `found`/`banish`/`noted`/`alert`/`sighting`/`sighted`)
into the `baphomet_alerts` table. The record's promoted flow vars land in
`src_ip`/`src_port`/`dest_ip`/`dest_port` and `username` (the EVE `user`), with
`src_ip` falling back to the first banished address -- a subnet ban's CIDR
included -- so the top-talker, escalation, and GeoIP machinery reuse it. Who
crossed a threshold stays in `raw` (`subjects_crossed`/`subject_vars`),
reachable with `raw->'...'`. Use the top-level `baphomet_event_ignore` to drop
event types you do not want stored. Baphomet is viewable in search and the
dashboard but is not escalated automatically (escalation stays opt-in).

A malformed instance is warned about and skipped rather than killing the
daemon. Note: prior to 4.0.0 instances were plain top-level tables
(`[suricata-eve]`); those are now ignored, with a warning from `lilith run`.

## Remote Virani instances: `[virani.*]`

Remote [Virani](https://github.com/LilithSec/Virani) (`mojo-virani`)
servers for PCAP retrieval, one sub table each. When any are configured the
web event view grows a "Download PCAP" control for Suricata events (the
instance matching the alert's `instance` is pre-selected) and a **Virani**
dropdown appears in the navbar. See [usage](usage.md) for what those do
and [security](security.md) for why you may not want them reachable.

| key               | required | description                                            |
|-------------------|----------|--------------------------------------------------------|
| `url`             | yes      | URL of the remote `mojo-virani` server.                |
| `apikey`          | no       | API key, if the remote requires one.                   |
| `set`             | no       | PCAP set to request; the remote's default if omitted.  |
| `type`            | no       | Filter type: `tcpdump`, `tshark`, or `bpf2tshark`.     |
| `timeout`         | no       | Fetch timeout in seconds. Default `60`.                |
| `verify_hostname` | no       | Verify the TLS certificate for HTTPS URLs. Default `true`. |

## Allani log store: `[allani]`

A single [Allani](https://github.com/LilithSec/Allani) log store to browse
from the web UI. Allani keeps every log line (syslog-ng JSON in PostgreSQL);
where Lilith keeps only the alerts, Allani keeps the lot. When an `[allani]`
block with a `dsn` is present, a read-only **Logs** page (`/logs`) and a
**Logs** navbar entry appear, letting you search the `syslog`, `http_access`,
and `http_error` tables (plus an interleaved http view). Omit the block and
the page and nav entry stay hidden.

The connection is Allani's own, independent of Lilith's top-level `dsn`, so
the two need not share a database (point it at the same one if they do).
Lilith only ever reads. This needs [Allani](https://github.com/LilithSec/Allani)
installed (it reuses `Allani::Sources` for the accepted columns and filters); it is
an optional dependency, so a config without `[allani]` does not require it.

| key    | required | description                                             |
|--------|----------|----------------------------------------------------------|
| `dsn`  | yes      | The DBI DSN of the Allani PostgreSQL database, e.g. `dbi:Pg:dbname=allani;host=192.168.1.2`. The whole feature is off unless this is set. |
| `user` | no       | Database user. |
| `pass` | no       | Database password. |

```toml
[allani]
dsn="dbi:Pg:dbname=allani;host=192.168.1.2"
user="allani"
pass="WhateverYouSetAsApassword"
```

Like the other web features it is unauthenticated; log lines can carry
sensitive data, so read [security](security.md) before exposing it.

## CAPEv2 boxes: `[cape_servers.*]`

The CAPEv2 boxes (`mojo_cape_submit`) Lilith may hand a sample to, one sub
table each. They do double duty:

- **Submission** :: `lilith cape_submit` and the web `/cape_submit` page upload
  a local file for detonation. This is what the top-level `cape_enable`,
  `cape_slug`, and `cape_max_upload_size` above gate and configure.
- **Results** :: the event view of a `cape` alert pulls that detonation's
  screenshots, signatures, and malscore from the box it ran on, matching the
  event's `instance` against the sub table name. Reading results is
  independent of `cape_enable` — it never pushes anything out — so it stays
  available with submission turned off.

| key              | required | description                                             |
|------------------|----------|----------------------------------------------------------|
| `url`            | yes      | The `mojo_cape_submit` endpoint samples are POSTed to.   |
| `apikey_needed`  | no       | Boolean. Whether the server wants an API key.            |
| `apikey`         | no       | The key to send when one is needed. It goes in the `Authorization: Bearer` header and the `apikey` form field, never in the JSON. |
| `results_url`    | no       | Where detonation results are read from, if not the same host as submission. Defaults to `url`. |
| `results_apikey` | no       | The key for the results endpoint. Defaults to `apikey`.  |
| `web_url`        | no       | The box's CAPEv2 web UI. When set, the event view links out to the full styled report there; without it the report is streamed back through the results endpoint and renders unstyled. |

```toml
cape_enable = true
cape_slug   = "lilith"

# name it after the instance whose cape alerts it detonates, so the event
# view can find the results for a run
[cape_servers.cape-foo]
url           = "http://192.168.14.15:8080/"
apikey_needed = true
apikey        = "deadbeefdeadbeefdeadbeef"
web_url       = "https://cape.example.net/"
```

See [usage](usage.md) for the `cape_submit` command and the page it mirrors.
Submission is off by default for the same reason the other outward-reaching
features are; read [security](security.md).

## EVE receiver keys

`mojo_lilith_receiver` (the daemon that accepts pushed alert rows, by HTTP
POST or over a WebSocket) has no config-file settings — its bearer keys live
in the database, not the TOML. Manage them with the `lilith receiver_key_*`
commands:

```shell
# a key that may push from a subnet, only as instances named foo-*
lilith receiver_key_create --name sensor1 \
    --ip 10.0.0.0/8 --ip 192.168.1.5/32 \
    --instance 'foo-*'
```

The command prints the generated key once; only its SHA-256 is stored, so it
cannot be shown again. `--ip` (host or CIDR subnet) and `--instance` (a name
or `*`/`?` glob) are each repeatable and each optional — omit an axis to leave
it unrestricted. With no keys created the receiver rejects every request. See
[usage](usage.md) for the commands and push format and [security](security.md)
for the reverse-proxy caveat that per-IP scoping depends on.

## A complete example

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

# keep the spammy stuff out of the extend
class_ignore=["Generic Protocol Command Decode"]

# lock the web UI down to requests coming from our own pages
allowed_referers=["https://lilith.example.net/"]

# escalation in the web UI: buttons and read-only views on, editing
# targets on, but rule editing stays CLI-only
escalation_enable = true
escalation_manage_enable = true
#auto_escalation_manage_enable = true

# hand samples to the CAPEv2 box configured further down
cape_enable = true

# a suricata instance
[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

# a second suricata instance
[eves.another-eve]
instance="foo2-pie"
type="suricata"
eve="/var/log/suricata/alert2.json"

# a sagan instance; instance name is the sub table name, 'foo-lae'
[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"

# CAPEv2 detonations, via CAPE::Utils
[eves.cape]
type="cape"
eve="/var/log/cape/eve.json"

# Baphomet's own judgment log
[eves.baphomet-sshd]
type="baphomet"
eve="/var/log/baphomet/eve.json"

# where the packets behind an alert can be fetched from
[virani.foo-pie]
url="https://virani.example.net:7000/"
apikey="whatever"
set="default"

# the Allani log store to browse from the /logs page
[allani]
dsn="dbi:Pg:dbname=allani;host=192.168.1.2"
user="allani"
pass="WhateverYouSetAsApassword"

# the CAPEv2 box the [eves.cape] detonations run on; named after that
# instance so the event view can pull a run's results back
[cape_servers.cape]
url="http://192.168.14.15:8080/"
apikey_needed=true
apikey="deadbeefdeadbeefdeadbeef"
```
