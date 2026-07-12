# Configuration

The config file is TOML, default `/usr/local/etc/lilith.toml`. The CLI
takes another via `lilith --config <file> <command>`; `lilith-web` reads
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

`Generic Protocol Command Decode` is a handy classification to drop —
it is spammy.

### The web frontend

All optional; all default off / unset. Read [security.md](security.md)
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

The CLI escalation actions are never gated by the enables above — those
gates exist for the unauthenticated web frontend, while the CLI already
holds the database credentials from this very file.

## EVE instances: `[eves.*]`

Each EVE file to follow is a sub table under `eves`. The sub table name is
the instance name unless `instance` overrides it.

| key        | required | description                                             |
|------------|----------|----------------------------------------------------------|
| `eve`      | yes      | The EVE file to follow.                                  |
| `type`     | yes      | `suricata`, `sagan`, or `cape`.                          |
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
```

`cape` is for the EVE-ish logs generated by
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils) from CAPEv2 detonations.

A malformed instance is warned about and skipped rather than killing the
daemon. Note: prior to 4.0.0 instances were plain top-level tables
(`[suricata-eve]`); those are now ignored, with a warning from `lilith run`.

## Remote Virani instances: `[virani.*]`

Remote [Virani](https://github.com/LilithSec/Virani) (`mojo-virani`)
servers for PCAP retrieval, one sub table each. When any are configured the
web event view grows a "Download PCAP" control for Suricata events (the
instance matching the alert's `instance` is pre-selected) and a **Virani**
dropdown appears in the navbar. See [usage.md](usage.md) for what those do
and [security.md](security.md) for why you may not want them reachable.

| key               | required | description                                            |
|-------------------|----------|--------------------------------------------------------|
| `url`             | yes      | URL of the remote `mojo-virani` server.                |
| `apikey`          | no       | API key, if the remote requires one.                   |
| `set`             | no       | PCAP set to request; the remote's default if omitted.  |
| `type`            | no       | Filter type: `tcpdump`, `tshark`, or `bpf2tshark`.     |
| `timeout`         | no       | Fetch timeout in seconds. Default `60`.                |
| `verify_hostname` | no       | Verify the TLS certificate for HTTPS URLs. Default `true`. |

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

# where the packets behind an alert can be fetched from
[virani.foo-pie]
url="https://virani.example.net:7000/"
apikey="whatever"
set="default"
```
