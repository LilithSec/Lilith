# Usage

## The CLI

Each action is a subcommand. Global options come before the subcommand.

```shell
lilith [--config <file>] [--debug] <command> [<options>]

# list every subcommand / a command's options
lilith commands
lilith help <command>
```

| global switch     | description                                              |
|-------------------|----------------------------------------------------------|
| `--config <file>` | The config file. Default `/usr/local/etc/lilith.toml`.   |
| `--debug`         | Enable debug output.                                     |
| `--version`, `-v` | Print the version and exit.                              |

A bare `lilith`, or one whose first argument is an option, runs `search` —
so `lilith --si 1.2.3.4` just works. Note: prior to 3.x the action was
selected with a `-a` flag (`lilith -a run`); that flag is gone in favor of
subcommands (`lilith run`).

The escalation subcommands (`esc`, `esc_*`, `ae_*`, `auto_escalate`) are
covered in [escalation](escalation.md).

### run

Start following the configured EVE files into PostgreSQL. Not expected to
return.

```shell
lilith run [--daemonize] [--user <user>] [--group <group>]
```

On a box that only feeds the annals,
[Lilu](https://github.com/LilithSec/App-Lilu)'s `lilu run` / `lilu extend`
do the same jobs without the rest of Lilith; see
[install](install.md).

### search

Search the annals. Which table via `-t` (`suricata` (default), `sagan`,
`cape`, or `baphomet`); output as an ANSI table or `--output json`.

```shell
# everything from the last day (the default window)
lilith search

# ssh traffic to or from 1.2.3.4 in the last hour, as JSON
lilith search -m 60 --ip 1.2.3.4 -p 22 --output json

# everything not classified as a scan
lilith search -c '!%scan%'
```

General options:

| switch            | description                                             |
|-------------------|---------------------------------------------------------|
| `-t <table>`      | Table to search. Default `suricata`.                    |
| `-m <minutes>`    | How far back to go. Default `1440`.                     |
| `--output <fmt>`  | `table` or `json`. Default `table`.                     |
| `--order <clm>`   | Column to sort by. Default `timestamp` (`stop` for cape). |
| `--orderdir <dir>`| `ASC` or `DSC`. Default `ASC`.                          |
| `--limit <int>` / `--offset <int>` | Paging.                                |
| `--bucket`        | Baphomet only: compress rows sharing an instance, signature, and subjects to the newest of them, with a `count` column of how many each stands for. |

Most filters share a small grammar: an **integer** option takes a comma
separated list, each item negatable with a `!` prefix (and the complex ones
take `<`, `<=`, `>`, `>=`); a **string** option may match via SQL LIKE
(`%` wildcards) and negate with `!`; positive values are ORed together and
negated ones ANDed.

| switch  | matches                                  | type            |
|---------|-------------------------------------------|-----------------|
| `--si`  | source IP                                 | IP              |
| `--di`  | destination IP                            | IP              |
| `--ip`  | either src or dst IP                      | complex IP      |
| `--sp`  | source port                               | integer         |
| `--dp`  | destination port                          | integer         |
| `-p`    | either src or dst port                    | complex integer |
| `--host`| host (Sagan: the sending system; Suricata: the system the instance runs on) | string |
| `--ih`  | instance host (Sagan only)                | string          |
| `-i`    | instance                                  | string          |
| `-c`    | classification; may be given several times or comma separated | string |
| `-s`    | signature                                 | string          |
| `--if`  | in interface                              | string          |
| `--ap`  | app proto                                 | string          |
| `--gid` / `--sid` / `--rev` | rule gid / sid / rev      | integer         |

And for the `cape` table:

| switch       | matches                              |
|--------------|---------------------------------------|
| `--slug`     | the slug it was submitted with        |
| `--pkg`      | the detonation package                |
| `--malscore` | the malscore of the sample            |
| `--size`     | the size of the sample                |
| `--target`   | the detonation target                 |
| `--task`     | the task ID of the run                |
| `--subip` / `--subhost` | the IP / host it was submitted from |

And for the `baphomet` table:

| switch       | matches                              |
|--------------|---------------------------------------|
| `--subjects` | subject vars. JSON matches the whole set structurally; `VAR=value` matches one var (`%` for LIKE), a bare `VAR` its presence, `!` negating either; `none` matches records with no subject vars |

Suricata, Sagan, and Baphomet searches can also filter on what the
[Shodan cache](configuration.md#shodan) holds for the alert's ends — the same
data the web UI's badges and the dashboard's enrichment dimensions read, so
they match whatever the cache currently holds. Each may be given several
times or comma separated, and negates with `!`. An end with no cached entry
never matches a positive filter.

| switch | matches |
|--------|---------|
| `--shodan_src_tag` / `--shodan_dest_tag` | a Shodan tag on that end (`tor`, `compromised`, ...) |
| `--shodan_src_known` / `--shodan_dest_known` | the cache state for that end: `known` (on Shodan), `unknown` (crawled, nothing there), or `unchecked` (never looked up) |
| `--shodan_src_cvss` / `--shodan_dest_cvss` | the worst CVSS of that end's CVEs (CVEDB standing in where the keyless tier sent no scores); takes `<`, `<=`, `>`, `>=` |
| `--cve` | a CVE id the rule names (Suricata). Normalized before matching, so `cve_2021_44228` finds what `CVE-2021-44228` does |
| `--shodan_src_cve_match` / `--shodan_dest_cve_match` | where the rule's CVEs and that end's cached ones stand against each other (Suricata): `matched` (the rule names a CVE that end is vulnerable to), `unmatched`, `no-cve`, or `unchecked` — the same four buckets as the dashboard dimensions of the same names |
| `--src_locality` / `--dest_locality` | which side of the config's [`local_networks`](configuration.md#the-web-frontend) that end sits on: `internal` or `external` (with none configured, the private/unroutable ranges). Every table, no cache needed; an alert naming no address on that end matches neither |

```shell
# alerts from tor exits or hosts Shodan tags compromised, last day
lilith search --shodan_src_tag tor,compromised

# exploit attempts against hosts with a critical CVE
lilith search --shodan_dest_cvss '>=9'

# everything the rule ties to Log4Shell
lilith search --cve CVE-2021-44228

# exploits thrown at destinations actually vulnerable to them
lilith search --shodan_dest_cve_match matched

# alerts where one of your own machines is the source
lilith search --src_locality internal
```

### event

Fetch a single event, by row ID or event ID.

```shell
lilith event [-t <table>] --id <row_id> [--raw]
lilith event [-t <table>] --event <event_id> [--raw]

# also pull the flow PCAP behind it via Virani (Suricata tables only)
lilith event --id 42 --pcap ./flow.pcap [--virani <remote>] [--buffer <secs>]
```

`--raw` skips decoding the EVE JSON. `--virani` picks which configured
remote to ask (default: the alert's instance name); `--buffer` pads the
flow window on each side (default 60 seconds).

### extend

Print a [LibreNMS](https://www.librenms.org/) style extend of recent alert
counts. `-Z` enables gzip+base64 extend compression; `-m` sets the window
(default 5 minutes for the extend). Wire it into snmpd with:

```
extend lilith /usr/local/bin/lilith extend
```

### cape_submit

Submit local files to a [CAPEv2](https://github.com/kevoreilly/CAPEv2) box
(`mojo_cape_submit`) for detonation. Each file's md5/sha1/sha256, size, and
libmagic description are computed and sent alongside the file as a
`lilith_cape_submit` submission; the file is uploaded as
`<slug>-<unixtime>-<filename>`. The API key, when the server needs one, goes in
the `Authorization: Bearer` header and `apikey` form field — never in the JSON.

Needs `cape_enable` set and at least one server under `[cape_servers.NAME]`:

```toml
cape_enable = true
cape_slug   = "lilith"    # default slug; overridden per-run with --slug

[cape_servers.main]
url           = "http://192.168.14.15:8080/"
apikey_needed = true
apikey        = "deadbeefdeadbeefdeadbeef"
```

```shell
# submit one file to the only configured server
lilith cape_submit /tmp/putty.exe

# pick a server and slug, submit several, get JSON back
lilith cape_submit --server main --slug hunt /tmp/a.exe /tmp/b.dll --output json
```

`--server` is optional when exactly one server is configured. It exits non-zero
if any file failed to submit.

### shodan_cache

Look up the addresses recent alerts name and store what Shodan knows in the
`shodan_cache` table, so the web UI's IP info modal and its results-table
badges have something to show without anyone having opened each address by
hand first. See [configuration](configuration.md#shodan) for the settings.

```shell
# what a run would ask about, without asking
lilith shodan_cache --dry-run

# the last ten minutes, for a timer run every minute -- wide so late or
# long runs cost nothing
lilith shodan_cache -s 600

# the whole database, five hundred addresses at a time
lilith shodan_cache -s 0 --limit 500

# refetch everything, fresh or not -- after a schema or plan change
lilith shodan_cache -s 0 --force

# refetch one address right now
lilith shodan_cache --ip 8.8.8.8
```

| option      | what                                                          |
|-------------|----------------------------------------------------------------|
| `-s`        | How far back to read, in seconds. Default `180`; `0` reads everything. |
| `--tables`  | Comma separated alert tables to read. All four by default.     |
| `--limit`   | Stop after this many lookups. `0`, the default, is no limit.   |
| `--force`   | Look up even addresses the cache already holds fresh.          |
| `--ip`      | Update just this address instead of reading the alert tables. Implies `--force`. |
| `--dry-run` | Report what would be looked up without asking Shodan.          |

Three kinds of address are dropped before anything leaves the machine, in
this order: the ones that are not public (nothing to learn, and nothing that
should go to a third party), the ones the cache already holds fresh, and
anything past `--limit`. The summary line accounts for all of them, so a run
that did nothing says why. `--force` skips the freshness drop — that is what
makes it a refetch — and `--ip` implies it, since asking to update an address
that is held fresh would otherwise do nothing. The public-only drop is never
skipped.

`-s` only bounds how far back a run reads. What stops an address being looked
up twice is its own cache entry, so a window wider than the interval it runs
on is safe, and is what keeps an alert ingested between runs from being
missed. CAPE is read on its `stop` time, which can lag ingestion, so give it
room.

Shodan allows about a request a second and this obeys that, so a run costs
roughly a second per address it has to look up. In steady state that is a
handful. The first pass over a database that has been collecting for a while
is not — do that by hand, in bounded chunks, before putting it on a timer.
Ready made systemd units and a cron.d entry ship under `rc/`; see
[install](install.md#the-shodan-cache-timer).

Unlike the web frontend's Shodan section, this is not gated on
`enable_shodan` — running it is already the operator saying so, the same
reasoning that leaves the CLI escalation actions ungated. It does need
`shodan_cache_ttl` to be non-zero; with caching off there would be nowhere to
put an answer.

### cvedb_cache

Look up the CVE ids the Shodan cache names and store what CVEDB — Shodan's
free, keyless CVE database — says about each in the `cvedb_cache` table:
CVSS, the EPSS exploitation probability, the CISA KEV flag, known ransomware
use. That is what the IP info modal's CVE chips and the results tables' CVE
badges are annotated from; the web never asks CVEDB itself. See
[configuration](configuration.md#cvedb) for the settings.

```shell
# what a run would ask about, without asking
lilith cvedb_cache --dry-run

# the last twenty minutes of shodan_cache, for a timer run every minute --
# wide so late or long runs cost nothing
lilith cvedb_cache -s 1200

# the whole table, two hundred ids at a time
lilith cvedb_cache -s 0 --limit 200
```

| option      | what                                                          |
|-------------|----------------------------------------------------------------|
| `-s`        | How far back to read `shodan_cache`, in seconds, against each row's fetched time. Default `360` — twice `shodan_cache`'s default window; `0` reads everything. |
| `--limit`   | Stop after this many lookups. `0`, the default, is no limit.   |
| `--dry-run` | Report what would be looked up without asking CVEDB.           |

Each run reads the distinct CVE ids named by the `shodan_cache` rows fetched
in the `-s` window — a newly cached or freshly refreshed address is what
introduces new ids — drops anything that is not a CVE id in canonical form
(the ids come out of other people's data), and fetches what the cache has
never seen, then what is older than `cvedb_cache_ttl`, oldest first. A run
capped by `--limit` therefore spends its lookups on what the cache knows
least about. The summary line accounts for every id scanned, so a run that
did nothing says why.

`-s` only bounds how far back in `shodan_cache` a run reads. What stops an
id being fetched twice is its own cache entry, so a window wider than the
interval it runs on is safe, and it defaults to twice `shodan_cache`'s so a
run of this sees everything a run of that cached between the two. Stale rows
are served while they wait; the refresh is about drift (EPSS moves a little
daily, KEV grows), not correctness, and an id past `cvedb_cache_ttl` gets
its refresh when an address naming it is fetched or refreshed inside the
window — which `shodan_cache`'s own TTL cycle sees to. A `-s 0` run sweeps
everything on demand.

The pacing is a lookup a second out of politeness, so a run costs roughly a
second per id it fetches. In steady state that is a handful; the first pass
over a Shodan cache that has been filling for a while is every id it holds —
do that by hand, in bounded chunks, before putting it on a timer. Ready made
systemd units and a cron.d entry ship under `rc/`; see
[install](install.md#the-cvedb-cache-timer).

### And the rest

| command                     | what                                              |
|-----------------------------|---------------------------------------------------|
| `class_map`                 | Table of classification long name to the short name used in search results. |
| `get_short_class_snmp_list` | The shortened class names as used for SNMP.       |
| `dump_self`                 | Initiate Lilith and dump it via Data::Dumper.     |

## The web frontend

```shell
mojo_lilith daemon -l http://127.0.0.1:8080
LILITH_CONFIG=/etc/lilith.toml mojo_lilith prefork
```

All the standard Mojolicious server commands work. Read
[security](security.md) before exposing it — it is unauthenticated.

It offers the same searching, escalation, and PCAP fetching as the CLI, plus
the [dashboard](dashboard.md). Which pages appear depends on what is
configured — see [configuration](configuration.md).

## The EVE receiver

```shell
mojo_lilith_receiver daemon -l http://127.0.0.1:8081
LILITH_CONFIG=/etc/lilith.toml mojo_lilith_receiver prefork
```

Instead of Lilith tailing EVE files locally, a remote sensor can parse its
own EVE stream and push the resulting rows to a central Lilith. The sensor
does the same `parse_eve` work `lilith run` does and sends the row as JSON;
only the receiver touches the database.

- **Endpoint** :: `/eve/:table`, where `:table` is `suricata_alerts`,
  `sagan_alerts`, `cape_alerts`, or `baphomet_alerts`. An unknown table is a
  `404`. It takes either an HTTP `POST` per alert or a WebSocket the sensor
  streams alerts down (see below); both validate and insert identically.
- **Auth** :: `Authorization: Bearer <key>`, checked against the keys in the
  database (see below). No/invalid key, or a key not permitted for the
  client's IP, is a `401`; a key not permitted for the row's instance is a
  `403`. With no keys created every request is refused.
- **Body** :: a JSON object with one key per ingestable column for that table
  (the same keys `parse_eve` returns, including `raw`). `raw` may be sent as
  a JSON object or as a JSON string.
- **Rejected columns** :: `id`, `escalations`, and `auto_escalated` are set by
  the database and the escalation subsystem, never by a sensor. A body that
  carries any of them — or any key that is not a column of that table — is
  rejected with `400` rather than silently stripped, so a caller is never
  misled about what was stored.
- **Response** :: `201 {"status":"ok","id":<new id>}` on success; a `4xx`/`5xx`
  with `{"status":"error","error":...}` otherwise.

### Streaming over a WebSocket

A sensor pushing a lot of alerts can open one WebSocket per table instead of
paying for a request per alert:

```
GET /eve/:table   (Upgrade: websocket)
Authorization: Bearer <key>

-> {"instance":"...", ..., "raw":{ ... }}   one JSON frame per alert
<- {"status":"ok","id":123}                 one status frame back per alert
```

The bearer key and its IP scope are checked at the handshake, exactly as for
the POST, and a handshake for an unknown table is refused with the same `404`
rather than opening a socket with nowhere to write. Each frame carries the
same row object a POST body would, gets the same validation, and is answered
with the same body the POST would have rendered. A bad frame is reported but
leaves the connection up, so one malformed alert does not cost the rest of the
batch. Idle connections are never timed out, since a sensor may go quiet
between alerts.

[Lilu](https://github.com/LilithSec/App-Lilu) picks between the two with its
`lilith_websocket` config value.

### Managing keys

Keys are managed with the CLI and stored hashed (only the SHA-256 is kept):

| command                | what                                                       |
|------------------------|-------------------------------------------------------------|
| `receiver_key_create`  | make a key; prints it once. `--ip`/`--instance` scope it.   |
| `receiver_key_list`    | list keys with their IP and instance scopes and last use.   |
| `receiver_key_get`     | show one key (`--id` or `--name`) as JSON.                   |
| `receiver_key_update`  | change scope/enable/disable; `--clear-ips`/`--clear-instances` to widen. |
| `receiver_key_delete`  | remove a key (`--id` or `--name`).                          |

`--ip` takes a host or CIDR subnet; `--instance` takes an instance name or a
`*`/`?` glob (e.g. `foo-*` for every instance beginning `foo-`). Both are
repeatable and optional — an unset axis is unrestricted. To rotate a key,
delete it and create a new one.

```shell
# create a key scoped to a subnet and the foo-* instances (quote the glob so
# the shell does not expand it)
lilith receiver_key_create --name sensor1 --ip 10.0.0.0/8 --instance 'foo-*'

# then push with it
curl -sS -X POST http://127.0.0.1:8081/eve/suricata_alerts \
  -H 'Authorization: Bearer <the-printed-key>' \
  -H 'Content-Type: application/json' \
  --data '{"instance":"foo-pie","host":"sensor1","timestamp":"2026-07-14T00:00:00Z","raw":{...}}'
```

Read [security](security.md) before exposing it — in particular the
`MOJO_REVERSE_PROXY` note if the receiver runs behind a proxy.

## Environment variables

These shape the CLI's table output.

| variable                     | description                                | default |
|------------------------------|--------------------------------------------|---------|
| `Lilith_color_enable`        | Enable colored output at all (otherwise `NO_COLOR` is set). | `0` |
| `Lilith_table_color`         | The [Text::ANSITable](https://metacpan.org/pod/Text::ANSITable) color theme. | `Text::ANSITable::Standard::NoGradation` |
| `Lilith_table_border`        | The Text::ANSITable border style.          | `ASCII::None` |
| `Lilith_IP_color`            | Color IPs.                                 | `1` |
| `Lilith_IP_private_color`    | ANSI color for private IPs.                | `bright_green` |
| `Lilith_IP_remote_color`     | ANSI color for remote IPs.                 | `bright_yellow` |
| `Lilith_IP_local_color`      | ANSI color for local IPs.                  | `bright_red` |
| `Lilith_timestamp_drop_micro` | Drop microseconds from timestamps.         | `0` |
| `Lilith_timestamp_drop_offset`| Drop the TZ offset from timestamps.        | `0` |
| `Lilith_instance_color`      | Color the instance column.                 | `1` |
| `Lilith_instance_type_color` | Color for the instance name.               | `bright_blue` |
| `Lilith_instance_slug_color` | Color for the instance slug.               | `bright_magenta` |
| `Lilith_instance_loc_color`  | Color for the instance loc.                | `bright_cyan` |
