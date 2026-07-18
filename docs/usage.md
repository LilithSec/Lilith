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

- **/search** — the same filters as the CLI search, in a form. Escalated
  events are badged with a red **E**. The **When** control switches the time
  window between *Last N min* (relative) and *Range* (an explicit From/To); the
  range bounds are read in the server's timezone.
- **/logs** — browse the logs an [Allani](https://github.com/LilithSec/Allani)
  store holds, when an `[allani]` block is configured. A source selector
  switches between syslog, http (access), http error, and an interleaved
  http view; per-source filters, a minutes-back window, paging, and
  optional auto-refresh mirror the search page, and each row opens the full
  stored record with its raw JSON. For charts over the same logs, the
  configurable [dashboard](dashboard.md) reads Allani sources too — set its
  **Default table** to a log source, add log widgets, or pick a built-in
  per-source preset (Syslog, HTTP, HTTP Access, HTTP Error). The page and its
  navbar entry stay hidden without `[allani]` — see
  [configuration](configuration.md).
- **Event view** — the full event with the decoded EVE record. IPs open an
  info modal (reverse DNS, whois, GeoIP when databases are configured);
  domains an info panel with whois and DNS, plus an **HTTPS** button
  (certificate and per-phase timing detail against `https://DOMAIN:PORT/`)
  and a **Mail** button (combined SPF / DMARC / DKIM check). With
  `[virani.*]` remotes configured, a **Download PCAP** control fetches the
  flow PCAP (see below). With `[allani]` configured, a **Logs** dropdown
  deep-links to `/logs` pre-filtered by the event's host (syslog) and source
  IP (interleaved http), windowed to reach back around the event. With
  `escalation_enable` on, an **Escalate** button and the escalation history
  appear ([escalation](escalation.md)).
- **Virani dropdown** — appears in the navbar when any `[virani.*]` remote
  is configured. **PCAP Search** takes an arbitrary BPF filter and time
  range: it always builds a ready-to-copy local `virani` command, and with
  `virani_search_enable` on it can download straight through the web
  server. With that option on, **Cached Searches** lists the remote's most
  recent (up to 50) cached searches with per-row download.
- **Download PCAP** — fetches the PCAP for the event's flow (src/dest IP
  and ports over the flow window, widened by 60 seconds each end) and
  streams it back. The set to pull from is selectable (queried live from
  the remote), and a dropdown offers the equivalent `virani` command to run
  on the box holding the PCAPs instead.

## The EVE receiver

```shell
mojo_lilith_receiver daemon -l http://127.0.0.1:8081
LILITH_CONFIG=/etc/lilith.toml mojo_lilith_receiver prefork
```

Instead of Lilith tailing EVE files locally, a remote sensor can parse its
own EVE stream and push the resulting rows to a central Lilith. The sensor
does the same `parse_eve` work `lilith run` does and POSTs the row as JSON;
only the receiver touches the database.

- **Endpoint** — `POST /eve/:table`, where `:table` is `suricata_alerts`,
  `sagan_alerts`, `cape_alerts`, or `baphomet_alerts`. An unknown table is a
  `404`.
- **Auth** — `Authorization: Bearer <key>`, checked against the keys in the
  database (see below). No/invalid key, or a key not permitted for the
  client's IP, is a `401`; a key not permitted for the row's instance is a
  `403`. With no keys created every request is refused.
- **Body** — a JSON object with one key per ingestable column for that table
  (the same keys `parse_eve` returns, including `raw`). `raw` may be sent as
  a JSON object or as a JSON string.
- **Rejected columns** — `id`, `escalations`, and `auto_escalated` are set by
  the database and the escalation subsystem, never by a sensor. A body that
  carries any of them — or any key that is not a column of that table — is
  rejected with `400` rather than silently stripped, so a caller is never
  misled about what was stored.
- **Response** — `201 {"status":"ok","id":<new id>}` on success; a `4xx`/`5xx`
  with `{"status":"error","error":...}` otherwise.

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
| `Lilith_timesamp_drop_micro` | Drop microseconds from timestamps.         | `0` |
| `Lilith_timesamp_drop_offset`| Drop the TZ offset from timestamps.        | `0` |
| `Lilith_instance_color`      | Color the instance column.                 | `1` |
| `Lilith_instance_type_color` | Color for the instance name.               | `bright_blue` |
| `Lilith_instance_slug_color` | Color for the instance slug.               | `bright_magenta` |
| `Lilith_instance_loc_color`  | Color for the instance loc.                | `bright_cyan` |
