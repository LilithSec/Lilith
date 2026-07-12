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
covered in [escalation.md](escalation.md).

### run

Start following the configured EVE files into PostgreSQL. Not expected to
return.

```shell
lilith run [--daemonize] [--user <user>] [--group <group>]
```

On a box that only feeds the annals,
[Lilu](https://github.com/LilithSec/App-Lilu)'s `lilu run` / `lilu extend`
do the same jobs without the rest of Lilith; see
[install.md](install.md).

### search

Search the annals. Which table via `-t` (`suricata` (default), `sagan`, or
`cape`); output as an ANSI table or `--output json`.

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
lilith-web daemon -l http://127.0.0.1:8080
LILITH_CONFIG=/etc/lilith.toml lilith-web prefork
```

All the standard Mojolicious server commands work. Read
[security.md](security.md) before exposing it — it is unauthenticated.

- **/search** — the same filters as the CLI search, in a form. Escalated
  events are badged with a red **E**.
- **Event view** — the full event with the decoded EVE record. IPs open an
  info modal (reverse DNS, whois, GeoIP when databases are configured);
  domains an info panel with whois and DNS, plus an **HTTPS** button
  (certificate and per-phase timing detail against `https://DOMAIN:PORT/`)
  and a **Mail** button (combined SPF / DMARC / DKIM check). With
  `[virani.*]` remotes configured, a **Download PCAP** control fetches the
  flow PCAP (see below). With `escalation_enable` on, an **Escalate**
  button and the escalation history appear ([escalation.md](escalation.md)).
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
