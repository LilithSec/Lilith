# Architecture

## The shape of it

```
  Suricata            Sagan              CAPEv2 (via CAPE::Utils)
  eve.json            eve.json           eve-ish json
     |                   |                  |
     v                   v                  v
  +---------------------------------------------+
  |  lilith run --- the ingest daemon           |
  |  one POE::Wheel::FollowTail per [eves.*]    |
  +---------------------|-----------------------+
                        v
                  PostgreSQL
     suricata_alerts / sagan_alerts / cape_alerts
     escalation_targets / escalations / auto_escalations
        |                |                 |
        v                v                 v
  lilith (CLI)      mojo_lilith       lilith auto_escalate
  search, event,    Mojolicious       (systemd timer / cron)
  extend, esc_*,    web frontend      rules -> escalate()
  ae_*                  |
                        v
                Virani (remote, HTTP) --- the flow PCAP behind an alert
```

There is no long running process besides the ingest daemon and (if you run
it) the web server. Everything else — the CLI, the LibreNMS extend, the
auto escalation run — connects to PostgreSQL, does its work, and exits.
The database is the meeting point; anything that can reach it can read the
annals.

## The ingest daemon

`lilith run` reads the config, and for every instance under `[eves.*]`
creates a [POE](https://metacpan.org/pod/POE) session with a
`POE::Wheel::FollowTail` following that EVE file. Each line is decoded as
JSON; anything that is not an `alert` event is ignored. A malformed
instance (missing `eve` or an unknown `type`) is warned about and skipped,
so one bad entry does not stop monitoring of the valid ones. Errors also go
to syslog (facility `daemon`).

For every alert an `event_id` is computed as the SHA256 (base64) of
instance + host + timestamp + flow id + interface, giving a stable handle
for the event independent of its row ID. The interesting fields are pulled
into real columns and the entire EVE record is stored alongside them in the
`raw` jsonb column, so nothing is lost to the flattening.

With `--daemonize` it forks into the background via
`Net::Server::Daemonize`, optionally dropping to `--user` / `--group`. It
needs read access to the EVE files and nothing else beyond the database.

For a box that only needs to feed the annals — a sensor with no use for
the search CLI, the web frontend, or escalation —
[Lilu](https://github.com/LilithSec/App-Lilu) (`App::Lilu`) is a cut down,
standalone reimplementation of just this daemon and the extend. Same
tables, same event IDs, same extend output, same `[eves.*]` config shape
(in `/usr/local/etc/lilu.toml`), and no dependency on Lilith itself, so
the sensors carry a much smaller dependency chain. See
[install](install.md).

## The tables

PostgreSQL is required — the `raw` column is jsonb, and the schema is
managed with
[DBIx::Class::Migration](https://metacpan.org/pod/DBIx::Class::Migration)
(currently schema version 3; see [install](install.md) for the
`dbic-migration` invocations).

| table                | what                                                         |
|----------------------|--------------------------------------------------------------|
| `suricata_alerts`    | Suricata alerts — flow tuple, classification, sig, gid/sid/rev, flow counters, `raw` |
| `sagan_alerts`       | Sagan alerts — as above plus facility, level, priority, program, xff, and both the sending `host` and the `instance_host` the instance runs on |
| `cape_alerts`        | CAPEv2 detonations — target, task, malscore, hashes, package, slug, submission source, start/stop |
| `escalation_targets` | where word can be sent — name, type, per-type jsonb config, enabled flag |
| `escalations`        | the audit trail — every escalation attempt, its status, error, and the raw payload actually sent |
| `auto_escalations`   | the standing orders — match/actions rule DSL, priority, table scoping, match stats |

Each alert table also carries a `escalations bigint[]` column (the IDs of
escalations recorded for that row, appended in the same transaction as the
`escalations` insert) and an `auto_escalated` timestamp (when the auto
escalation run last considered the row, so each alert is evaluated exactly
once). Anything reading the alert tables can therefore see whether and how
often an alert was escalated without touching the `escalations` table.

## The CLI

`lilith` is an [App::Cmd](https://metacpan.org/pod/App::Cmd) application;
each action is a subcommand under `Lilith::CLI::Command`. Global options
(`--config`, `--debug`, `--version`) come before the subcommand, and a bare
`lilith` (or one whose first argument is an option) runs `search`. See
[usage](usage.md).

## The web frontend

`mojo_lilith` is a [Mojolicious](https://metacpan.org/pod/Mojolicious) app
(`Lilith::Web`) started with the standard Mojolicious server commands
(`daemon`, `prefork`, ...). It reads the same config file, via the
`LILITH_CONFIG` env var when set. It serves:

- `/search` — the annals, filtered and paged, with per-event badges
- `/event/<table>/<id>` — a single event in full, with the decoded `raw`,
  IP/domain info lookups, escalation, and PCAP download via Virani
- `/escalation` and `/auto_escalation` — target and rule management, each
  gated by its own config option (see [escalation](escalation.md) and
  [security](security.md))
- `/api/...` — the JSON endpoints behind all of the above

Blocking work — Virani fetches, whois/DNS lookups, escalation sends — runs
in subprocesses so the event loop is never stalled by a slow remote.

## The EVE receiver

`mojo_lilith_receiver` (`Lilith::Receiver`) is the network counterpart to the
local ingest daemon. Instead of Lilith tailing EVE files on the database host,
a remote sensor parses its own EVE stream with the same `parse_eve` and POSTs
each row to `POST /eve/:table`. The receiver authenticates the bearer key,
validates the body against that table's column set — rejecting the
database/escalation-managed columns (`id`, `escalations`, `auto_escalated`)
outright — and inserts through the shared `Lilith::insert_alert`, the same
method the local tailer uses, so neither can drift from `%Lilith::alert_columns`.
Sensors thus need no database credentials of their own.

Keys live in the `receiver_apikeys` table (managed with `lilith
receiver_key_*`), stored as their SHA-256. Each key can be scoped to a set of
client IPs/subnets and instance names: the IP check happens up front (a Postgres
`inet <<= any(cidr[])` containment test, so subnets and IPv6 just work), while
the instance check runs once the body is parsed, matching the row's `instance`
against the key's patterns — which may use `*`/`?` wildcards. An unset axis is
unrestricted.

## The auto escalation timer

`lilith auto_escalate` is a periodic, run-to-completion job: it loads the
enabled rules from `auto_escalations`, evaluates them (via
[Rule::Engine](https://metacpan.org/pod/Rule::Engine)) against alerts
ingested within its `-m` window that have not yet been considered, and
escalates matches through the same path as a manual escalation — same audit
trail, same per-row `escalations` array. Ready made systemd service+timer
units and a cron entry ship under `rc/`. See
[escalation](escalation.md).

## Where Lilith sits in the pantheon

- **[Baphomet](https://github.com/LilithSec/Baphomet)** reads logs and
  *accuses*: consigns repeat offenders to Ereshkigal.
- **[Ereshkigal](https://github.com/LilithSec/Ereshkigal)** works the
  firewall and *punishes*: holds the banned below and releases them when
  their time is served.
- **[Lamashtu](https://github.com/LilithSec/Lamashtu)** *remembers*: hoards
  the raw packets in rotating pcaps.
- **[Virani](https://github.com/LilithSec/Virani)** *reads*: given a window
  and a filter, carves the matching packets back out of the hoard.
- **[Lilu](https://github.com/LilithSec/App-Lilu)** *carries*: a cut down
  Lilith — only the ingest daemon and the extend — for sensor boxes that
  just feed the annals.
- **Lilith** *knows*: the alerts of the watchers — Suricata, Sagan,
  CAPEv2 — are written into her annals to be searched, examined, and sent
  onward.

Lilith depends on none of her household, but she and Virani work well
together: when one or more remote `mojo-virani` servers are configured
(`[virani.*]` in the config), the event view can fetch the flow PCAP behind
a Suricata alert — the flow's tuple over its window, widened by a buffer —
straight from the box holding the captures Lamashtu wrote. Suricata, Sagan,
and CAPEv2 are not part of the household; they are the watchers in the
night whose cries she keeps.
