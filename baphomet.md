# Route A: `baphomet_alerts` ingestion — implementation plan

Add ingestion of the EVE log **Baphomet emits** (its own judgment log,
`eve_type: "baphomet"`; event types found/banish/noted/alert/sighting/sighted)
into Lilith, the same way Lilith ingests Suricata/Sagan/CAPE EVE. "Route A" =
a dedicated `baphomet_alerts` table + first-class `baphomet` EVE type.

Defaults chosen below are flagged **[default]** so they can be redirected.

## Design decisions (baked in)

- **Dedicated `baphomet_alerts` table**, schema **v9 → v10**.
- **Offender mapping:** Baphomet `.ip → src_ip` (so existing top-talkers /
  escalation / `%INET` reuse it); `.subject` stored in its own column.
- **`event_id`** (Baphomet has no flow identity):
  `sha256_base64(hostname . kur . timestamp . event_type . rule_name . (ip // subject))`.
- **[default] Ingest all six event types**, stored in an `event_type` column,
  with a per-instance `baphomet_event_ignore` knob (mirrors `suricata_sid_ignore`).
- **[default] Transport = file tail** (`type=baphomet` EVE instance);
  receiver-push is Phase 2.
- **`references` is a SQL reserved word** → the column is named **`refs`** to
  avoid quoting landmines in the generated INSERT.
- **jsonb columns** (`refs`, `attack`, `marks_set`, `unmarked`, `rule`,
  `found`, `raw`) are `encode_json`-ed to text inside `parse_eve`, so
  `insert_alert` stays unchanged.
- **Escalation is opt-in:** baphomet is added to search/stats/dashboard so it's
  viewable, but **not** added to the `{suricata,sagan,cape}` auto-escalation
  default.

## Reference facts (verified against the code, 2026-07-17)

- Lilith ingest spine: `%Lilith::alert_columns{$type}` (column-order source of
  truth) → `Lilith::parse_eve( type => … )` (per-type branch) →
  `Lilith::insert_alert` (builds INSERT from `%alert_columns`) → per-type
  `Schema::Result::*Alert` + DBIx migration. Transport: local file tail
  (`lilith`/`lilu run`, POE::Wheel::FollowTail) OR push to `Lilith::Receiver`
  `/eve/:table` (HTTP POST + WebSocket; `%TABLE_TYPE` allow-lists the tables).
- `parse_eve` early guard returns undef unless `event_type eq 'alert'` — this
  drops **every** Baphomet record, and Baphomet has its own `alert` event_type,
  so we must dispatch on the configured `type` **before** that guard.
- `insert_alert` table dispatch is a ternary
  `suricata_alerts : sagan_alerts : cape_alerts` (lib/Lilith.pm ~504).
- `run()` validates type with `ne 'suricata' && ne 'sagan' && ne 'cape'`
  (~842) and maps type→table in the POE handler (~875-882).
- Migrations are DBIx::Class::DeploymentHandler style under
  `share/migrations/PostgreSQL/{deploy/N,upgrade/N-M,downgrade/M-N}`. **deploy/N
  is the full schema at version N**; upgrade/N-M is incremental. Currently at
  **v9**. Newest triple = deploy/9, upgrade/8-9, downgrade/9-8.
- `Lilith::Stats` maps: `%TABLE`, `%TIME_COL` (cape uses `stop`, others
  `timestamp`), `%DIMENSION`, `%INET` (`src_ip`,`dest_ip`), `%VIRTUAL`,
  `%MEASURE`.
- `_auto_check_tables` (lib/Lilith.pm ~2580) defaults to
  `['suricata','sagan','cape']`.
- `App::Lilu` mirrors `%alert_columns` + `parse_eve` standalone (sensor boxes).
- Baphomet `_eve_emit` envelope (Galla.pm ~1088): top-level `eve_type`
  (`baphomet`), `event_type`, `timestamp` (`%Y-%m-%dT%H:%M:%S%z`), `hostname`,
  `kur`, merged with `%$fields` (`path`, `raw`, `parsed`, `found`, `msg`,
  `rule`, `severity`, `classtype`, `references`, `attack`, `score`,
  `marks_set`, `unmarked`); banish adds `ip`/`ban_time`/`recidive`/`country`,
  sighted adds `subject`. Baphomet EVE schema doc: `Baphomet/docs/eve.md`.

## Column layout (`%alert_columns{baphomet}` order = DDL order)

| # | column | ← Baphomet EVE | type |
|---|---|---|---|
| 1 | `instance` | configured name (default `kur`) | varchar(255) NOT NULL |
| 2 | `host` | `hostname` | varchar(255) NOT NULL |
| 3 | `timestamp` | `timestamp` | timestamptz NOT NULL |
| 4 | `event_id` | derived | varchar(64) NOT NULL |
| 5 | `event_type` | `event_type` | varchar(32) NOT NULL |
| 6 | `kur` | `kur` | varchar(255) |
| 7 | `path` | `path` | varchar(1024) |
| 8 | `score` | `score` | double precision |
| 9 | `signature` | `msg` | varchar(2048) |
| 10 | `severity` | `severity` | varchar(32) |
| 11 | `classification` | `classtype` | varchar(1024) |
| 12 | `refs` | `references` | jsonb |
| 13 | `attack` | `attack` | jsonb |
| 14 | `src_ip` | `ip` | inet |
| 15 | `subject` | `subject` | varchar(1024) |
| 16 | `ban_time` | `ban_time` | bigint |
| 17 | `recidive` | `recidive` | boolean |
| 18 | `country` | `country` | varchar(16) |
| 19 | `marks_set` | `marks_set` | jsonb |
| 20 | `unmarked` | `unmarked` | jsonb |
| 21 | `rule` | `rule` | jsonb |
| 22 | `found` | `found` | jsonb |
| 23 | `raw` | whole record | jsonb NOT NULL |
| — | `escalations` | (managed) | bigint[] |
| — | `auto_escalated` | (managed) | timestamptz |

Reusing `signature`/`classification`/`severity`/`attack`/`src_ip` names lets the
existing dashboard/search widgets light up with near-zero special-casing.

---

## Phase 1 — Lilith-side ingestion (self-contained)

### 1. Schema / migrations (v10)
- `share/migrations/PostgreSQL/upgrade/9-10/001-auto.sql` — `CREATE TABLE
  baphomet_alerts (...)` + indexes:
  ```sql
  CREATE INDEX baphomet_alerts_ts_idx       ON baphomet_alerts (timestamp);
  CREATE INDEX baphomet_alerts_event_ts_idx ON baphomet_alerts (event_type, timestamp);
  CREATE INDEX baphomet_alerts_src_ts_idx   ON baphomet_alerts (src_ip, timestamp);
  CREATE INDEX baphomet_alerts_kur_ts_idx   ON baphomet_alerts (kur, timestamp);
  ```
- `share/migrations/PostgreSQL/downgrade/10-9/001-auto.sql` — `DROP TABLE baphomet_alerts;`
- `share/migrations/PostgreSQL/deploy/10/001-auto.sql` — full-schema copy of
  `deploy/9` **plus** the `baphomet_alerts` block and its indexes.
- Bump the schema-version constant (in `Lilith::Schema`; verify against
  `SchemaVersion`/`Migrate` commands) from 9 → 10.
- `lib/Lilith/Schema/Result/BaphometAlert.pm` — new DBIx::Class result, modeled
  on `SuricataAlert.pm` (`__PACKAGE__->table("baphomet_alerts")`, `add_columns`,
  PK `id`).

### 2. Core ingest (`lib/Lilith.pm`)
- Add `baphomet => [ … 23 cols … ]` to `%alert_columns`.
- **Restructure the `parse_eve` guard** — dispatch on the configured `type`
  before the `event_type eq 'alert'` check:
  ```perl
  return $self->_parse_baphomet($json, \%opts) if defined($type) && $type eq 'baphomet';
  # suricata/sagan/cape keep the existing event_type eq 'alert' guard
  ```
- New `_parse_baphomet` helper: gate to the six known `event_type`s minus
  `baphomet_event_ignore`; derive `event_id`; map the table above; `encode_json`
  the jsonb fields (`refs`/`attack`/`marks_set`/`unmarked`/`rule`/`found`);
  `instance = configured // kur`.
- `insert_alert`: extend the `suricata_alerts : sagan_alerts : cape_alerts`
  ternary with `baphomet → baphomet_alerts`.
- `run()`: add `baphomet` to the accepted-type check and to the type→table map
  in the POE handler.
- New config knob `baphomet_event_ignore` (array, default `[]`) alongside
  `suricata_sid_ignore` in `new()`.

### 3. Read/aggregation surface
- `lib/Lilith/Stats.pm`: add `baphomet` to `%TABLE`, `%TIME_COL`
  (`timestamp`), `%DIMENSION` (`instance host kur event_type severity
  classification src_ip subject signature`); optional `%MEASURE` (`avg`/`max` of
  `score`). `src_ip` already covered by `%INET`.
- `lib/Lilith.pm` `_auto_check_tables`: add `baphomet` to the default
  `['suricata','sagan','cape']`.
- Web + CLI type selectors — wherever the three types are enumerated:
  `Web/Controller/{Dashboard,Search,Event}.pm`, `CLI/Command/{Search,Event}.pm`.
  (Escalation controllers/commands left as-is → escalation opt-in.)

### 4. Standalone parity (`App-Lilu`)
- Mirror the `%alert_columns{baphomet}` entry, the `parse_eve` baphomet branch,
  and the type validation in `App::Lilu` + `src_bin/lilu`, so a sensor box can
  tail Baphomet's `eve.json` without the full Lilith.

### 5. Config & docs
- `lilith.toml` example:
  `[eves.baphomet-sshd] type="baphomet" eve="/var/log/baphomet/eve.json"`.
- Document `type=baphomet` and `baphomet_event_ignore` in the Lilith config
  docs; note the offender-mapping and event_id semantics.

### 6. Tests + bookkeeping
- `t/lilith-parse-eve.t`: baphomet cases — a `banish` (has
  `ip`/`ban_time`/`country`), a `sighted` (has `subject`, no `ip`), a `found`,
  an ignored `event_type`, and jsonb-field encoding.
- `t/pg-migrate.t` / `t/lilith-migrate-cli.t`: assert v10 deploy + 9→10→9
  round-trip.
- `MANIFEST`: add the new Schema result + three migration files (`manifest.t`
  enforces).
- `Changes`: note the new `baphomet` EVE type + `baphomet_alerts` table under
  4.0.0.

## Phase 2 — receiver push (optional, cross-host)
- `lib/Lilith/Receiver.pm`: add `baphomet_alerts => 'baphomet'` to `%TABLE_TYPE`
  (+ POD). Then both the HTTP POST and the WebSocket stream accept
  `/eve/baphomet_alerts` for free.
- Baphomet-side (separate repo): a small `send_alert`-style emitter mirroring
  `App::Lilu`, POSTing/streaming each EVE record to the receiver — so a Baphomet
  sensor needs no DB creds. Only cross-repo work; cleanly deferrable.

## Out of scope (deliberately)
- `extend()` (LibreNMS) stays suricata+sagan only.
- Auto-escalation default array `{suricata,sagan,cape}` unchanged (baphomet
  escalation opt-in).

## Touch count
~7 new files (Schema result, 3 migrations, tests) + ~10 edited (`Lilith.pm`,
`Stats.pm`, `Schema.pm`, 2 web + 2 CLI selectors, `App::Lilu`, `Changes`,
`MANIFEST`) for Phase 1; +2 files for Phase 2.

## Open toggles to reconsider at implementation time
- Event-type set (currently all six + ignore knob) vs. actions-only
  (banish+alert) vs. banish-only.
- Transport (file tail now; receiver push Phase 2) vs. push-first.
- Whether baphomet joins the escalation / auto-escalation defaults.
