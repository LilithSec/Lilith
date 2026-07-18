# Allani log viewer — web front-end plan

Add a read-only **Logs** page to `Lilith::Web` for browsing the logs **Allani**
stores (its PostgreSQL `syslog` / `http_access` / `http_error` tables). Allani
is the household's syslog store (syslog-ng JSON → PostgreSQL); it has no HTTP
server yet, so Lilith reads its tables directly over a dedicated connection.

This is a **standalone `/logs` surface**, deliberately *not* a fourth entry in
the `suricata|sagan|cape` alert-type switch. Decisions below are flagged
**[default]** where they can be redirected.

## Design decisions (baked in)

- **Standalone page**, its own controller/templates/route — no changes to
  `Lilith::search`, `Lilith::Stats`, the alert-type regex, or the escalation
  path. This sidesteps the two gates that killed the "4th type" approach: one
  shared DB handle, and the hardcoded `escalations` column.
- **Depends on Allani being installed.** Lilith `use`s `Allani::Sources` as the
  single source of truth for the per-source whitelist (tables, timestamp
  columns, exact-match filter columns, dimensions, display columns) and its
  `build_where` / `select_and_headers` query helpers. `Allani` becomes a
  runtime prereq in `Makefile.PL`. No metadata is copied into Lilith.
- **Own DB connection** via an `[allani]` TOML block (`dsn` / `user` / `pass`),
  read-only. The feature is **off unless `[allani]` is configured** (mirrors
  `virani_enabled`). Works whether or not Allani is co-located with Lilith's DB.
- **Four sources in one selector:** `syslog`, `http` (→ `http_access`),
  `http_error`, and `http_all` (the interleaved http view). The first three come
  straight from `Allani::Sources`; `http_all` is the *only* thing Lilith adds on
  top — an app-level `UNION ALL` of the two http tables, ordered by `r_isodate`,
  with a `log_source` discriminator column. No DB view, no Result class.
- **Read-only.** Lilith only SELECTs Allani; no ingest/enrich/prune/index from
  the web. Columns are whitelisted by `Allani::Sources`; every value is bound.
- **Behind the existing web auth** like the rest of the UI (log bodies can carry
  secrets); no separate exposure.

## Reference facts (verified against the code, 2026-07-17)

- **Allani store** (`/home/kitsune/github/Allani`): PostgreSQL tables `syslog`,
  `http_access`, `http_error`, each with a `raw` jsonb. `Allani::Sources`
  centralizes `%SOURCES` (per source: `table`, `ts` columns + `default_ts`, `eq`
  exact-match cols, `dims`, `display` `[header, expr]` pairs), `%FILTER_COL`,
  `%LIKEABLE`, and the helpers `source($name)`, `names()`, `filter_opt_spec()`,
  `build_where($meta,$opt)`, `select_and_headers($meta,$tscol,$json,$with_id)`.
  `syslog` cols: `c_isodate`/`r_isodate`/`s_isodate` (default `s_isodate`),
  `facility`, `host`, `host_from`, `pid`, `priority`, `program`, `sourceip`,
  `raw`. http tables key off `r_isodate`. `Allani::duration_to_interval('24h')`
  turns a window string into an interval. No mojo/HTTP server exists yet.
- **`build_where` impedance:** it reads its filters off an **App::Cmd-style opt
  object** (`$opt->$accessor` for each `%FILTER_COL` key, plus `$opt->message`,
  `$opt->field`). From a web controller we hand it a tiny accessor shim (a
  blessed hash with an `AUTOLOAD` returning `$self->{$name}`) populated from the
  sanitized query params — so the whitelist/validation stays in `Allani::Sources`
  and Lilith adds no SQL of its own for the three real sources.
- **Lilith web wiring** (`lib/Lilith/Web.pm`): TOML is parsed in `startup`; the
  `[virani.*]` block at ~216-234 registers `virani_remotes`/`virani_enabled`
  helpers — the exact shape to mirror for `[allani]`. Routes are registered at
  ~338-380 (`/search`, `/dashboard`, `/event/:table/:id`, …). Nav buttons live
  in `share/templates/layouts/default.html.ep` (~28-29:
  `<a class="btn ..." href="/search" id="nav-search">Search</a>` etc.).
- **Search page shape to clone** (`Web::Controller::Search` +
  `search/index.html.ep` + `search/_results.html.ep`): a sanitized `table`
  param, `go_back_minutes`/`limit`/`offset`/`order_*`, a single `search()` call,
  and a `partial=1` fragment render for auto-refresh. The `cape-filters`
  show/hide JS is the template for per-source filter fields.

## Sources as presented on `/logs`

| selector | Allani source | table / relation | time col | display cols (from `Allani::Sources`) |
|---|---|---|---|---|
| `syslog` | `syslog` | `syslog` | `s_isodate` | host, program, message (`raw->>'MESSAGE'`) |
| `http` | `http_access` | `http_access` | `r_isodate` | vhost, client, status, method, request |
| `http_error` | `http_error` | `http_error` | `r_isodate` | level, client, code, message |
| `http_all` | *(Lilith)* | `http_access ∪ http_error` | `r_isodate` | source, host, client, vhost/server, status/code, method/level, message |

Per-source filters come from each source's `eq` set + `message`/`field`
(`Allani::Sources::filter_opt_spec`); `http_all` accepts the intersection
(`host`, `client_ip`, `vhost`, `message`, `field`).

## Phase 1 — the Logs page (self-contained)

### 1. Config + wiring (`lib/Lilith/Web.pm`)
- Parse an `[allani]` table (`dsn`/`user`/`pass`); build `%allani_cfg`.
- `allani_enabled` helper (true iff a `dsn` is set) and an `allani` helper
  returning a cached `Lilith::Allani` reader built from `%allani_cfg`.
- Routes: `$r->get('/logs')->to('logs#index')` and
  `$r->get('/logs/:source/:id')->to('logs#view')` (raw-record detail). Add an
  `/api/logs/*` JSON route only if the results move to client-side fetch; Phase 1
  server-renders like Search.

### 2. Reader (`lib/Lilith/Allani.pm`)
- `new(dsn,user,pass)`; `_dbh` via `DBI->connect_cached`. Does **not** use
  Allani's app object — just `Allani::Sources` metadata + `DBI`.
- `sources()` — the four selector entries above (label + internal key).
- `search( source, %filters, since, order_dir, limit, offset )` — resolves the
  source via `Allani::Sources::source`, builds the WHERE with `build_where` (fed
  the accessor shim), adds the `since`/window on the source's timestamp column
  (`Allani::duration_to_interval`), selects `id`, the ts col aliased `time`, and
  the `display` exprs aliased to their header names, then `fetchrow_hashref`.
  Whitelist + binds all live in `Allani::Sources`.
- `http_all` special case: a `UNION ALL` of the two http tables projected onto
  the normalized column set + a `'http_access'`/`'http_error'` `log_source`
  literal, ordered by `r_isodate`. This is the one Lilith-authored query.
- `row( source, id )` — one record including decoded `raw`, for the detail view.

### 3. Controller (`lib/Lilith/Web/Controller/Logs.pm`)
- `index`: sanitize `source` against `Allani::Sources::names` + `http_all`
  (default `syslog`); `since`/`limit`/`offset`/`order_dir`; collect the
  source-valid filter params; call `allani->search`; stash results. Honor
  `partial=1` → render `logs/_results` with `layout => undef` (auto-refresh),
  exactly like `Search::index`. 400/empty gracefully when `!allani_enabled`.
- `view`: `allani->row`, pretty-print `raw` (reuse the Event page's
  `JSON->new->pretty->canonical` treatment).

### 4. Templates
- `share/templates/logs/index.html.ep` — source `<select>`, per-source filter
  fields with show/hide JS (model on `search/index.html.ep`'s `cape-filters`
  toggle), window/limit, `#log-results` container, auto-refresh hook.
- `share/templates/logs/_results.html.ep` — per-source `<thead>`/`<tbody>`
  driven by the source's `display` headers; each row's `id` links to
  `/logs/:source/:id`; `sourceip`/`client_ip` reuse the existing `ip-filter` /
  GeoIP badge treatment from `search/_results.html.ep`.
- `share/templates/logs/view.html.ep` — the single-record raw-JSON detail.
- `share/templates/layouts/default.html.ep` — a **Logs** nav button after
  Dashboard, wrapped `% if (allani_enabled) { ... }`.

### 5. Packaging + docs + tests
- `Makefile.PL`: add `Allani` to `PREREQ_PM`.
- `MANIFEST`: new reader, controller, three templates.
- Config docs + example `lilith.toml`: `[allani] dsn="dbi:Pg:dbname=allani"
  user="..." pass="..."`.
- `Changes`: note the Allani log viewer.
- `t/`: a `Lilith::Allani` reader test (source validation, WHERE via the shim,
  `http_all` union shape) against a fixture DB or mocked `$dbh`; a controller
  test that `/logs` renders and that it's absent/empty without `[allani]`.

## Phase 2 — event context (optional, deferred)
On the Event page, when an alert carries `host`/`src_ip`/`timestamp`, add "Logs
around this event" deep-links to
`/logs?source=syslog&host=<host>&since=<window>` (and an http variant keyed on
`client_ip`). This is the log analogue of the existing Virani "fetch this flow's
PCAP" button — purely additive, no new reader work.

## Out of scope (deliberately)
- No log **dashboard**/aggregation in Phase 1 (would reuse Allani `dims`; a
  later `Lilith::Allani`-side `top`/`timeseries` if wanted).
- No writes to Allani (ingest/enrich/prune/index stay CLI-only).
- No escalation/auto-escalation of log lines.

## Touch count
~4 new files (`Lilith::Allani`, `Logs` controller, 3 templates — counting
`view`) + ~4 edits (`Web.pm`, `layouts/default.html.ep`, `Makefile.PL`,
`MANIFEST`, `Changes`) for Phase 1; Phase 2 is one edit to the Event template.

## Open toggles to reconsider at implementation time
- `http_all` normalized projection (which columns survive the union).
- Whether `field`/`message` search is exposed in the web filters from day one
  (the `raw->'enriched'` predicates can be slow without a per-key `allani index`).
- Server-render + `partial` (Phase 1) vs. a `/api/logs` JSON + client fetch.
- Detail view route `/logs/:source/:id` vs. reusing `/event`-style plumbing.
