# Log dashboard

The web frontend's `/logs/dashboard` is an at-a-glance overview of the logs an
[Allani](https://github.com/LilithSec/Allani) store holds, drawn with a vendored
[Chart.js](https://www.chartjs.org/). Where the alert
[dashboard](dashboard.md) is a configurable grid over Lilith's own annals, this
is a **fixed** dashboard over Allani's log tables — no saved boards, no edit
mode. It is reached from the **Logs → Dashboard** entry in the navbar, which
only appears when an `[allani]` block is configured (the frontend is
unauthenticated — see [security](security.md)). Omit `[allani]` and the page,
like the rest of the log viewer, stays hidden.

Aggregation runs over the three real single-table sources; the interleaved
`http_all` view offered on the [log search page](usage.md) is **not** a
dashboard source.

## Controls

Along the top:

- **Source** — which log table the panels read: `syslog`, `http (access)`, or
  `http error`. Changing it reloads the page, and the top-value panels follow
  that source's own dimensions.
- **When** — a preset relative window (Last hour … Last 30 days) or a **Custom
  range** with From/To pickers (native date plus 24-hour hour/minute) every panel
  covers.
- **Bucket** — the time-bucket the "rows over time" chart uses: `auto` (the
  default), or a fixed `minute` / `hour` / `day` / `week` / `month`. `auto`
  sizes the bucket to the window (minute up to 3h, hour up to 2d, day up to 90d,
  week up to ~2y, month beyond) so a long window does not produce a giant
  minute-series; the resolved unit is shown next to the chart title.
- **Split by** — split the over-time chart per value of a dimension, drawn as a
  stacked bar (restricted to that dimension's busiest handful of values). `(none)`
  is the plain total line. This is how an error spike shows up: split syslog by
  `priority`, http by `status`, http_error by `loglevel`.
- **Measure** — what the over-time and top panels aggregate: `Count` (rows), or,
  for `http (access)`, `Total bytes` (sum of the `bytes` column) — so "top vhosts
  by Total bytes" is a traffic panel rather than a hit count.
- **Apply** — reloads with the chosen source/window.
- **Log Search →** — jumps to the `/logs` search page for the same source.

## Panels

- **Total log rows** and **Distinct hosts** — stat cards for the source/window.
- **Over time** — a line chart of the measure per time bucket, or a stacked bar
  when **Split by** is set.
- **Top &lt;dimension&gt;** — up to four charts, one per dimension the source
  offers (its `default_dim` first), each the ten busiest values. Low-cardinality
  dimensions (`priority`, `facility`, `method`, `status`, `loglevel`, `code`) are
  drawn as doughnuts; the rest as horizontal bars. For `syslog` the dimensions
  are program / facility / host / host_from; for the http sources vhost or server
  / host / method or loglevel / status or code.
- **Source countries** — the busiest source IPs (`sourceip` for syslog,
  `client_ip` for the http sources) resolved to countries through the GeoIP
  databases the web UI opens. Shown only when an MMDB is configured (see
  [configuration](configuration.md)).

The dimensions and measures come from Allani's own per-source definitions, and
every value is bound, so a panel can only group by or sum a column that source
actually has.

## Endpoints

The shell page renders even when the database is unreachable; the browser pulls
the numbers from JSON endpoints, each taking `source` and `go_back_minutes`:

- `GET /api/logs/summary` — `{ total, distinct_host }`.
- `GET /api/logs/top?column=&limit=&measure=` — `{ rows: [ { value, count }, ... ] }`.
- `GET /api/logs/timeseries?bucket=&group_by=&measure=` —
  `{ rows, bucket, grouped }`; with `group_by` each row carries a `group` and
  `grouped` is 1, and `bucket` is the unit actually used (so `auto` can be
  labelled).
- `GET /api/logs/countries` — `{ enabled, rows: [ { country, count }, ... ] }`;
  `enabled` is 0 (rows empty) when no MMDB is configured.

A bad source, column, measure, or bucket comes back as a 400 rather than
reaching the database.
