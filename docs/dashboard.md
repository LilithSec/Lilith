# Dashboard

The web frontend's `/dashboard` is a configurable overview of the annals: a grid
of chart widgets over the same alerts the search page lists, drawn with a
vendored [Chart.js](https://www.chartjs.org/) and laid out with a vendored
[Gridstack](https://gridstackjs.com/). It is reached from the **Dashboard** link
in the navbar (the frontend is unauthenticated — see [security](security.md)).

## Controls

Along the top:

- **Dashboard** — which saved board to show. Pick another to switch to it; the
  star (★) marks the default board (the one loaded first).
- **Default table** — the annal the stat cards read, and the default for any
  widget that does not set its own: Suricata, Sagan, or CAPE. Each widget can
  override it (see the widget config below), so one board can span tables.
- **Time range** — 1h / 6h / 24h / 7d.
- **Show GPCD** — off by default. When off, `Generic Protocol Command Decode`
  alerts are excluded everywhere (as the search page hides them). Tick it to
  include them. Only affects tables with a classification (Suricata/Sagan).
- **Refresh** — re-pulls all data for the current controls.
- **Edit** — toggles edit mode (see below). Its dropdown holds the board actions:
  **New dashboard**, **Rename**, **Set as default**, and **Delete**.

The **Default table**, **Time range**, and **Show GPCD** controls are per-board: each
board remembers its own, restored when you switch to it. Changing them just
re-draws until you save (in edit mode).

Below the controls is a fixed strip of stat cards (total alerts, unique sources,
a per-table detail count, escalated, and the busiest sensor), and then the
widget grid.

## Edit mode

The board is **read-only until you click Edit**. In view mode the grid is
locked — widgets can't be moved or resized, so casually dragging one never
overwrites the saved layout. Clicking **Edit** unlocks it and reveals the
editing controls:

- **+ Add widget** — opens the widget picker (see below).
- **Reset layout** — replaces this board's widgets with the built-in set.
- Each widget grows a gear (reconfigure) and an × (remove), **drags by its
  title** to reorder, and **resizes from the bottom-right corner**.

While editing, layout and control changes are saved automatically; click
**Done** to leave edit mode and lock the grid again.

Boards are stored in the database and, because the web UI has no accounts, are
**shared, not per-user**. They persist across reloads. A brand-new board starts
empty; the built-in `default` board comes seeded with the widget set below.

## Widget types

- **Alerts over time** — a stacked bar over the time range, optionally split by a
  column (the default splits by classification/target).
- **Top values** — the most common values of any column, as a **bar or pie**,
  showing between 1 and 50 values.
- **Source countries** — the busiest source IPs resolved to countries through the
  GeoIP databases (needs an MMDB configured, see [configuration](configuration.md);
  otherwise the panel notes it is unavailable).

The column pickers are driven by the backend's own list of accepted columns, so
they only offer columns that table actually supports.

### Measures

The **Top values** and **Alerts over time** widgets take a *measure* — what to
aggregate, instead of just counting rows:

- **Count** (default) — number of alerts.
- **Total bytes / packets** (Suricata) — sums the flow byte/packet counters, so
  "Top values of `src_ip` by Total bytes" is a **top-talkers** panel and
  "Alerts over time by Total bytes" is a **bandwidth** chart.
- **Distinct destination ports / IPs / sources** — counts distinct values, so
  "Top values of `src_ip` by Distinct destination ports" surfaces **port scans /
  fan-out**.
- **Average / Max malscore, Total size** (CAPE).

## Recipe panels

Everything below is just a **Top values** or **Alerts over time** widget on an
existing column — add them from the picker. A column that does not exist for the
selected table (e.g. `classification` on CAPE) simply notes so.

### Suricata / Sagan

| panel | widget | column |
|-------|--------|--------|
| Top signatures / classifications | Top values | `signature`, `classification` |
| Severity breakdown (Suricata) | Top values (pie) | `severity` (shown High/Medium/Low/Informational) |
| MITRE ATT&CK tactics / techniques (Suricata) | Top values | `mitre_tactic`, `mitre_technique` (from `alert.metadata`, when the ruleset tags it) |
| Top source / destination IPs | Top values | `src_ip`, `dest_ip` |
| Top destination ports | Top values | `dest_port` |
| Protocols / app protocols (Suricata) | Top values (pie) | `proto`, `app_proto` |
| Per-sensor breakdown | Top values | `instance`, `host` |
| Alert evolution by severity/class | Alerts over time | group by `severity` / `classification` |
| Sagan programs / facilities | Top values | `program`, `facility` |
| Sagan priority / level | Top values | `priority`, `level` |

### CAPE

| panel | widget | column |
|-------|--------|--------|
| Top targets / packages | Top values | `target`, `pkg` |
| Malscore distribution | Top values | `malscore` |
| Top hashes | Top values | `md5`, `sha256` |
| Top URL hostnames | Top values | `url_hostname` |
| Top source IPs | Top values | `src_ip` |

The panels come off the version-5/7 indexes, so a time-windowed breakdown reads
from an index rather than scanning the whole table.
