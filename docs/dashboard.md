# Dashboard

The web frontend's `/dashboard` is a configurable overview of the annals: a grid
of chart widgets over the same alerts the search page lists, drawn with a
vendored [Chart.js](https://www.chartjs.org/) and laid out with a vendored
[Gridstack](https://gridstackjs.com/). It is reached from the **Dashboard** link
in the navbar (the frontend is unauthenticated — see [security](security.md)).

## Controls

Along the top:

- **Dashboard** :: which saved board to show. Pick another to switch to it; the
  star (★) marks the default board (the one loaded first).
- **Default table** :: the default source for any widget that does not set its
  own: Suricata, Sagan, CAPE, or Baphomet, and — when an [Allani](#allani-log-widgets)
  store is configured — the log sources `syslog`, `http (access)`, or
  `http error`. Each widget can override it (see the widget config below), so one
  board can span tables; a widget left to follow the default reads whichever it
  is set to.
- **Time range** :: a preset relative window (Last hour … Last 30 days) or a
  **Custom range** with From/To pickers (native date plus 24-hour hour/minute).
  A relative window is what the board saves; a custom absolute range is a live
  override that is not persisted with the board.
- **Bucket** :: the time bucket the over-time charts use: `auto` (the default),
  or a fixed `minute` / `hour` / `day` / `week` / `month`. `auto` sizes the
  bucket to the window (minute up to 3h, hour up to 2d, day up to 90d, week up to
  ~2y, month beyond) so a long window does not produce a giant series. Each
  **Alerts over time** widget can override it (see the widget config below).
- **Show GPCD** :: off by default. When off, `Generic Protocol Command Decode`
  alerts are excluded everywhere (as the search page hides them). Tick it to
  include them. Only affects tables with a classification (Suricata/Sagan).
- **Refresh** :: re-pulls all data for the current controls.
- **Edit** :: toggles edit mode (see below). Its dropdown holds the board actions:
  **New dashboard**, **Rename**, **Set as default**, and **Delete**.

The **Default table**, **Time range**, **Bucket**, and **Show GPCD** controls are
per-board: each board remembers its own, restored when you switch to it. Changing
them just re-draws until you save (in edit mode).

Below the controls is the widget grid. The built-in board opens with a row of
**stat widgets** across the top (total alerts, unique sources, unique
signatures, escalated, and the busiest sensor); these are ordinary widgets, so
they can be moved, retyped, retabled, or removed like any other.

## Edit mode

The board is **read-only until you click Edit**. In view mode the grid is
locked — widgets can't be moved or resized, so casually dragging one never
overwrites the saved layout. Clicking **Edit** unlocks it and reveals the
editing controls:

- **+ Add widget** :: opens the widget picker (see below).
- **Reset to…** :: replaces this board's widgets with a built-in **preset**
  (after a confirm). The menu offers **Suricata** (the SIEM overview seeded on
  the default board), **CAPE**, **Baphomet** (a judgments overview), and
  **Shodan enrichment** (see [below](#shodan-enrichment)); when an
  [Allani](#allani-log-widgets) store is
  configured it also offers **Syslog**, **HTTP (access + error)** — a combined
  overview — **HTTP Access**, and **HTTP Error**. An alert preset also points the
  board's **Default table** at its table; a log preset instead pins each widget's
  own source, so it reads that log whatever the Default table is.
- Each widget grows a gear (reconfigure) and an × (remove), **drags by its
  title** to reorder, and **resizes from the bottom-right corner**.

While editing, layout and control changes are saved automatically; click
**Done** to leave edit mode and lock the grid again.

Boards are stored in the database and, because the web UI has no accounts, are
**shared, not per-user**. They persist across reloads. A brand-new board starts
empty; the built-in `default` board comes seeded with the Suricata preset (the
widget set below).

## Widget types

- **Alerts over time** :: a stacked bar over the time range, optionally split by a
  column (the default splits by classification/target). Its **Time bucket** field
  defaults to *Follow dashboard* (the board's Bucket control) but can pin its own
  `auto` / `minute` / `hour` / `day` / `week` / `month`.
- **Top values** :: the most common values of any column, as a **bar or pie**,
  showing between 1 and 50 values.
- **Source countries** :: the busiest source IPs resolved to countries through the
  GeoIP databases (needs an MMDB configured, see [configuration](configuration.md);
  otherwise the panel notes it is unavailable).
- **Stat (text)** :: a single big number: the **Total** count, **Distinct** values
  of a column, **Escalated** count, the **Busiest** value of a column, or
  **Shodan coverage** / **Shodan staleness** for either end (see
  [below](#shodan-enrichment)), with an
  optional custom label (defaulting from the metric). Numbers are shown in full
  with thousands separators by default; tick **Abbreviate large numbers** to
  shorten them (2010 → 2k) instead. The row of numbers at the
  top of the built-in board — Total alerts, Unique sources/signatures, Escalated,
  busiest sensor — is just these widgets, movable and per-table (or
  per-log-source) like any other.

The column pickers are driven by the backend's own list of accepted columns, so
they only offer columns that table actually supports.

### Measures

The **Top values** and **Alerts over time** widgets take a *measure* — what to
aggregate, instead of just counting rows:

- **Count** (default) :: number of alerts.
- **Total bytes / packets** (Suricata) :: sums the flow byte/packet counters, so
  "Top values of `src_ip` by Total bytes" is a **top-talkers** panel and
  "Alerts over time by Total bytes" is a **bandwidth** chart.
- **Distinct destination ports / IPs / sources** :: counts distinct values, so
  "Top values of `src_ip` by Distinct destination ports" surfaces **port scans /
  fan-out**.
- **Average / Max malscore, Total size** (CAPE).
- **Average / Max score, Distinct source / destination IPs** (Baphomet) :: so
  "Top values of `src_ip` by Max score" ranks the worst offenders by their
  harshest judgment.

## Shodan enrichment

Alongside the columns an alert carries, Suricata, Sagan, and Baphomet offer
columns describing the *hosts at either end of it*, read from the
`shodan_cache` table by matching on `src_ip` and `dest_ip`. The charts keep
alert volume and time on the axes and cut them by what those hosts are:

- `shodan_src_tag` :: Shodan's tags for the host — `compromised`, `scanner`,
  `vpn`, `tor`, and the rest.
- `shodan_src_vuln` :: the CVEs Shodan attributes to it.
- `shodan_src_cpe` :: what it is running. One appliance model or one exposed
  service across many addresses is a botnet's fingerprint.
- `shodan_src_port` :: what it has open.
- `shodan_src_known` :: *Known to Shodan* / *Not on Shodan* (crawled, nothing
  there) / *Not looked up*.
- `shodan_src_cvss` :: the worst CVSS against the host, banded *Critical (9+)* /
  *High* / *Medium* / *Low* / *None known* / *Not looked up*, ordered
  worst-first rather than by count.

Each has a `shodan_dest_*` twin reading `dest_ip` — same six, same meanings, the
far end of the alert. Which end an outside host lands on is up to the rule that
fired, so a source-only board hides everything about traffic going the other
way: on inbound alerts the source is the attacker, while the destination is what
was reached out to, which is where the command-and-control and download side
shows up. The two are separate joins, so a board can panel both at once.

One column crosses the two halves instead of describing one:

- `shodan_dest_cve_match` :: whether the rule that fired names a CVE the
  destination's cache entry lists it as vulnerable to — *Matched* / *Not
  matched* / *No CVE in rule* / *Not looked up*, *Matched* first. An exploit
  thrown at a host actually vulnerable to it is the loudest thing this data
  can say, and the same comparison badges the search rows and the event view.
  Suricata and destination only — the rule's ids come from its metadata and
  signature, and the question is about what was attacked. Needs the `cves`
  column (schema version 16).

Expect the destination panels to read mostly *Not looked up* on a sensor
watching inbound traffic: there the destination is your own asset, which is a
private address, and Lilith never sends those to Shodan. The destination
coverage stat below says so plainly rather than leaving it to be guessed at.

CAPE is offered none of them: a detonation's `src_ip` is whoever submitted the
sample, not an offender. The columns appear in the pickers only when the
database has the `shodan_cache` table (schema version 15).

### Coverage and staleness

The cache holds what has been looked up — addresses someone opened the IP info
modal for, plus whatever `lilith shodan_cache` has warmed — so **an enrichment
panel describes that subset, not the whole window**. Four stat metrics say how
much of a subset, a pair per end, and the matching pair belongs on any board of
these; the built-in preset leads each of its two halves with one.

- **Shodan coverage (sources)** / **(destinations)** :: reads `62% (124/200)` —
  the window's distinct addresses on that end, and how many of them the cache
  answers for at all.
- **Shodan staleness (sources)** / **(destinations)** :: reads `12% (15/124)` —
  of those answers, how many have gone off. An answer is stale once it is older
  than `shodan_cache_ttl`, and also when it came from the other Shodan tier (a
  keyless summary once an API key is configured, or the reverse), the two
  differing too much in depth for one to stand in for the other. That is the
  same rule the IP info modal and the results-table badges read by, so a stale
  answer is one nothing else would use either. With `shodan_cache_ttl = 0` —
  caching off — everything reads as stale, which is what it is.

The two ends are counted separately because they are cached to very different
depths — `lilith shodan_cache` warms both, but only the public addresses among
them, and on inbound traffic the destinations are not public.

Run `lilith shodan_cache` on a timer to raise the coverage numbers and hold the
staleness ones down — see [configuration](configuration.md#shodan). The
dashboard only ever reads the cache, so no widget costs a lookup, and none of
these numbers goes anywhere on its own.

Two things to read the charts by:

- `tag`, `vuln`, `cpe`, and `port` — either end — come from lists, so **one
  alert counts once per value** and the slices sum to more than the alert
  total. An address with nothing cached drops out of these entirely.
- `known`, `cvss`, and `cve_match` keep every alert, putting the addresses with
  nothing cached in their own bucket.

Either way an alert that names no address on the end being read — a Baphomet
judgment passed on a username, or an alert with no destination — is left out,
there being nothing to describe.

## Allani log widgets

When an [Allani](https://github.com/LilithSec/Allani) store is configured
(`[allani]`), a widget's **Table** picker also offers the log sources — `syslog`,
`http (access)`, `http error` — under a *Logs (Allani)* group. Such a widget
reads from the log store instead of the alert tables, with that source's own
dimensions and measures (e.g. top programs for syslog, top vhosts by Total bytes
for http), so one board can mix alert and log graphs. The **Top values**,
**Alerts over time**, **Source countries**, and **Stat (text)** widget types all
work against a log source too.

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
| What the sources are tagged as | Top values | `shodan_src_tag` |
| CVEs / software on the sources | Top values | `shodan_src_vuln`, `shodan_src_cpe` |
| Alerts from crawled vs unseen hosts | Alerts over time | group by `shodan_src_known` |
| What the alerts reached out to | Top values | `shodan_dest_tag`, `shodan_dest_cpe` |
| Exploits against hosts vulnerable to them (Suricata) | Top values (pie) / Alerts over time | `shodan_dest_cve_match` |

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
