# Security considerations

## The web frontend is unauthenticated

The big one. `mojo_lilith` has no login of its own — anyone who can reach it
can search every alert, read every raw EVE record, and use whatever
features are enabled. Treat reachability as authorization:

- bind it to localhost or an internal interface, and/or
- put it behind a reverse proxy that does the authentication, and/or
- set `allowed_referers` so requests whose `Referer` does not start with
  one of the listed prefixes are refused with a 403.

The referer check is a tripwire, not a lock — a `Referer` header is
trivially forged by anything that is not a well behaved browser. It is
useful against drive-by cross-site nonsense, not against an attacker with
network reach. The reverse proxy is the real gate.

## The EVE receiver writes to the database

`mojo_lilith_receiver` is authenticated where the frontend is not — every
push must carry a bearer token that names an enabled key in the
`receiver_apikeys` table, and with no keys created it refuses everything.
Keys are stored as their SHA-256, so a database leak does not hand out usable
tokens; the plaintext is shown only once at `receiver_key_create` time. Still,
an accepted request writes a row into the annals, so a leaked *token* lets an
attacker inject alerts — give each sensor its own key so one can be revoked
without disturbing the rest, and run the receiver over TLS (directly or behind
a reverse proxy) so the token and the alert data are not exposed on the wire.

A key can be scoped to a set of client IPs/subnets and to a set of instance
names (with `*`/`?` wildcards), so a stolen sensor key is only useful from the
sensor's network and only for its own instances. **The IP scope is only as
trustworthy as the client address the receiver sees:** behind a reverse proxy
set `MOJO_REVERSE_PROXY=1` so that address comes from `X-Forwarded-For` rather
than being the proxy itself — otherwise every request shares the proxy's IP
and per-IP scoping is meaningless. Only trust `X-Forwarded-For` from a proxy
you control.

The receiver only ever inserts the ingestable columns; `id`, `escalations`,
and `auto_escalated` cannot be set by a caller, so a push can never forge an
escalation state.

## The annals themselves are sensitive

The alert tables hold raw EVE records: payload snippets, hostnames, URLs,
usernames from Sagan-watched logs, hashes and targets from CAPE runs. That
is exactly what makes Lilith useful and exactly why the database and the
web frontend deserve the same care as the logs they were distilled from.
The config file holds the database credentials — keep
`/usr/local/etc/lilith.toml` owned and readable by the user that needs it
and nobody else.

## The Allani log store, if configured, is exposed read-only

With an `[allani]` block configured, the `/logs` page reads an
[Allani](https://github.com/LilithSec/Allani) store — *every* log line it
holds, not just the alerts Lilith keeps. Lilith only ever SELECTs Allani (no
writes, no ingest), so `/logs` cannot alter the store, but it does widen what
the unauthenticated frontend can read from the distilled annals to the whole
syslog corpus behind it. Treat it like the alert tables: put the UI behind
authentication before configuring `[allani]`. The block holds its own database
credentials, so guard the config file the same way, and point the DSN at a
read-only Allani role if you want defence in depth.

## Features that reach outward are gated, and default off

Several web features cause the server to *send* data somewhere, so each is
its own opt-in:

- `escalation_enable` — the Escalate button, history, the read-only target
  view, and the read-only rule page with its dry-run preview. Escalating
  pushes event data at the configured targets, so even the "read mostly"
  tier can emit.
- `escalation_manage_enable` — creating/editing/deleting/testing targets
  from the web UI. Kept separate because editing a target changes *where
  alerts are sent*, and the test button pushes synthetic events at outside
  services.
- `auto_escalation_manage_enable` — editing rules from the web UI. Kept
  separate because a saved and enabled rule escalates automatically on the
  timer, forever, without further human involvement. With it off, rules can
  be seen and previewed but only changed via the CLI.
- `virani_search_enable` — downloading arbitrary PCAP searches and browsing
  cached searches through the web server. Off by default because it exposes
  arbitrary captures, not just the flow behind an alert being examined.

The tiering is deliberate: each step up moves from *reading the annals* to
*acting on the world*, and each is a separate decision.

The CLI escalation actions are never gated by any of these. Those gates
exist for the unauthenticated web frontend; the CLI already holds the
database credentials from the config file, so gating it would be theater.

## PCAP retrieval exposes captures

With `[virani.*]` remotes configured, the event view can pull the flow PCAP
behind an alert through the web server — which means anyone who can reach
the web UI can pull packet captures off your capture boxes, `apikey` or no
(the key is Lilith's, not the visitor's). Put the UI behind authentication
before configuring remotes, use `verify_hostname` (on by default) with
HTTPS remotes, and think before turning on `virani_search_enable` — the
standalone search is not tied to any alert and will carve whatever the
filter matches.

## The lookups make the server talk to the world

The IP and domain info panels do live reverse DNS, whois, GeoIP, HTTPS
probes, and SPF/DMARC/DKIM checks. Two consequences:

- The *server* makes those connections, triggered by whoever is using the
  UI. On a locked-down segment that may be an egress you did not intend;
  it can also tip your hand to an adversary watching their own
  infrastructure (the classic reason analysts avoid touching attacker
  domains directly).
- The lookups run in subprocesses so they cannot stall the event loop, but
  they are still work anyone reaching the UI can cause.

The HTTPS check caps itself (5s timeout, 512KB read) and GeoIP lookups are
local `.mmdb` reads, but DNS, whois, and the mail checks go where they must.

## The ingest daemon

`lilith run` needs read access to the EVE files and the database
credentials — nothing more. Run it as a dedicated low-privilege user
(`--user`/`--group` with `--daemonize`) that is in whatever group Suricata
and Sagan write their logs for. It does not need root once it can read the
logs, and nothing in Lilith ever needs to touch the firewall — accusing and
punishing are [Baphomet](https://github.com/LilithSec/Baphomet)'s and
[Ereshkigal](https://github.com/LilithSec/Ereshkigal)'s work.

The auto escalation timer only touches the database, so the shipped systemd
unit runs it as the low privilege `lilith` user; keep it that way.

## Escalation targets are trust decisions

An escalation target is a place event data will be sent — a webhook URL, a
mailbox, syslog. Whoever can edit targets can redirect alert data, which is
why target editing has its own gate in the web UI and why `esc_target_*`
changes are worth the same review as a firewall rule. The audit trail
(`escalations`, with the exact payload sent) is your friend after the fact;
it does not prevent anything.
