# Install

## Dependencies

Declared in `Makefile.PL`; the load bearing ones are below.

| module                                  | why                                            |
|-----------------------------------------|------------------------------------------------|
| `App::Cmd`                              | the `lilith` CLI and its subcommands           |
| `POE`                                   | the ingest daemon's FollowTail sessions        |
| `DBI`, `DBD::Pg`                        | talking to PostgreSQL                          |
| `DBIx::Class`, `DBIx::Class::Migration` | the schema and its versioned migrations        |
| `Mojolicious` (>= 9.0)                  | the `mojo_lilith` frontend                      |
| `JSON`, `TOML::Tiny`                    | EVE decoding and the config file               |
| `Text::ANSITable`, `Term::ANSIColor`    | the CLI's table output                         |
| `Mail::SPF`, `Mail::DMARC`, `Mail::DKIM`| the web UI's mail checks under Domain Info     |
| `Net::Server::Daemonize`                | `run --daemonize`                              |
| `File::ShareDir`                        | finding the templates, public assets, migrations |

Optional, each powering a single feature and loaded lazily — Lilith runs
without them and the feature simply stays inactive:

| module                    | feature                                             |
|---------------------------|-----------------------------------------------------|
| `Virani`                  | fetching flow PCAPs from remote Virani instances    |
| `Allani`                  | browsing an Allani log store from the `/logs` page and the dashboard's log widgets |
| `IP::Geolocation::MMDB`   | GeoIP data in the IP info modal                     |
| `Mozilla::PublicSuffix`   | accurate registrable-domain reduction for whois     |
| `Net::IP`                 | IPv6 reverse-DNS lookups in the IP info modal       |
| `WWW::Shodan::API`        | the keyed Shodan tier in the IP info modal; without it `enable_shodan` still works, using the keyless InternetDB summary |
| `File::LibMagic`          | the full libmagic description sent with a `cape_submit` submission; falls back to `file(1)` |

Two of the web UI's lookups shell out to a binary rather than using a
module: the whois shown for an IP or a domain needs a `whois` client, and
the domain info panel's optional dnstracer section needs `dnstracer`
installed and `dnstracer_enable` set.

## From source

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

## FreeBSD

```shell
pkg install p5-App-cpanminus p5-App-Cmd p5-DBI p5-DBIx-Class p5-DBD-Pg \
    p5-Digest-SHA p5-File-Slurp p5-JSON p5-MIME-Base64 p5-Mojolicious \
    p5-Net-Server p5-POE p5-Sys-Syslog p5-Term-ANSIColor p5-Text-ANSITable \
    p5-Time-Piece p5-TOML-Tiny
cpanm Lilith
```

## Debian

```shell
apt-get install cpanminus zlib1g-dev libapp-cmd-perl libdbi-perl \
    libdbix-class-perl libdbd-pg-perl libdigest-sha-perl libfile-slurp-perl \
    libjson-perl libmojolicious-perl libnet-server-perl libpoe-perl \
    libtoml-tiny-perl
cpanm Lilith
```

## PostgreSQL

Lilith really does need PostgreSQL — the raw EVE records live in jsonb
columns. Create a user and database for her...

```shell
createuser -D -l -P -R -S lilith
createdb -E UTF8 -O lilith lilith
```

...write the connection details into `/usr/local/etc/lilith.toml` (see
[configuration](configuration.md))...

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"
```

...and deploy the schema into the empty database with `lilith deploy`, which
reads `dsn`/`user`/`pass` from the config and installs the current schema
version:

```shell
lilith --config /usr/local/etc/lilith.toml deploy
```

`lilith schema_version` prints the version recorded in the database against the
one this release expects, and whether a deploy or upgrade is pending.

### Upgrading

Move an already-deployed database to the schema this release expects with
`lilith migrate` (a no-op when it is already current):

```shell
lilith --config /usr/local/etc/lilith.toml migrate
```

The 4 → 5 step is the first upgrade that adds indexes to existing tables
rather than creating new ones, so on a database with a lot of history it does
real work. A plain `CREATE INDEX` blocks writes — the ingest daemon and the
receiver — until each index finishes building, while reads (search and the web
frontend) keep working. Ingest is not lost (the tailer lags and catches up),
but run the upgrade during a quiet window on a busy sensor. If that pause is
unacceptable, build the indexes by hand with `CREATE INDEX CONCURRENTLY`
(which does not block writes) before upgrading — `lilith migrate` runs each
step in a transaction and `CONCURRENTLY` cannot, so it has to be done out of
band. The index set is in
`share/migrations/PostgreSQL/deploy/5/001-auto.sql`; it is a conservative
default and any index a deployment does not search or graph by can be dropped.

Both commands wrap `DBIx::Class::Migration`, so the underlying `dbic-migration`
CLI still works if you need it. If coming from an old unversioned schema
(pre 3.0.0), mark it as version 1 with `dbic-migration` first, then run
`lilith migrate`:

```shell
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn --to_version 1 upgrade
lilith --config /usr/local/etc/lilith.toml migrate
```

## Running at boot

### The ingest daemon

A systemd unit ships as [rc/systemd/lilith.service](../rc/systemd/lilith.service)
and a FreeBSD rc.d script as [rc/freebsd/lilith](../rc/freebsd/lilith):

```shell
# systemd
cp rc/systemd/lilith.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith

# FreeBSD
install -m 0755 rc/freebsd/lilith /usr/local/etc/rc.d/lilith
sysrc lilith_enable=YES
service lilith start
```

The systemd unit runs `lilith run` in the foreground (systemd supervises it);
the FreeBSD script runs `lilith run --daemonize --user $lilith_user --group
$lilith_group`. Either way the user it runs as needs read access to the
followed EVE files — see the comments in the unit about `User=`/`Group=`.

### The web frontend

`mojo_lilith` supports every standard Mojolicious server command, so run it
however you prefer to run Mojolicious apps:

```shell
mojo_lilith daemon -l http://127.0.0.1:8080
```

To run it at boot, a systemd unit ships as
[rc/systemd/mojo_lilith.service](../rc/systemd/mojo_lilith.service) and a
FreeBSD rc.d script as [rc/freebsd/mojo_lilith](../rc/freebsd/mojo_lilith):

```shell
# systemd
cp rc/systemd/mojo_lilith.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mojo_lilith

# FreeBSD
install -m 0755 rc/freebsd/mojo_lilith /usr/local/etc/rc.d/mojo_lilith
sysrc mojo_lilith_enable=YES
service mojo_lilith start
```

Both default to `prefork` on `http://127.0.0.1:8080`; edit the listen URL in
the unit/`mojo_lilith_listen` to change it. Read [security](security.md)
before binding it anywhere other than localhost — the frontend is
unauthenticated.

### The EVE receiver

`mojo_lilith_receiver` is the network counterpart to the local EVE-file
tailer: remote sensors POST already parsed alert rows to it and it inserts
them into the database, so a sensor never needs its own DB credentials. Like
`mojo_lilith` it takes any Mojolicious server command:

```shell
mojo_lilith_receiver daemon -l http://127.0.0.1:8081
```

It ships the same pair of boot scripts,
[rc/systemd/mojo_lilith_receiver.service](../rc/systemd/mojo_lilith_receiver.service)
and [rc/freebsd/mojo_lilith_receiver](../rc/freebsd/mojo_lilith_receiver),
installed the same way (service name `mojo_lilith_receiver`, default port
`8081`). If it sits behind a TLS terminating proxy, set `MOJO_REVERSE_PROXY=1`
in its environment (the systemd unit has a commented line for it) so per-key
IP scoping sees the real client address.

Unlike the frontend it authenticates every request against the API keys in
the database (created with `lilith receiver_key_create`) and refuses every
request until at least one key exists. Keys can be scoped to client
IPs/subnets and instance names. See [configuration](configuration.md) and
[usage](usage.md) for key management and the push format.

### The auto escalation timer

If you use auto escalation rules (see [escalation](escalation.md)), run
`lilith auto_escalate` periodically. Ready made units ship under `rc/`.

```shell
# systemd
cp rc/systemd/lilith-auto-escalate.service rc/systemd/lilith-auto-escalate.timer \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith-auto-escalate.timer

# cron
install -m 0644 rc/lilith-auto-escalate.cron /etc/cron.d/lilith-auto-escalate

# FreeBSD
install -m 0644 rc/lilith-auto-escalate.cron /usr/local/etc/cron.d/lilith-auto-escalate
```

There is no rc.d script, and should not be: this is a periodic job rather
than a daemon, so unlike `lilith run` and `mojo_lilith` there is nothing for
`service` to supervise.

All three run every five minutes with `-m 60`. The `-m` window only bounds how
far back each run scans for alerts it has not considered yet; the per-alert
`auto_escalated` marker is what prevents an alert from being escalated
twice, so a generous window is safe. It mostly matters for CAPE alerts,
whose `stop` time can lag well behind ingestion — raise `-m` if your CAPE
analysis lag exceeds it.

### The Shodan cache timer

If the web frontend has Shodan turned on (see
[configuration](configuration.md#shodan)), run `lilith shodan_cache`
periodically. Each run looks up the addresses recent alerts name and stores
what Shodan knows, so the IP info modal and the results tables' badges have
something to show without anyone having opened each address by hand first.

```shell
# systemd
cp rc/systemd/lilith-shodan-cache.service rc/systemd/lilith-shodan-cache.timer \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith-shodan-cache.timer

# cron
install -m 0644 rc/lilith-shodan-cache.cron /etc/cron.d/lilith-shodan-cache

# FreeBSD
install -m 0644 rc/lilith-shodan-cache.cron /usr/local/etc/cron.d/lilith-shodan-cache
```

There is no rc.d script, and should not be: this is a periodic job rather
than a daemon, so unlike `lilith run` and `mojo_lilith` there is nothing for
`service` to supervise.

All three run every minute with `-s 600`, so whoever is in the web UI sees a
new address's data about as soon as it can exist. The `-s` window only
bounds how far back each run reads; an address's own cache entry is what
stops it being looked up twice, so the window being much wider than the
interval is safe, and is what covers runs that fire late or take longer than
a minute as well as alerts ingested between runs. CAPE is read on its `stop`
time, which can lag ingestion, so give it room.

Do the first pass by hand before enabling any of this. Shodan allows about a
request a second, so a run costs roughly a second per address it looks up —
in steady state a handful, but on a database that has been collecting for a
while every distinct external address is cold at once:

```shell
lilith shodan_cache -s 0 --limit 500
```

Repeat until it reports nothing left to reach, then install the timer.

### The CVEDB cache timer

With the Shodan cache filling, run `lilith cvedb_cache` periodically too.
Each run stores what CVEDB — Shodan's free, keyless CVE database — says about
the CVE ids named by recently cached addresses, which is what annotates the
CVE chips and badges with scores, EPSS, and the CISA KEV flag; see
[usage](usage.md#cvedb_cache).

```shell
# systemd
cp rc/systemd/lilith-cvedb-cache.service rc/systemd/lilith-cvedb-cache.timer \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith-cvedb-cache.timer

# cron
install -m 0644 rc/lilith-cvedb-cache.cron /etc/cron.d/lilith-cvedb-cache

# FreeBSD
install -m 0644 rc/lilith-cvedb-cache.cron /usr/local/etc/cron.d/lilith-cvedb-cache
```

All three run every minute with `-s 1200 --limit 200`, the same cadence as
the Shodan cache timer they feed off. As with that timer, the `-s` window
only bounds how far back in `shodan_cache` each run reads; an id's own cache
entry is what stops it being fetched twice, so the window being much wider
than the interval is safe, and is what covers runs that fire late or take
longer than a minute.

Do the first pass by hand before enabling any of this, the same as with the
Shodan cache — on one that has been filling for a while, every id it holds is
cold at once:

```shell
lilith cvedb_cache -s 0 --limit 200
```

Repeat until it reports nothing left to reach, then install the timer.

## Sensor boxes: Lilu

A box that only feeds the annals does not need Lilith at all —
[Lilu](https://github.com/LilithSec/App-Lilu) (`App::Lilu`) is a cut down,
standalone reimplementation of just the ingest daemon and the extend, with
a much smaller dependency chain (no Mojolicious, DBIx::Class, or App::Cmd).

```shell
cpanm App::Lilu
```

The config is `/usr/local/etc/lilu.toml`: just `dsn`/`user`/`pass` and the
same `[eves.*]` sub tables as Lilith's config (see
[configuration](configuration.md)). Then:

```shell
lilu run --daemonize --user lilith --group lilith
```

He writes the same tables with the same event IDs, so the central Lilith
searches, escalates, and serves the web frontend over what the sensors
carried in. `lilu extend` produces the same LibreNMS extend as
`lilith extend` (though without the `class_ignore`/`sid_ignore` trimming),
covering the alerts ingested on that host.

## The LibreNMS extend

If using snmpd, Lilith can feed
[LibreNMS](https://www.librenms.org/) via an extend:

```
extend lilith /usr/local/bin/lilith extend
```
