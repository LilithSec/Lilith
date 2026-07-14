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
| `JSON`, `TOML`                          | EVE decoding and the config file               |
| `Rule::Engine`                          | evaluating auto escalation rules               |
| `Text::ANSITable`, `Term::ANSIColor`    | the CLI's table output                         |
| `Mail::SPF`, `Mail::DMARC`, `Mail::DKIM`| the web UI's mail checks under Domain Info     |
| `Net::Server::Daemonize`                | `run --daemonize`                              |
| `File::ShareDir`                        | finding the templates, public assets, migrations |

Optional, each powering a single web UI feature and loaded lazily — Lilith
runs without them and the feature simply stays inactive:

| module                    | feature                                             |
|---------------------------|-----------------------------------------------------|
| `Virani`                  | fetching flow PCAPs from remote Virani instances    |
| `IP::Geolocation::MMDB`   | GeoIP data in the IP info modal                     |
| `Mozilla::PublicSuffix`   | accurate registrable-domain reduction for whois     |
| `Net::IP`                 | IPv6 reverse-DNS lookups in the IP info modal       |

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
    p5-Time-Piece p5-TOML
cpanm Lilith
```

## Debian

```shell
apt-get install cpanminus zlib1g-dev libapp-cmd-perl libdbi-perl \
    libdbix-class-perl libdbd-pg-perl libdigest-sha-perl libfile-slurp-perl \
    libjson-perl libmojolicious-perl libnet-server-perl libpoe-perl \
    libtoml-perl
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

...and deploy the schema with `dbic-migration` (installed with
DBIx::Class::Migration):

```shell
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn install
```

### Upgrading

```shell
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn upgrade
```

If coming from an old unversioned schema (pre 3.0.0), mark it as version 1
first and then upgrade:

```shell
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn --to_version 1 upgrade
dbic-migration --schema_class Lilith::Schema -P $password -U $user --dsn $dsn upgrade
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

With systemd:

```shell
cp rc/systemd/lilith-auto-escalate.service rc/systemd/lilith-auto-escalate.timer \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith-auto-escalate.timer
```

Without systemd, the cron flavor:

```shell
cp rc/lilith-auto-escalate.cron /etc/cron.d/lilith-auto-escalate
```

Both run every five minutes with `-m 60`. The `-m` window only bounds how
far back each run scans for alerts it has not considered yet; the per-alert
`auto_escalated` marker is what prevents an alert from being escalated
twice, so a generous window is safe. It mostly matters for CAPE alerts,
whose `stop` time can lag well behind ingestion — raise `-m` if your CAPE
analysis lag exceeds it.

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
