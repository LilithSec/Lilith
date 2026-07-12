# Lilith

Lilith is the demoness of the night — the first who would not submit, who
left the garden and made the wild places her own. Nothing that happens in
the dark happens without her hearing of it.

In the world above, Lilith is an alert keeper: a daemon that follows the
EVE logs of [Suricata](https://suricata.io/) and
[Sagan](https://github.com/quadrantsec/sagan) (plus detonation reports from
[CAPEv2](https://github.com/kevoreilly/CAPEv2) via
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils)) and writes every alert
into PostgreSQL — the interesting fields as columns, the full EVE record as
jsonb beside them. From her book the alerts can be searched from the CLI or
a Mojolicious web frontend, any single event examined in full, the flow
PCAP behind it fetched from a remote
[Virani](https://github.com/LilithSec/Virani), and word sent onward —
escalated to webhooks, email, or syslog, by hand or by standing rule.

She is the matriarch of the LilithSec household:
[Baphomet](https://github.com/LilithSec/Baphomet) accuses,
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) punishes,
[Lamashtu](https://github.com/LilithSec/Lamashtu) remembers,
[Virani](https://github.com/LilithSec/Virani) reads — and Lilith knows.
Her lesser kinsman [Lilu](https://github.com/LilithSec/App-Lilu) is a cut
down Lilith for sensor boxes that only feed the annals: just the ingest
daemon and the extend, with no dependency on Lilith itself.

Keeping the annals and consulting them looks like this...

```shell
# follow the configured EVE files into PostgreSQL
lilith run --daemonize --user lilith --group lilith

# what has happened in the last hour involving 1.2.3.4?
lilith search -m 60 --ip 1.2.3.4

# look closer at one omen, and fetch the packets behind it
lilith event --id 42 --pcap ./flow.pcap

# send word to whoever must act
lilith esc --id 42 --to soc-hook --note 'C2 traffic'

# and the web frontend
lilith-web daemon -l http://127.0.0.1:8080
```

...with the instances to follow named in `/usr/local/etc/lilith.toml`:

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

[eves.pie]
type="suricata"
eve="/var/log/suricata/alert.json"

[eves.lae]
type="sagan"
eve="/var/log/sagan/alert.json"
```

## Install

### From source

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

### FreeBSD

```shell
pkg install p5-App-cpanminus p5-App-Cmd p5-DBI p5-DBIx-Class p5-DBD-Pg \
    p5-Digest-SHA p5-File-Slurp p5-JSON p5-MIME-Base64 p5-Mojolicious \
    p5-Net-Server p5-POE p5-Sys-Syslog p5-Term-ANSIColor p5-Text-ANSITable \
    p5-Time-Piece p5-TOML
cpanm Lilith
```

### Debian

```shell
apt-get install cpanminus zlib1g-dev libapp-cmd-perl libdbi-perl \
    libdbix-class-perl libdbd-pg-perl libdigest-sha-perl libfile-slurp-perl \
    libjson-perl libmojolicious-perl libnet-server-perl libpoe-perl \
    libtoml-perl
cpanm Lilith
```

PostgreSQL is required (the raw EVE records are jsonb); creating the
database and deploying the schema with `dbic-migration` is covered in
[docs/install.md](docs/install.md).

## Documentation

To continue your journey go to [docs/index.md](docs/index.md).

Also...

- `perldoc Lilith`
- `perldoc Lilith::Web`
- `perldoc Lilith::Escalate`
- `perldoc Lilith::AutoEscalate`
- `perldoc lilith`
- `perldoc lilith-web`
