# Examples

Copy-paste scenarios. All assume the database and schema are in place per
[install.md](install.md).

## A single Suricata sensor

The minimal case: one box, one Suricata, everything local.

```toml
dsn="dbi:Pg:dbname=lilith"
user="lilith"
pass="WhateverYouSetAsApassword"

[eves.pie]
type="suricata"
eve="/var/log/suricata/alert.json"
```

```shell
lilith run --daemonize --user lilith --group lilith

# a bit later...
lilith search -m 60
```

## Several watchers, one book

Two Suricata instances, a Sagan, and CAPE detonations, all into the same
annals; searches pick the table with `-t` and the instance with `-i`.

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"
class_ignore=["Generic Protocol Command Decode"]

[eves.pie]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

[eves.pie2]
instance="foo2-pie"
type="suricata"
eve="/var/log/suricata/alert2.json"

[eves.lae]
type="sagan"
eve="/var/log/sagan/alert.json"

[eves.cape]
type="cape"
eve="/var/log/cape/eve.json"
```

```shell
# sagan alerts from a particular sending host
lilith search -t sagan --host mailbox.example.net

# CAPE runs that scored badly
lilith search -t cape --malscore '>=8'
```

## Search recipes

```shell
# to or from an IP, last hour
lilith search -m 60 --ip 1.2.3.4

# ssh or telnet, ignoring the scanners' favorite
lilith search -p 22,23 -c '!%scan%'

# one signature across every instance, as JSON for further mangling
lilith search -s '%ET CINS%' --output json

# a specific rule
lilith search --sid 2403302

# pull the full event once found, and the packets behind it
lilith event --id 42
lilith event --id 42 --pcap ./flow.pcap
```

## Wiring in Virani

[Lamashtu](https://github.com/LilithSec/Lamashtu) hoards the packets,
[Virani](https://github.com/LilithSec/Virani)'s `mojo-virani` serves them,
and Lilith fetches the flow behind an alert. Name the remote after the
alert instance and it is pre-selected in the event view.

```toml
[virani.foo-pie]
url="https://virani.example.net:7000/"
apikey="whatever"
set="default"
```

CLI side, `--pcap` on `event` uses the same remotes:

```shell
lilith event --id 42 --pcap ./flow.pcap --buffer 120
```

## Escalation: a webhook and a standing order

Create a target, test it, and set a rule that escalates any CAPE run with a
malscore of 8 or more (see [escalation.md](escalation.md) for the DSL):

```shell
lilith esc_target_create --name soc-hook --type Webhook \
    --set url=https://soc.example/hook --set apikey=xyz
lilith esc_target_test --name soc-hook

lilith ae_create --name high-malscore --tables cape --rule '{
    "match":   { "field": "malscore", "op": ">=", "value": 8 },
    "actions": [ { "escalate_to": [ "soc-hook" ], "note": "auto: high malscore" } ]
}'

# see what it would have done, without sending anything
lilith auto_escalate --dry-run
```

Then put the timer in place (see [install.md](install.md)):

```shell
cp init/lilith-auto-escalate.service init/lilith-auto-escalate.timer \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lilith-auto-escalate.timer
```

## Lilu on the sensors, Lilith at the center

Each sensor box runs [Lilu](https://github.com/LilithSec/App-Lilu) — the
cut down, ingest-only Lilith — feeding the central database; the analyst
box runs full Lilith for search, the web frontend, and escalation.

On each sensor, `/usr/local/etc/lilu.toml`:

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

[eves.pie]
instance="edge1-pie"
type="suricata"
eve="/var/log/suricata/alert.json"
```

```shell
lilu run --daemonize --user lilith --group lilith
```

On the analyst box, the same `dsn` in `lilith.toml` — with no `[eves.*]`
of its own, `lilith run` is not even needed there:

```shell
lilith search -m 60 -i edge1-pie
lilith-web daemon -l http://127.0.0.1:8080
```

## Feeding LibreNMS

On the box running snmpd, in `snmpd.conf`:

```
extend lilith /usr/local/bin/lilith extend
```

`class_ignore` / `sid_ignore` (and their `suricata_*` / `sagan_*`
flavors) in the config trim noisy classes out of the extend without
keeping them out of the database.

## The web frontend, behind nginx

`lilith-web` on localhost, nginx doing TLS and auth in front:

```shell
LILITH_CONFIG=/usr/local/etc/lilith.toml lilith-web prefork -l http://127.0.0.1:8080
```

```nginx
server {
    listen 443 ssl;
    server_name lilith.example.net;

    auth_basic "the annals";
    auth_basic_user_file /usr/local/etc/nginx/lilith.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

With auth in front, the escalation and Virani features can reasonably be
enabled:

```toml
allowed_referers=["https://lilith.example.net/"]
escalation_enable = true
escalation_manage_enable = true
virani_search_enable = true
```

Read [security.md](security.md) before doing this without the auth.
