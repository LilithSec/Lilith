# Lilith documentation

Lilith is the demoness of the night — the first who would not submit, who
left the garden and made the wild places her own. Nothing that happens in
the dark happens without her hearing of it.

In the world above she is an alert keeper: a daemon that follows the EVE
logs of [Suricata](https://suricata.io/) and
[Sagan](https://github.com/quadrantsec/sagan) (and detonation reports from
[CAPEv2](https://github.com/kevoreilly/CAPEv2) via
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils)) and writes every alert
into PostgreSQL. From her book the alerts can be searched from the CLI or a
web frontend, any single omen examined in full, the packets behind it
fetched, and word sent onward — by hand or by rule — to whoever must act.

She is the matriarch of the LilithSec household, which is named for her.
[Baphomet](https://github.com/LilithSec/Baphomet) accuses,
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) punishes,
[Lamashtu](https://github.com/LilithSec/Lamashtu) remembers, and
[Virani](https://github.com/LilithSec/Virani) reads what Lamashtu kept.
Lilith is the one who *knows* — the cries the watchers raise in the night
are gathered into her annals, and when the packets behind a cry are wanted
she sends Virani to fetch them. She also has a lesser kinsman:
[Lilu](https://github.com/LilithSec/App-Lilu), a cut down Lilith who only
carries alerts into her book — just the ingest daemon and the extend, for
sensor boxes that hold no court of their own. See
[architecture](architecture.md) for how she relates.

- [architecture](architecture.md) :: the daemon and its followed EVE
  files, the tables, the CLI, the web frontend, the auto escalation timer,
  and where Lilith sits in the pantheon

- [install](install.md) :: dependencies in detail, per-OS install,
  setting up PostgreSQL and the schema, and running at boot

- [configuration](configuration.md) :: the `lilith.toml` reference and a
  complete example

- [usage](usage.md) :: the `lilith` CLI, searching the annals, and the
  web frontend

- [dashboard](dashboard.md) :: the configurable `/dashboard` overview —
  its controls, widget types, and recipe panels per table

- [escalation](escalation.md) :: sending word onward — targets, types,
  the escalation CLI, and the auto escalation rule DSL

- [security](security.md) :: the heavy part — the web frontend is
  unauthenticated, and several features reach out to the world

- [examples](examples.md) :: copy-paste scenarios

Also...

- [Lilith](https://metacpan.org/pod/Lilith)
- [Lilith::Web](https://metacpan.org/pod/Lilith::Web)
- [Lilith::Receiver](https://metacpan.org/pod/Lilith::Receiver)
- [Lilith::Escalate](https://metacpan.org/pod/Lilith::Escalate)
- [Lilith::AutoEscalate](https://metacpan.org/pod/Lilith::AutoEscalate)
- [lilith](https://metacpan.org/pod/lilith)
- [mojo_lilith](https://metacpan.org/pod/mojo_lilith)
- [mojo_lilith_receiver](https://metacpan.org/pod/mojo_lilith_receiver)
