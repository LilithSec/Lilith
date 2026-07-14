# Escalation

When an omen demands action, Lilith sends word onward. An **escalation**
delivers an event to one or more **targets**; a target has a pluggable
**type** (webhook, email, syslog, or your own) and a per-type config.
Escalations happen by hand — the CLI or the event view's Escalate button —
or by standing order, via **auto escalation rules** evaluated on a timer.

Everything is recorded. Every attempt lands in the `escalations` table with
its status (`sent`/`failed`), any error, and the raw JSON payload actually
sent — including attempts refused before a send (an unknown or disabled
target). The target's name is snapshotted per attempt so history stays
readable after a target is deleted, and each alert row carries the IDs of
its escalations in its `escalations bigint[]` column. Escalated events are
badged with a red **E** in search results.

## Targets and types

Targets live in SQL (`escalation_targets`): a name, a type, a per-type
config, and an enabled flag. A type is a module under the
`Lilith::Escalate::Type::` namespace — see the
[Lilith::Escalate](https://metacpan.org/pod/Lilith::Escalate) POD for the
small interface a type implements, and use `escalation_type_namespaces` in
the config to add site-local namespaces. The dist ships with:

| type    | what it does                                                                  |
|---------|--------------------------------------------------------------------------------|
| Webhook | POSTs the event as JSON to a URL, optionally with an `Authorization: Bearer` key. |
| Email   | Sends a plain text summary of the event via SMTP (STARTTLS and AUTH supported). |
| Syslog  | Logs a one line summary of the event to syslog.                               |

The config form in the web UI is generated from the type's own field spec,
so a newly installed type shows up without any UI changes, and every target
has a **Test** button/action that sends a synthetic event at it.

## Escalating by hand

From the web UI (with `escalation_enable` on): the event view's
**Escalate** button sends the event to one or more targets along with a
note and who requested it, and the view shows the escalation history, each
row expandable to the payload actually sent.

From the CLI (never gated — the gates exist for the unauthenticated web
frontend, the CLI already holds the DB credentials):

```shell
lilith esc --id 42 --to soc-hook,mail-oncall --note 'C2 traffic'
```

| command             | what                                                       |
|---------------------|-------------------------------------------------------------|
| `esc`               | Escalate an event (`-t`/`--id`) to targets (`--to`, ID or name), with `--note` and `--by`. Exits non-zero if any target failed. |
| `esc_history`       | The escalations recorded for an event, newest first. `--output json` includes the raw payloads. |
| `esc_types`         | The installed types and the config fields each takes.       |
| `esc_targets`       | The configured targets. `--output json` includes configs.   |
| `esc_target_get`    | One target as JSON, via `--tid <id>` or `--name <name>`.    |
| `esc_target_create` | Create a target: `--name`, `--type`, repeated `--set key=value`, optional `--desc`, `--disable`. |
| `esc_target_update` | Update a target; `--set` items merge over the current config, an empty value removes the key, `--enable`/`--disable` flip the flag. |
| `esc_target_delete` | Delete a target. Recorded escalations to it are kept.       |
| `esc_target_test`   | Send a synthetic test event at a target.                    |

```shell
lilith esc_target_create --name soc-hook --type Webhook \
    --set url=https://soc.example/hook --set apikey=xyz
```

## Auto escalation

Standing orders live in the `auto_escalations` table: a rule (the DSL
below), the tables it applies to (`suricata`, `sagan`, `cape` — default
all), a priority (lower first), and a `stop_on_match` flag that halts later
rules for an alert an earlier rule already matched.

`lilith auto_escalate` evaluates the enabled rules against alerts ingested
within its `-m` window that have not been considered yet, and escalates
each match to the rule's targets through the same path as a manual
escalation — same audit trail, same per-row `escalations` array. Each
alert's `auto_escalated` timestamp marks it considered, so it is evaluated
exactly once no matter how the windows overlap.

Run it periodically — ready made systemd timer units and a cron entry ship
under `rc/`, both every five minutes with `-m 60`; see
[install](install.md). Use `--dry-run` first to see what would fire
without sending anything, and `--tables` to restrict a run.

```shell
lilith auto_escalate --dry-run
```

| command     | what                                                          |
|-------------|----------------------------------------------------------------|
| `ae_list`   | List the rules.                                                |
| `ae_get`    | One rule, with its DSL.                                        |
| `ae_create` | Create a rule.                                                 |
| `ae_update` | Update a rule.                                                 |
| `ae_delete` | Delete a rule.                                                 |

### The rule DSL

A rule is a JSON object with a `match` tree and an `actions` array:

```json
{
    "match": {
        "all": [
            { "field": "malscore", "op": ">=", "value": 8 },
            { "not": { "field": "classification", "op": "contains",
                       "value": "Not Suspicious" } }
        ]
    },
    "actions": [
        { "escalate_to": [ "soc-hook", 3 ], "note": "auto: high malscore" }
    ]
}
```

A `match` node is one of:

```
{ "all": [ node, ... ] }    every child must match
{ "any": [ node, ... ] }    at least one child must match
{ "not": node }             the child must not match
{ "field": <name>, "op": <op>, "value": <value> }    a leaf test
```

A leaf `field` names an alert column (`malscore`, `signature`, `src_ip`,
...) or a dotted path into the decoded raw EVE record
(`raw.alert.severity`). The ops:

| op                  | meaning                                                   |
|---------------------|-----------------------------------------------------------|
| `==` / `!=`         | equality — numeric when both sides are numeric, else string |
| `>` `>=` `<` `<=`   | numeric comparison                                        |
| `regex`             | the field matches the value as a regular expression       |
| `in`                | the field equals one of the value list                    |
| `contains`          | string contains the value as a substring; array contains it as an element |
| `exists`            | the field is (value true) or is not (value false) defined |

Rules are never evaluated as Perl — a leaf only ever does hash lookups and
the fixed comparisons above — so a rule is safe to accept from the web UI.
`escalate_to` items are target names or IDs.

### In the web UI

With `escalation_enable` on, `/auto_escalation` shows the rules: a visual
builder for the match tree (nested ALL/ANY/NOT groups of field/op/value
tests) with an "Advanced (JSON)" toggle for the raw DSL, and a live dry-run
preview against recent alerts that never sends. Creating, editing, or
deleting rules from the web UI additionally requires
`auto_escalation_manage_enable`; with it off the page is read only. See
[security](security.md) for why the gates are tiered like that.

## How the sends happen

Web-initiated escalations are sent from a subprocess so the Mojolicious
event loop is not blocked; CLI escalations send inline. Either way the
attempt is recorded first-class in `escalations`, and the alert row's
`escalations` array is appended in the same transaction as the insert.
