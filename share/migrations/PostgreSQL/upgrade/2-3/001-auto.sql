-- Lilith schema upgrade 2 -> 3: escalation system
--
-- escalation_targets holds the configured escalation destinations. 'type'
-- selects the Lilith::Escalate::Type::* module; 'config' is that module's
-- configuration as validated by its check_config.
--
-- escalations is the audit trail; every attempt is recorded, including ones
-- refused before a send (unknown or disabled target). 'table_name' is the
-- short table type (suricata/sagan/cape) as used by search() and the web UI,
-- 'raw' is the payload the escalation type actually sent, and 'target_name'
-- snapshots the target's name at attempt time so history stays readable
-- after a target is deleted (which nulls target_id via the FK).

CREATE TABLE escalation_targets (
    id bigserial NOT NULL,
    name varchar(255) NOT NULL UNIQUE,
    type varchar(255) NOT NULL,
    config jsonb NOT NULL DEFAULT '{}',
    enabled boolean NOT NULL DEFAULT TRUE,
    description varchar(2048),
    updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

CREATE TABLE escalations (
    id bigserial NOT NULL,
    table_name varchar(64) NOT NULL,
    alert_id bigint NOT NULL,
    event_id varchar(64),
    target_id bigint REFERENCES escalation_targets(id) ON DELETE SET NULL,
    target_name varchar(255),
    status varchar(32) NOT NULL DEFAULT 'pending',
    note text,
    requested_by varchar(255),
    error text,
    raw jsonb,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

CREATE INDEX escalations_event_idx ON escalations (table_name, alert_id);

-- Denormalized list of escalation IDs per alert, maintained by escalate()
-- in the same transaction as the escalations insert. Lets anything reading
-- the alert tables see whether/how many times a alert has been escalated
-- without querying the escalations table; the IDs are there when more
-- detail is wanted. The escalations table remains the source of truth.

ALTER TABLE suricata_alerts ADD COLUMN escalations bigint[];

ALTER TABLE sagan_alerts ADD COLUMN escalations bigint[];

ALTER TABLE cape_alerts ADD COLUMN escalations bigint[];

-- auto_escalations holds rules evaluated against newly ingested alerts by
-- auto_escalate(). 'rule' is the match/actions DSL as JSONB, compiled into a
-- Rule::Engine ruleset at evaluation time. 'tables' scopes which alert tables
-- a rule applies to, 'priority' orders evaluation (lower first), and
-- 'stop_on_match' keeps later rules from firing on an alert an earlier rule
-- already matched.

CREATE TABLE auto_escalations (
    id bigserial NOT NULL,
    name varchar(255) NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT TRUE,
    priority integer NOT NULL DEFAULT 100,
    tables varchar(64)[] NOT NULL DEFAULT '{suricata,sagan,cape}',
    rule jsonb NOT NULL DEFAULT '{}',
    stop_on_match boolean NOT NULL DEFAULT FALSE,
    description varchar(2048),
    last_matched TIMESTAMP WITH TIME ZONE,
    match_count bigint NOT NULL DEFAULT 0,
    updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

-- Records when auto_escalate() last considered an alert row, so each is
-- evaluated exactly once regardless of whether any rule matched.

ALTER TABLE suricata_alerts ADD COLUMN auto_escalated TIMESTAMP WITH TIME ZONE;

ALTER TABLE sagan_alerts ADD COLUMN auto_escalated TIMESTAMP WITH TIME ZONE;

ALTER TABLE cape_alerts ADD COLUMN auto_escalated TIMESTAMP WITH TIME ZONE;
