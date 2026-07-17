-- Lilith schema version 5

CREATE TABLE suricata_alerts (
    id bigserial NOT NULL,
    instance varchar(255) NOT NULL,
    host varchar(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_id varchar(64) NOT NULL,
    flow_id bigint,
    in_iface varchar(255),
    src_ip inet,
    src_port integer,
    dest_ip inet,
    dest_port integer,
    proto varchar(32),
    app_proto varchar(255),
    flow_pkts_toserver integer,
    flow_bytes_toserver integer,
    flow_pkts_toclient integer,
    flow_bytes_toclient integer,
    flow_start TIMESTAMP WITH TIME ZONE,
    classification varchar(1024),
    signature varchar(2048),
    gid int,
    sid bigint,
    rev bigint,
    raw jsonb,
    escalations bigint[],
    auto_escalated TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY(id)
);

CREATE TABLE sagan_alerts (
    id bigserial NOT NULL,
    instance varchar(255) NOT NULL,
    instance_host varchar(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE,
    event_id varchar(64) NOT NULL,
    flow_id bigint,
    in_iface varchar(255),
    src_ip inet,
    src_port integer,
    dest_ip inet,
    dest_port integer,
    proto varchar(32),
    facility varchar(255),
    host varchar(255),
    level varchar(255),
    priority varchar(255),
    program varchar(255),
    xff inet,
    stream bigint,
    classification varchar(1024),
    signature varchar(2048),
    gid int,
    sid bigint,
    rev bigint,
    raw jsonb NOT NULL,
    escalations bigint[],
    auto_escalated TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY(id)
);

CREATE TABLE cape_alerts (
    id bigserial NOT NULL,
    instance varchar(255) NOT NULL,
    target varchar(255) NOT NULL,
    instance_host varchar(255) NOT NULL,
    task bigserial NOT NULL,
    start TIMESTAMP WITH TIME ZONE,
    stop TIMESTAMP WITH TIME ZONE,
    malscore bigint NOT NULL,
    subbed_from_ip inet,
    subbed_from_host varchar(255),
    pkg varchar(255),
    md5 varchar(255),
    sha1 varchar(255),
    sha256 varchar(255),
    slug varchar(255),
    url varchar(255),
    url_hostname varchar(255),
    proto varchar(255),
    src_ip inet,
    src_port integer,
    dest_ip inet,
    dest_port integer,
    size integer,
    raw jsonb NOT NULL,
    escalations bigint[],
    auto_escalated TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY(id)
);

-- 'type' selects the Lilith::Escalate::Type::* module; 'config' is that
-- module's configuration as validated by its check_config.
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

-- Escalation audit trail; every attempt is recorded, including ones refused
-- before a send (unknown or disabled target). 'table_name' is the short
-- table type (suricata/sagan/cape) as used by search() and the web UI,
-- 'raw' is the payload the escalation type actually sent, and 'target_name'
-- snapshots the target's name at attempt time so history stays readable
-- after a target is deleted (which nulls target_id via the FK).
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

-- auto_escalations holds rules evaluated against newly ingested alerts by
-- auto_escalate(). 'rule' is the match/actions DSL as JSONB, compiled into a
-- Rule::Engine ruleset at evaluation time. 'tables' scopes which alert tables
-- a rule applies to, 'priority' orders evaluation (lower first), and
-- 'stop_on_match' keeps later rules from firing on an alert an earlier rule
-- already matched. The per-alert 'auto_escalated' timestamp records when
-- auto_escalate() last considered a row so each is evaluated exactly once.
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

-- receiver_apikeys holds the bearer keys accepted by mojo_lilith_receiver.
-- Only the SHA-256 of each key is stored (key_sha256, base64) so a database
-- leak does not expose usable credentials. allowed_ips (host or subnet) and
-- allowed_instances scope where a key may be used and which instance names it
-- may write; a NULL/empty array means "no restriction on that axis".
-- allowed_instances entries may use the '*' and '?' shell-style wildcards.
CREATE TABLE receiver_apikeys (
    id bigserial NOT NULL,
    name varchar(255) NOT NULL UNIQUE,
    key_sha256 varchar(44) NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT TRUE,
    allowed_ips cidr[],
    allowed_instances varchar(255)[],
    description varchar(2048),
    last_used TIMESTAMP WITH TIME ZONE,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

-- Search / dashboard indexes (schema version 5). Composite
-- (column, <order-col>) btrees so "the newest N rows matching a filter" -- and
-- the zero-hit case -- is served from an index with no sort, and so the
-- dashboard's time-windowed GROUP BYs range-scan instead of seq-scanning. The
-- lead time column (timestamp, or stop for cape) also serves the bare
-- go_back_minutes window and the ORDER BY. Conservative set (time + top three
-- filters per table); every index costs write time on ingest, so drop any a
-- given deployment does not search or graph by.
CREATE INDEX suricata_alerts_ts_idx       ON suricata_alerts (timestamp);
CREATE INDEX suricata_alerts_class_ts_idx ON suricata_alerts (classification, timestamp);
CREATE INDEX suricata_alerts_src_ts_idx   ON suricata_alerts (src_ip, timestamp);
CREATE INDEX suricata_alerts_sid_ts_idx   ON suricata_alerts (sid, timestamp);

CREATE INDEX sagan_alerts_ts_idx       ON sagan_alerts (timestamp);
CREATE INDEX sagan_alerts_class_ts_idx ON sagan_alerts (classification, timestamp);
CREATE INDEX sagan_alerts_src_ts_idx   ON sagan_alerts (src_ip, timestamp);
CREATE INDEX sagan_alerts_sid_ts_idx   ON sagan_alerts (sid, timestamp);

CREATE INDEX cape_alerts_stop_idx          ON cape_alerts (stop);
CREATE INDEX cape_alerts_malscore_stop_idx ON cape_alerts (malscore, stop);
CREATE INDEX cape_alerts_src_stop_idx      ON cape_alerts (src_ip, stop);
CREATE INDEX cape_alerts_target_stop_idx   ON cape_alerts (target, stop);

CREATE TABLE dbix_class_deploymenthandler_versions (
  id bigserial NOT NULL,
  version varchar(50) NOT NULL UNIQUE,
  ddl text NULL,
  upgrade_sql text NULL,
  PRIMARY KEY (id)
);
