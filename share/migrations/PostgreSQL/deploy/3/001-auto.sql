-- Lilith schema version 3

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

CREATE TABLE dbix_class_deploymenthandler_versions (
  id bigserial NOT NULL,
  version varchar(50) NOT NULL UNIQUE,
  ddl text NULL,
  upgrade_sql text NULL,
  PRIMARY KEY (id)
);
