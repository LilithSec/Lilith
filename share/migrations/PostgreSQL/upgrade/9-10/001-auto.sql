-- Lilith schema upgrade 9 -> 10: Baphomet judgment-log ingestion
--
-- Baphomet emits its own EVE (eve_type "baphomet") recording the verdicts it
-- reaches -- found/banish/noted/alert/sighting/sighted. This table stores those
-- records the same way suricata_alerts/sagan_alerts/cape_alerts store their
-- sources. Baphomet's offender IP maps to src_ip so the existing top-talker,
-- escalation, and %INET machinery reuse it; its subject (a non-IP offender, e.g.
-- a username) gets its own column. As with the sibling tables only the scalar
-- fields worth filtering / sorting / grouping by are promoted to columns; the
-- nested detail (attack, rule, found, marks, references, ...) stays in raw,
-- reachable via raw->'...'. Baphomet has no flow identity, so event_id is
-- derived (see Lilith::_parse_baphomet). Escalation is opt-in: baphomet is not
-- added to the auto_escalations default tables.

CREATE TABLE baphomet_alerts (
    id bigserial NOT NULL,
    instance varchar(255) NOT NULL,
    host varchar(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_id varchar(64) NOT NULL,
    event_type varchar(32) NOT NULL,
    kur varchar(255),
    path varchar(1024),
    score double precision,
    signature varchar(2048),
    severity varchar(32),
    classification varchar(1024),
    src_ip inet,
    dest_ip inet,
    subject varchar(1024),
    ban_time bigint,
    recidive boolean,
    country varchar(16),
    raw jsonb NOT NULL,
    escalations bigint[],
    auto_escalated TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY(id)
);

CREATE INDEX baphomet_alerts_ts_idx       ON baphomet_alerts (timestamp);
CREATE INDEX baphomet_alerts_event_ts_idx ON baphomet_alerts (event_type, timestamp);
CREATE INDEX baphomet_alerts_src_ts_idx   ON baphomet_alerts (src_ip, timestamp);
CREATE INDEX baphomet_alerts_kur_ts_idx   ON baphomet_alerts (kur, timestamp);
