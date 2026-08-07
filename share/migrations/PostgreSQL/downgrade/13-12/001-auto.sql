-- Lilith schema downgrade 13 -> 12: drop the generated columns and restore the
-- expression indexes
--
-- Nothing is lost with the columns: they were computed from raw, which still
-- holds every value. Dropping them takes the indexes on them with it.
--
-- The version 5 expression indexes are recreated, since a reader back on
-- version 12 reads these fields by expression again and those are what served
-- it. They are built here without CONCURRENTLY because a migration runs in a
-- transaction; on a large table expect the same lock the upgrade warns about.

ALTER TABLE suricata_alerts
    DROP COLUMN IF EXISTS severity,
    DROP COLUMN IF EXISTS mitre_tactic,
    DROP COLUMN IF EXISTS mitre_technique;

CREATE INDEX IF NOT EXISTS suricata_alerts_severity_ts_idx
    ON suricata_alerts ((raw->'alert'->>'severity'), "timestamp");

CREATE INDEX IF NOT EXISTS suricata_alerts_mitre_tactic_idx
    ON suricata_alerts ((raw->'alert'->'metadata'->'mitre_tactic_name'->>0), "timestamp")
    WHERE (raw->'alert'->'metadata'->'mitre_tactic_name'->>0) IS NOT NULL;

CREATE INDEX IF NOT EXISTS suricata_alerts_mitre_technique_idx
    ON suricata_alerts ((raw->'alert'->'metadata'->'mitre_technique_name'->>0), "timestamp")
    WHERE (raw->'alert'->'metadata'->'mitre_technique_name'->>0) IS NOT NULL;

ANALYZE suricata_alerts;
