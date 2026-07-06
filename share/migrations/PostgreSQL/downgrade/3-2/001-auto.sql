-- Lilith schema downgrade 3 -> 2: drop the escalation system tables and
-- the per-alert escalation ID arrays

ALTER TABLE suricata_alerts DROP COLUMN escalations;

ALTER TABLE sagan_alerts DROP COLUMN escalations;

ALTER TABLE cape_alerts DROP COLUMN escalations;

DROP TABLE escalations;

DROP TABLE escalation_targets;
