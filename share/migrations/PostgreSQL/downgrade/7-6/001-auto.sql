-- Lilith schema downgrade 7 -> 6: drop the Suricata severity index

DROP INDEX IF EXISTS suricata_alerts_severity_ts_idx;
