-- Lilith schema downgrade 5 -> 4: drop the search / dashboard indexes

DROP INDEX IF EXISTS suricata_alerts_ts_idx;
DROP INDEX IF EXISTS suricata_alerts_class_ts_idx;
DROP INDEX IF EXISTS suricata_alerts_src_ts_idx;
DROP INDEX IF EXISTS suricata_alerts_sid_ts_idx;

DROP INDEX IF EXISTS sagan_alerts_ts_idx;
DROP INDEX IF EXISTS sagan_alerts_class_ts_idx;
DROP INDEX IF EXISTS sagan_alerts_src_ts_idx;
DROP INDEX IF EXISTS sagan_alerts_sid_ts_idx;

DROP INDEX IF EXISTS cape_alerts_stop_idx;
DROP INDEX IF EXISTS cape_alerts_malscore_stop_idx;
DROP INDEX IF EXISTS cape_alerts_src_stop_idx;
DROP INDEX IF EXISTS cape_alerts_target_stop_idx;
