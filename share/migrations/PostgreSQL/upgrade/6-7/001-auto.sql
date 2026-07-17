-- Lilith schema upgrade 6 -> 7: Suricata severity index
--
-- Expression index backing the dashboard's Suricata severity widget, which
-- groups by raw->alert->severity (a field kept only in the raw EVE, not promoted
-- to a column). Same (dimension, time) shape as the version-5 indexes so a
-- time-windowed GROUP BY on severity is served from the index. Only Suricata
-- populates alert.severity; Sagan carries severity in its priority/level columns.

CREATE INDEX suricata_alerts_severity_ts_idx ON suricata_alerts ((raw->'alert'->>'severity'), timestamp);
