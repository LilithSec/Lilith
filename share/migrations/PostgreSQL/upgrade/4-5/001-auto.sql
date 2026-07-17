-- Lilith schema upgrade 4 -> 5: search / dashboard indexes
--
-- Until now the alert tables carried only their primary key, so both the
-- search() query and the web dashboard's aggregations seq-scanned the whole
-- table. These composite (column, <order-col>) btrees serve "the newest N rows
-- matching a filter" -- and the zero-hit case -- straight from an index with no
-- sort, and let the dashboard's time-windowed GROUP BYs range-scan instead of
-- reading every row. The lead time column (timestamp, or stop for cape) also
-- serves the bare go_back_minutes window and the ORDER BY.
--
-- This is the conservative set: the time column plus the top three filters per
-- table. Other cuts (dest_ip, dest_port, instance, app_proto, program, and the
-- md5/sha256 hash pivots) can be added per deployment, and a BRIN on the time
-- column is a cheaper alternative to the btree for very high ingest rates.
-- Every index costs write time on ingest, so drop any a given deployment does
-- not search or graph by.

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
