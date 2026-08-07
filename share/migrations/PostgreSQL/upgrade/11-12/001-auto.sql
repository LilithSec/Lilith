-- Lilith schema upgrade 11 -> 12: keep analyze and vacuum to a flat cadence on
-- the alert tables
--
-- The alert tables only grow, and the dashboards read them over a recent
-- window. The server's defaults trigger analyze and vacuum at a fraction of the
-- table, so the bar rises as the annals fill and the statistics for the newest
-- rows -- the ones being queried -- are the first to go stale.
--
-- The failure is not gradual. Without a histogram of the timestamp column the
-- planner cannot tell how much of a table a window covers, falls back to a
-- fixed guess of about a third, and at that fraction a sequential scan really
-- is cheaper than an index lookup. So it reads the whole table and never
-- touches the timestamp index that exists for the query. This was measured on
-- the sibling Allani store: an 8 million row table estimated a 24 hour window
-- at 2.7 million rows when it held 170 thousand, and the dashboard took 20
-- seconds instead of under one.
--
-- The insert trigger matters separately. These tables are appended to far more
-- than they are updated, so dead tuples alone may never reach any threshold and
-- the table can go unvacuumed indefinitely -- which leaves the visibility map
-- stale, and a stale visibility map is what stops Postgres answering a count or
-- a group-by from an index alone.
--
-- A zero scale factor with a flat threshold gives a constant cadence for all
-- three, whatever the table size. 50k is roughly a day of a busy sensor and
-- cheap either way: analyze samples rather than reads, and vacuuming an
-- append-only table has little to do beyond marking pages visible.

ALTER TABLE suricata_alerts SET (
    autovacuum_analyze_scale_factor       = 0,
    autovacuum_analyze_threshold          = 50000,
    autovacuum_vacuum_scale_factor        = 0,
    autovacuum_vacuum_threshold           = 50000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold    = 50000
);

ALTER TABLE sagan_alerts SET (
    autovacuum_analyze_scale_factor       = 0,
    autovacuum_analyze_threshold          = 50000,
    autovacuum_vacuum_scale_factor        = 0,
    autovacuum_vacuum_threshold           = 50000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold    = 50000
);

ALTER TABLE cape_alerts SET (
    autovacuum_analyze_scale_factor       = 0,
    autovacuum_analyze_threshold          = 50000,
    autovacuum_vacuum_scale_factor        = 0,
    autovacuum_vacuum_threshold           = 50000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold    = 50000
);

ALTER TABLE baphomet_alerts SET (
    autovacuum_analyze_scale_factor       = 0,
    autovacuum_analyze_threshold          = 50000,
    autovacuum_vacuum_scale_factor        = 0,
    autovacuum_vacuum_threshold           = 50000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold    = 50000
);

-- The settings above only take effect once a table next gains 50k rows, and an
-- existing database may have no statistics at all. Seed them here so the
-- upgrade itself fixes the plans. ANALYZE is allowed inside a transaction
-- block, unlike VACUUM, so only the analyze half can run from a migration --
-- a store that has never been vacuumed wants one afterwards, to populate the
-- visibility map.

ANALYZE suricata_alerts;
ANALYZE sagan_alerts;
ANALYZE cape_alerts;
ANALYZE baphomet_alerts;
