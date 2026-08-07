-- Lilith schema upgrade 12 -> 13: promote the Suricata alert severity and MITRE
-- annotations out of raw into generated columns
--
-- The dashboard can group by three Suricata fields that live only in the raw
-- EVE record: the alert severity, and the ATT&CK tactic and technique rulesets
-- put in alert.metadata. Reading one of them means digging it out of raw with
-- an expression, once per row.
--
-- That is far more expensive than it looks, because raw is large. On a
-- production store it averages 15.7KB and 91% of rows exceed the 2KB threshold
-- at which Postgres stores a value out of line, so the whole document has to be
-- fetched back from the TOAST table to read a one character severity. Grouping
-- by severity over 30 days took 11.5 seconds against 90 milliseconds for
-- classification, an ordinary column, over the same window -- 128 times slower,
-- and 45 times the I/O.
--
-- Indexing the expression does not fix it. Postgres will use an expression
-- index to filter by a value, but will not hand the value back from the index
-- to satisfy a grouping, so it reads and detoasts anyway. Measured with a
-- ("timestamp", expression) index in place and every other plan type disabled,
-- it still chose the plain timestamp index and still took 1.3 seconds.
--
-- So the value has to be a real column. GENERATED ALWAYS ... STORED computes it
-- on insert from the row's own raw, which means the ingest path needs no
-- changes and the column cannot drift from the record it came from. With a
-- ("timestamp", column) index the same grouping became an index only scan: 18
-- milliseconds, and three buffers rather than half a million.
--
-- The MITRE columns are indexed only where they are set. The annotations come
-- from rulesets that carry them, and on the store this was written against that
-- was 0.7% of alerts -- a partial index covers the rows worth finding at a
-- fraction of the size.
--
-- Suricata only. Baphomet already carries severity as an ordinary column.
--
-- NOTE ON RUNNING THIS: adding a stored generated column rewrites the table and
-- holds ACCESS EXCLUSIVE while it does, which blocks readers and the ingest
-- daemon alike. Every existing row has its raw detoasted once to compute the
-- value, so the time scales with the TOAST rather than the row count -- 73
-- seconds for 100k rows of this shape in testing. Take the ingest down for it
-- rather than discovering the lock in production.

ALTER TABLE suricata_alerts
    ADD COLUMN severity text
        GENERATED ALWAYS AS (raw->'alert'->>'severity') STORED,
    ADD COLUMN mitre_tactic text
        GENERATED ALWAYS AS (raw->'alert'->'metadata'->'mitre_tactic_name'->>0) STORED,
    ADD COLUMN mitre_technique text
        GENERATED ALWAYS AS (raw->'alert'->'metadata'->'mitre_technique_name'->>0) STORED;

CREATE INDEX suricata_alerts_ts_severity_idx ON suricata_alerts ("timestamp", severity);

CREATE INDEX suricata_alerts_ts_mitre_tactic_idx ON suricata_alerts ("timestamp", mitre_tactic)
    WHERE mitre_tactic IS NOT NULL;
CREATE INDEX suricata_alerts_ts_mitre_technique_idx ON suricata_alerts ("timestamp", mitre_technique)
    WHERE mitre_technique IS NOT NULL;

-- The version 5 indexes on the same expressions are what filtering by one of
-- these used before there was a column, and the column makes them unreachable:
-- a query naming the column cannot match an index on the expression. Drop them
-- rather than leave three indexes maintained on every insert for nothing.
DROP INDEX IF EXISTS suricata_alerts_severity_ts_idx;
DROP INDEX IF EXISTS suricata_alerts_mitre_tactic_idx;
DROP INDEX IF EXISTS suricata_alerts_mitre_technique_idx;

ANALYZE suricata_alerts;
