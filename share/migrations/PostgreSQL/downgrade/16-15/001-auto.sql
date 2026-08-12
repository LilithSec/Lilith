-- Lilith schema downgrade 16 -> 15: drop the CVEDB lookup cache and the
-- Suricata cves column
--
-- Nothing is lost that matters. Every cvedb_cache row is a copy of an answer
-- CVEDB will give again for the asking, and cves is generated from raw, which
-- stays -- upgrading again recomputes it.

DROP TABLE IF EXISTS cvedb_cache;

-- The column depends on the function, so it goes first.
ALTER TABLE suricata_alerts DROP COLUMN IF EXISTS cves;
DROP FUNCTION IF EXISTS suricata_alert_cves(jsonb);
