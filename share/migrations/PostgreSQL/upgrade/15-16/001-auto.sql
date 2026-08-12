-- Lilith schema upgrade 15 -> 16: the CVEDB lookup cache, and the CVE ids a
-- Suricata rule names promoted out of raw into a generated column
--
-- Purely additive. The table is the store behind `lilith cvedb_cache`; nothing
-- reads or writes it until that command is run, so upgrading turns nothing on.
--
-- One row per CVE id, holding what Shodan's free, keyless CVEDB
-- (https://cvedb.shodan.io) said about it. 'raw' is the response as it
-- arrived, minus its 'cpes' list -- the one field nothing displays, and for a
-- CVE like Log4Shell most of the payload. The columns beside it are the parts
-- worth querying without opening the JSON: the score to color a chip by, and
-- the EPSS / KEV / ransomware signals that change what a CVE means in triage.
-- 'found' is false for an id CVEDB has nothing on, cached deliberately so it
-- is not re-asked every run.
--
-- Unlike shodan_cache there is no freshness gate on reads: CVE detail only
-- firms up (CVSS is effectively immutable, KEV only grows, EPSS drifts a
-- little daily), so the web serves whatever row exists however old, and
-- 'fetched' is read only by `lilith cvedb_cache` to pick what to refresh.
--
-- fillfactor is lowered for the same reason as on shodan_cache: refresh is
-- UPDATE churn against a stable row count, the opposite of the alert tables.
--
-- No index beyond the primary key: every read is a point or ANY() lookup on
-- cve over a table holding at most a few thousand rows.
CREATE TABLE cvedb_cache (
    cve varchar(32) NOT NULL,
    found boolean NOT NULL,
    fetched TIMESTAMP WITH TIME ZONE NOT NULL,
    cvss numeric(3,1),
    epss numeric(6,5),
    kev boolean,
    ransomware boolean,
    raw jsonb,
    PRIMARY KEY(cve)
) WITH (fillfactor = 70);

-- The CVE ids a Suricata rule names, promoted out of raw the same way and for
-- the same reason as severity and the MITRE annotations in 12 -> 13: comparing
-- them against shodan_cache.vulns -- "an exploit for a CVE the destination is
-- actually vulnerable to" -- has to happen in SQL for the dashboard and the
-- search filters, and digging them out of raw per row means detoasting the
-- whole EVE record to read a few ids.
--
-- Rulesets write the ids into alert.metadata.cve in several shapes
-- (CVE_2021_44228, cve-2021-44228, a bare 2021-44228) and often only into the
-- signature text, so the extraction reads both and normalizes everything to
-- CVE-YYYY-NNNN. That takes a function rather than an inline expression; it is
-- IMMUTABLE (it reads nothing but its argument) so it can back the generated
-- column. Kept in step with Lilith::CVEDB::rule_cves, the same extraction for
-- code holding a decoded row -- change one and change the other.
--
-- NULL rather than an empty array when a rule names none, so "no CVE in rule"
-- is one IS NULL test.
--
-- No index. Every read of cves rides an existing timestamp index: the search
-- filters always carry the time window, and the dashboard dimension groups
-- over it.
--
-- NOTE ON RUNNING THIS: like 12 -> 13, adding a stored generated column
-- rewrites the table and holds ACCESS EXCLUSIVE while it does, detoasting
-- every row's raw once. Take the ingest down for it rather than discovering
-- the lock in production.
CREATE FUNCTION suricata_alert_cves(raw jsonb) RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $func$
SELECT nullif(
    array(
        SELECT DISTINCT 'CVE-' || matched[1]
        FROM (
            -- alert.metadata.cve entries; a string is taken as a one-entry list
            SELECT upper(translate(value, '_', '-')) AS candidate
            FROM jsonb_array_elements_text(
                CASE jsonb_typeof(raw->'alert'->'metadata'->'cve')
                    WHEN 'array' THEN raw->'alert'->'metadata'->'cve'
                    WHEN 'string' THEN jsonb_build_array(raw->'alert'->'metadata'->'cve')
                    ELSE '[]'::jsonb
                END)
            UNION ALL
            -- ids named in the signature text
            SELECT 'CVE-' || m[1] || '-' || m[2]
            FROM regexp_matches(upper(coalesce(raw->'alert'->>'signature', '')),
                                'CVE[-_ ]?([0-9]{4})[-_]([0-9]{4,})', 'g') AS m
        ) AS candidates,
        LATERAL regexp_match(candidate, '^(?:CVE-)?([0-9]{4}-[0-9]{4,})$') AS matched
        WHERE matched IS NOT NULL
        ORDER BY 1
    ),
    '{}'
)
$func$;

ALTER TABLE suricata_alerts
    ADD COLUMN cves text[]
        GENERATED ALWAYS AS (suricata_alert_cves(raw)) STORED;

ANALYZE suricata_alerts;
