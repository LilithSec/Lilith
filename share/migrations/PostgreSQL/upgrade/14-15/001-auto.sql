-- Lilith schema upgrade 14 -> 15: the Shodan lookup cache
--
-- Purely additive. The table is the store behind shodan_cache_ttl; with that
-- unset nothing reads or writes it, so upgrading does not turn anything on.
--
-- One row per address. 'raw' is Shodan's response as it arrived and is what the
-- IP info modal is rendered from -- the columns beside it are the parts worth
-- querying without opening the JSON, written by Lilith rather than generated,
-- since pulling an array out of jsonb needs a set-returning function and a
-- generated column cannot use one.
--
-- 'source' names which tier answered ('api' or 'internetdb'), since the two
-- differ in depth -- a row from the keyless tier is treated as a miss once a key
-- is configured. 'found' is false for an address Shodan has never crawled, which
-- is cached deliberately: it is the lookup that would otherwise be repeated most.
-- 'fetched' is when Lilith asked and is what freshness is measured against;
-- 'last_update' is when Shodan itself last crawled, and is null on the keyless
-- tier, which does not report it.
--
-- fillfactor is lowered because this is almost all UPDATE churn against a stable
-- row count -- the opposite of the alert tables. Leaving space on the page lets
-- Postgres do the update in place and skip the index write.
--
-- No index beyond the primary key: every read is a point lookup on ip, and the
-- prune that runs on write is a sequential scan of a table holding at most a few
-- thousand rows either way.
CREATE TABLE shodan_cache (
    ip inet NOT NULL,
    source varchar(16) NOT NULL,
    found boolean NOT NULL,
    fetched TIMESTAMP WITH TIME ZONE NOT NULL,
    last_update TIMESTAMP WITH TIME ZONE,
    ports integer[],
    tags varchar[],
    cpes varchar[],
    vulns varchar[],
    max_cvss numeric(3,1),
    hostnames varchar[],
    raw jsonb,
    PRIMARY KEY(ip)
) WITH (fillfactor = 70);
