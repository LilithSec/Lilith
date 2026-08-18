-- Lilith schema upgrade 18 -> 19: the product names a host runs, promoted out
-- of shodan_cache.raw into a column
--
-- Purely additive, and cheap: shodan_cache is one row per address, so the
-- ALTER is instant.
--
-- The product names its service banners identify ('nginx', 'Apache httpd') are
-- a column so the /shodan browser can filter on them and the neighborhood panel
-- can facet them the way the Shodan count endpoint does -- which the raw
-- response holds per service but neither could query, and which the CPE strings
-- serve only clumsily. Names only; versions stay per-service in raw.
--
-- Nothing is backfilled: rows written before this hold the raw response but not
-- the column, and `lilith shodan_cache` on its timer refills each within its
-- TTL, re-normalizing from the raw it kept.

ALTER TABLE shodan_cache
    ADD COLUMN products varchar[];
