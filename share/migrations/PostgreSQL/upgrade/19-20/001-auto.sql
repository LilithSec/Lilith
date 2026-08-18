-- Lilith schema upgrade 19 -> 20: the port-to-product pairing, promoted out of
-- shodan_cache.raw into a column
--
-- Purely additive, and cheap: shodan_cache is one row per address, so the
-- ALTER is instant.
--
-- The products column (schema 19) holds the names alone, so a port list
-- rendered from columns -- the /shodan browser, the results tables' port
-- badges -- cannot say which port runs what. This keeps the pairing as
-- 'PORT product version' strings, e.g. '443 nginx 1.18.0', one per distinct
-- pair, current ports only.
--
-- Nothing is backfilled: rows written before this hold the raw response but not
-- the column, and `lilith shodan_cache` on its timer refills each within its
-- TTL, re-normalizing from the raw it kept.

ALTER TABLE shodan_cache
    ADD COLUMN port_products varchar[];
