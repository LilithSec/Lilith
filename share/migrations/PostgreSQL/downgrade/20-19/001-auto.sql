-- Lilith schema downgrade 20 -> 19: drop the shodan_cache port_products column
--
-- Nothing is lost that matters. It is the queryable projection of the per-port
-- product pairing the raw column keeps holding, so upgrading again and letting
-- `lilith shodan_cache` refresh fills it right back in.

ALTER TABLE shodan_cache
    DROP COLUMN IF EXISTS port_products;
