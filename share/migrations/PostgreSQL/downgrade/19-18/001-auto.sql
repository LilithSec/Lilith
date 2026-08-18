-- Lilith schema downgrade 19 -> 18: drop the shodan_cache products column
--
-- Nothing is lost that matters. It is the queryable projection of product names
-- the raw column keeps holding, so upgrading again and letting `lilith
-- shodan_cache` refresh fills it right back in.

ALTER TABLE shodan_cache
    DROP COLUMN IF EXISTS products;
