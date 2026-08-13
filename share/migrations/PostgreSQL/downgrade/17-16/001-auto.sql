-- Lilith schema downgrade 17 -> 16: drop the shodan_cache os/org/isp/asn
-- columns
--
-- Nothing is lost that matters. The four are the queryable projection of
-- fields the raw column keeps holding, so upgrading again and letting
-- `lilith shodan_cache` refresh fills them right back in.

ALTER TABLE shodan_cache
    DROP COLUMN IF EXISTS os,
    DROP COLUMN IF EXISTS org,
    DROP COLUMN IF EXISTS isp,
    DROP COLUMN IF EXISTS asn;
