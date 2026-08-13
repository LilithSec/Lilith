-- Lilith schema upgrade 16 -> 17: what the host runs and who it belongs to,
-- promoted out of shodan_cache.raw into columns
--
-- Purely additive, and cheap: shodan_cache is one row per address, so the
-- ALTER is instant.
--
-- The four are the queryable projection of fields the raw response already
-- holds -- columns so the dashboard can group by them ("top attacking ASNs",
-- "top attacker OSes"), which a render-time read of raw or a GeoIP lookup
-- never can. The keyless tier sends none of them, so on an InternetDB-only
-- install they stay NULL and the dimensions built on them stay empty.
--
-- Nothing is backfilled: rows written before this held only what the old
-- normalize kept, and `lilith shodan_cache` on its timer refreshes each row
-- within its TTL anyway, filling the columns as it goes.

ALTER TABLE shodan_cache
    ADD COLUMN os varchar(255),
    ADD COLUMN org varchar(255),
    ADD COLUMN isp varchar(255),
    ADD COLUMN asn varchar(32);
