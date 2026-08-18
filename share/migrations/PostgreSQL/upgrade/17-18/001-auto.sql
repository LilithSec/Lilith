-- Lilith schema upgrade 17 -> 18: the interpretive projection of the response,
-- promoted out of shodan_cache.raw into columns
--
-- Purely additive, and cheap: shodan_cache is one row per address, so the
-- ALTER is instant.
--
-- The four are the queryable projection of what normalize already works out of
-- the raw response -- the callout keys the modal shows, and the service
-- fingerprints (HTML hash, certificate, banner hash) it pivots on. Columns so
-- the /shodan browser can filter on them and the neighborhood panel can find
-- other cached hosts sharing them, neither of which a render-time read of raw
-- could do.
--
-- Nothing is backfilled: rows written before this hold the raw response but not
-- the new columns, and `lilith shodan_cache` on its timer refills each within
-- its TTL, re-normalizing from the raw it kept.

ALTER TABLE shodan_cache
    ADD COLUMN callouts varchar[],
    ADD COLUMN html_hashes bigint[],
    ADD COLUMN cert_fingerprints varchar[],
    ADD COLUMN banner_hashes bigint[];
