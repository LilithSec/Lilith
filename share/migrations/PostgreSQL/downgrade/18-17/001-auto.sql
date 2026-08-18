-- Lilith schema downgrade 18 -> 17: drop the shodan_cache callout and
-- fingerprint columns
--
-- Nothing is lost that matters. The four are the queryable projection of what
-- the raw column keeps holding, so upgrading again and letting `lilith
-- shodan_cache` refresh fills them right back in.

ALTER TABLE shodan_cache
    DROP COLUMN IF EXISTS callouts,
    DROP COLUMN IF EXISTS html_hashes,
    DROP COLUMN IF EXISTS cert_fingerprints,
    DROP COLUMN IF EXISTS banner_hashes;
