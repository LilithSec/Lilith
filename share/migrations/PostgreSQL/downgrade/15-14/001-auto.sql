-- Lilith schema downgrade 15 -> 14: drop the Shodan lookup cache
--
-- Nothing is lost that matters. Every row is a copy of an answer Shodan will
-- give again for the asking, so dropping the table costs the lookups back, not
-- any data of Lilith's own.

DROP TABLE IF EXISTS shodan_cache;
