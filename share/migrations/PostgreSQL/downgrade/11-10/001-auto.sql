-- Lilith schema downgrade 11 -> 10: cape_alerts.malscore back to bigint
--
-- Reverses the 10 -> 11 widening. Fractional scores stored while at version 11
-- are rounded to the nearest integer, since bigint cannot hold them.

ALTER TABLE cape_alerts ALTER COLUMN malscore TYPE bigint USING round(malscore);
