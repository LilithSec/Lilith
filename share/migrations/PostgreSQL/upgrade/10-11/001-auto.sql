-- Lilith schema upgrade 10 -> 11: cape_alerts.malscore becomes floating point
--
-- CAPEv2's malscore is a fractional score (e.g. 0.2, 7.5), but the column was
-- declared bigint, so any non-integer score aborted the INSERT with
-- "invalid input syntax for type bigint". Widen it to double precision to match
-- what CAPE actually emits (and the sibling baphomet_alerts.score column). The
-- cape_alerts_malscore_stop_idx index rides along with the type change.

ALTER TABLE cape_alerts ALTER COLUMN malscore TYPE double precision;
