-- Lilith schema downgrade 14 -> 13: drop the promoted Baphomet columns and
-- restore subject
--
-- Nothing is lost with the dropped columns: they were read out of raw, which
-- still holds every value. subject comes back empty -- the EVE format that
-- carried it is gone, and the rows ingested under 14 never had one -- so this
-- only restores the shape a version-13 reader expects. The classification
-- rewrite is not undone; the word forms remain valid values for a version-13
-- reader.

ALTER TABLE baphomet_alerts
    DROP COLUMN IF EXISTS gid,
    DROP COLUMN IF EXISTS sid,
    DROP COLUMN IF EXISTS rev,
    DROP COLUMN IF EXISTS src_port,
    DROP COLUMN IF EXISTS dest_port,
    DROP COLUMN IF EXISTS username,
    ADD COLUMN subject varchar(1024);
