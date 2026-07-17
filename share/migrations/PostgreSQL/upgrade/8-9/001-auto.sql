-- Lilith schema upgrade 8 -> 9: per-dashboard view settings
--
-- Each dashboards row gains a 'settings' JSONB holding that board's own view
-- state -- table, go_back_minutes, and show_gpcd -- applied when the board is
-- selected. Existing boards default to '{}', so they keep using the UI's
-- current controls until saved.

ALTER TABLE dashboards ADD COLUMN settings jsonb NOT NULL DEFAULT '{}';
