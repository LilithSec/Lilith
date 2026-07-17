-- Lilith schema downgrade 9 -> 8: drop the per-dashboard view settings

ALTER TABLE dashboards DROP COLUMN settings;
