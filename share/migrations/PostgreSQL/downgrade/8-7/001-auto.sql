-- Lilith schema downgrade 8 -> 7: drop the MITRE ATT&CK indexes

DROP INDEX IF EXISTS suricata_alerts_mitre_tactic_idx;
DROP INDEX IF EXISTS suricata_alerts_mitre_technique_idx;
