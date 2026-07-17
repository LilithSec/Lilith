-- Lilith schema upgrade 7 -> 8: MITRE ATT&CK indexes
--
-- Partial expression indexes backing the dashboard's MITRE tactic/technique
-- widgets, which group by the names rulesets (e.g. Emerging Threats) put in
-- alert.metadata as single-element arrays. Partial because MITRE is present on
-- only a small fraction of alerts, so the index stays tiny. Only Suricata
-- carries this metadata.

CREATE INDEX suricata_alerts_mitre_tactic_idx ON suricata_alerts
    ((raw->'alert'->'metadata'->'mitre_tactic_name'->>0), timestamp)
    WHERE (raw->'alert'->'metadata'->'mitre_tactic_name'->>0) IS NOT NULL;
CREATE INDEX suricata_alerts_mitre_technique_idx ON suricata_alerts
    ((raw->'alert'->'metadata'->'mitre_technique_name'->>0), timestamp)
    WHERE (raw->'alert'->'metadata'->'mitre_technique_name'->>0) IS NOT NULL;
