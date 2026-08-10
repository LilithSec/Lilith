-- Lilith schema upgrade 13 -> 14: follow Baphomet's EVE format changes
--
-- Baphomet reworked its EVE output: the top-level offender ip and subject
-- scalars are gone (an offense is now the banishing array and the
-- subject_vars / subjects_crossed maps, which stay in raw), classtype was
-- replaced by category (the same class in the words Suricata's
-- classification.config would use, e.g. 'misc-attack' -> 'Misc Attack'), and
-- the flow vars src_ip / src_port / dest_ip / dest_port / user are promoted to
-- the top level of every event.
--
-- So: the promoted flow vars and the gid/sid/rev trio become columns, subject
-- is dropped (read it from raw if the old rows matter), and existing
-- classification slugs are rewritten to the word form so old and new rows
-- filter as one set. The EVE "user" var is stored as username -- "user" is
-- reserved in Postgres and column names are interpolated unquoted into SQL by
-- the dashboard.
ALTER TABLE baphomet_alerts
    ADD COLUMN gid bigint,
    ADD COLUMN sid bigint,
    ADD COLUMN rev bigint,
    ADD COLUMN src_port integer,
    ADD COLUMN dest_port integer,
    ADD COLUMN username varchar(1024),
    DROP COLUMN subject;

-- The slug -> words table is Baphomet's own (App::Baphomet::Rules::Base), the
-- canonical Snort/Suricata classification.config wording plus Baphomet's log
-- specific additions. Its fallback for an unknown slug is the slug title-cased
-- with the hyphens taken out, which initcap(replace(...)) reproduces. The
-- WHERE keeps this to rows still carrying a slug-shaped value, so word-form
-- rows (and a rerun) pass through untouched.
UPDATE baphomet_alerts SET classification = CASE classification
    WHEN 'attempted-admin'                THEN 'Attempted Administrator Privilege Gain'
    WHEN 'attempted-user'                 THEN 'Attempted User Privilege Gain'
    WHEN 'inappropriate-content'          THEN 'Inappropriate Content was Detected'
    WHEN 'policy-violation'               THEN 'Potential Corporate Privacy Violation'
    WHEN 'shellcode-detect'               THEN 'Executable code was detected'
    WHEN 'successful-admin'               THEN 'Successful Administrator Privilege Gain'
    WHEN 'successful-user'                THEN 'Successful User Privilege Gain'
    WHEN 'trojan-activity'                THEN 'A Network Trojan was detected'
    WHEN 'unsuccessful-user'              THEN 'Unsuccessful User Privilege Gain'
    WHEN 'web-application-attack'         THEN 'Web Application Attack'
    WHEN 'attempted-dos'                  THEN 'Attempted Denial of Service'
    WHEN 'attempted-recon'                THEN 'Attempted Information Leak'
    WHEN 'bad-unknown'                    THEN 'Potentially Bad Traffic'
    WHEN 'default-login-attempt'          THEN 'Attempt to login by a default username and password'
    WHEN 'denial-of-service'              THEN 'Detection of a Denial of Service Attack'
    WHEN 'misc-attack'                    THEN 'Misc Attack'
    WHEN 'non-standard-protocol'          THEN 'Detection of a non-standard protocol or event'
    WHEN 'rpc-portmap-decode'             THEN 'Decode of an RPC Query'
    WHEN 'successful-dos'                 THEN 'Denial of Service'
    WHEN 'successful-recon-largescale'    THEN 'Large Scale Information Leak'
    WHEN 'successful-recon-limited'       THEN 'Information Leak'
    WHEN 'suspicious-filename-detect'     THEN 'A suspicious filename was detected'
    WHEN 'suspicious-login'               THEN 'An attempted login using a suspicious username was detected'
    WHEN 'system-call-detect'             THEN 'A system call was detected'
    WHEN 'unusual-client-port-connection' THEN 'A client was using an unusual port'
    WHEN 'web-application-activity'       THEN 'Access to a potentially vulnerable web application'
    WHEN 'icmp-event'                     THEN 'Generic ICMP event'
    WHEN 'misc-activity'                  THEN 'Misc activity'
    WHEN 'network-scan'                   THEN 'Detection of a Network Scan'
    WHEN 'not-suspicious'                 THEN 'Not Suspicious Traffic'
    WHEN 'protocol-command-decode'        THEN 'Generic Protocol Command Decode'
    WHEN 'string-detect'                  THEN 'A suspicious string was detected'
    WHEN 'unknown'                        THEN 'Unknown Traffic'
    WHEN 'tcp-connection'                 THEN 'A TCP connection was detected'
    WHEN 'coin-mining'                    THEN 'Crypto Currency Mining Activity Detected'
    WHEN 'command-and-control'            THEN 'Malware Command and Control Activity Detected'
    WHEN 'credential-theft'               THEN 'Successful Credential Theft Detected'
    WHEN 'domain-c2'                      THEN 'Domain Observed Used for C2 Detected'
    WHEN 'exploit-kit'                    THEN 'Exploit Kit Activity Detected'
    WHEN 'external-ip-check'              THEN 'Device Retrieving External IP Address Detected'
    WHEN 'pup-activity'                   THEN 'Possibly Unwanted Program Detected'
    WHEN 'social-engineering'             THEN 'Possible Social Engineering Attempted'
    WHEN 'targeted-activity'              THEN 'Targeted Malicious Activity was Detected'
    WHEN 'blocked'                        THEN 'Traffic the Sensor Blocked'
    WHEN 'brute-force'                    THEN 'Brute Force Attack'
    WHEN 'configuration-change'           THEN 'Configuration Change'
    WHEN 'correlated-attack'              THEN 'Correlated Attack'
    WHEN 'exploit-attempt'                THEN 'Exploit Attempt'
    WHEN 'malware'                        THEN 'Malware Activity Detected'
    WHEN 'network-event'                  THEN 'Network Event'
    WHEN 'program-error'                  THEN 'Program Error'
    WHEN 'suspicious-traffic'             THEN 'Suspicious Traffic'
    WHEN 'system-error'                   THEN 'System Error'
    WHEN 'system-event'                   THEN 'System Event'
    WHEN 'unsuccessful-admin'             THEN 'Unsuccessful Administrator Privilege Gain'
    ELSE initcap(replace(classification, '-', ' '))
END
WHERE classification IS NOT NULL AND classification ~ '^[a-z0-9][a-z0-9-]*$';
