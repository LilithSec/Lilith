/*
 * The built-in dashboard presets the Reset menu offers.
 *
 * Each is a plain list of ordinary widgets, so anything seeded can still be
 * reconfigured, moved, or removed afterwards. An alert preset carries a
 * `table`, which also becomes the board's Default table; a log preset has none
 * and instead pins each widget's own Allani source, so it reads that log
 * whatever the Default table is. A panel whose column does not exist for its
 * table simply notes so rather than failing.
 *
 * Data only -- see /js/dashboard.js for what consumes it. Exposed as
 * window.LilithDashboardPresets.
 */
(function () {
var PRESETS = [
  // Suricata -- the SIEM overview (also the default board's seed).
  { key: 'suricata', label: 'Suricata (SIEM overview)', table: 'suricata', widgets: [
    { type: 'stat', config: { metric: 'total' },                                                      x: 0,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique sources' },        x: 2,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'dest_ip', label: 'Unique destinations' },  x: 4,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'signature', label: 'Unique signatures' },  x: 6,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'escalated' },                                                  x: 8,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'busiest', column: 'instance', label: 'Busiest sensor' },       x: 10, y: 0, w: 2, h: 1 },
    { type: 'timeseries', config: { group_by: 'classification' },         x: 0,  y: 1, w: 10, h: 4 },
    { type: 'top',        config: { column: 'mitre_tactic', style: 'pie' },x: 10, y: 1, w: 2,  h: 4 },
    { type: 'top',        config: { column: 'classification' },        x: 0, y: 5,  w: 4,  h: 4 },
    { type: 'top',        config: { column: 'signature' },             x: 4, y: 5,  w: 4,  h: 4 },
    { type: 'top',        config: { column: 'severity', style: 'pie' },      x: 8,  y: 5, w: 2, h: 4 },
    { type: 'top',        config: { column: 'mitre_technique', style: 'pie' },x: 10, y: 5, w: 2, h: 4 },
    { type: 'top',        config: { column: 'src_ip' },                x: 0, y: 9,  w: 4,  h: 4 },
    { type: 'top',        config: { column: 'dest_ip' },               x: 4, y: 9,  w: 4,  h: 4 },
    { type: 'top',        config: { column: 'dest_port' },             x: 8, y: 9,  w: 4,  h: 4 },
    { type: 'top',        config: { column: 'app_proto', style: 'pie' },x: 0, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'instance' },              x: 4, y: 13, w: 4,  h: 4 },
    { type: 'countries',  config: {},                                  x: 8, y: 13, w: 4,  h: 4 },
    { type: 'timeseries', config: { measure: 'bytes' },                x: 0, y: 17, w: 12, h: 4 },
    { type: 'top',        config: { column: 'src_ip', measure: 'bytes' },             x: 0, y: 21, w: 6, h: 4 },
    { type: 'top',        config: { column: 'src_ip', measure: 'distinct_dest_port' },x: 6, y: 21, w: 6, h: 4 }
  ] },
  // CAPE -- malware sandbox detonations.
  { key: 'cape', label: 'CAPE (malware sandbox)', table: 'cape', widgets: [
    // dest_ip on a detonation is not an offender but what the sample reached
    // out to -- the download and command and control side -- so it earns a
    // count and a panel of its own next to the source the submission came from.
    { type: 'stat', config: { metric: 'total', label: 'Total detonations' },                          x: 0,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique sources' },        x: 2,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'dest_ip', label: 'Unique destinations' },  x: 4,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'target', label: 'Unique targets' },        x: 6,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'md5', label: 'Unique samples' },           x: 8,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'busiest', column: 'instance', label: 'Busiest sensor' },       x: 10, y: 0, w: 2, h: 1 },
    { type: 'timeseries', config: {},                             x: 0, y: 1, w: 8, h: 4 },
    { type: 'top',        config: { column: 'malscore', style: 'pie' }, x: 8, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { column: 'target' },       x: 0, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'pkg', style: 'pie' }, x: 4, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'url_hostname' }, x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip' },       x: 0, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'dest_ip' },      x: 4, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'md5' },          x: 8, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'sha256' },       x: 0, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'target', measure: 'max_malscore' }, x: 4, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'instance' },     x: 8, y: 13, w: 4, h: 4 },
    { type: 'countries',  config: {},                         x: 0, y: 17, w: 4, h: 4 },
    { type: 'timeseries', config: { measure: 'sum_size' },     x: 4, y: 17, w: 8, h: 4 }
  ] },
  // Baphomet -- its own judgment log (found/banish/noted/alert/sighting/sighted).
  { key: 'baphomet', label: 'Baphomet (judgments overview)', table: 'baphomet', widgets: [
    // src_ip and dest_ip are counted separately rather than summed into one
    // "offenders" number: which side an offender lands on is up to the rule that
    // judged the line, so neither column alone is the offender count and adding
    // them would count a judgment naming both twice.
    { type: 'stat', config: { metric: 'total', label: 'Total judgments' },                            x: 0,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique sources' },        x: 2,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'dest_ip', label: 'Unique destinations' },  x: 4,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'username', label: 'Unique users' },        x: 6,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'escalated' },                                                  x: 8,  y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'busiest', column: 'kur', label: 'Busiest kur' },               x: 10, y: 0, w: 2, h: 1 },
    { type: 'timeseries', config: { group_by: 'event_type' },              x: 0,  y: 1, w: 10, h: 4 },
    { type: 'top',        config: { column: 'event_type', style: 'pie' },  x: 10, y: 1, w: 2,  h: 4 },
    { type: 'top',        config: { column: 'classification' },        x: 0, y: 5,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'signature' },             x: 4, y: 5,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'severity', style: 'pie' },x: 8, y: 5,  w: 4, h: 4 },
    // dest_ip is panelled alongside src_ip for the same reason the stat boxes
    // are: an offender lands on whichever side the rule that judged the line
    // reads, so a src-only panel hides every verdict passed on the far end.
    { type: 'top',        config: { column: 'src_ip' },                x: 0, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'dest_ip' },               x: 4, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'username' },              x: 8, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'kur' },                   x: 0, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'country', style: 'pie' }, x: 4, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'instance' },              x: 8, y: 13, w: 4, h: 4 },
    { type: 'countries',  config: {},                                         x: 0, y: 17, w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip',  measure: 'max_score' }, x: 4, y: 17, w: 4, h: 4 },
    { type: 'top',        config: { column: 'dest_ip', measure: 'max_score' }, x: 8, y: 17, w: 4, h: 4 },
    { type: 'timeseries', config: { measure: 'avg_score' },                    x: 0, y: 21, w: 12, h: 4 }
  ] },
  // Shodan enrichment -- Suricata alerts cut by what Shodan knows about the
  // hosts at either end of them, rather than by the alert's own columns.
  //
  // The coverage and staleness stats lead deliberately. Every other panel here
  // describes only the addresses shodan_cache has a current answer for, so
  // without them a board of these reads as if it covered the whole window. Run
  // `lilith shodan_cache` on a timer to keep coverage up and staleness down.
  //
  // The source panels come first because on inbound traffic that is the outside
  // host; the destination band at the bottom is what the alerts reached out to,
  // which is where the command and control and download side shows up. On a
  // sensor watching inbound traffic only, those panels are mostly "not looked
  // up" -- the destination is your own asset, which is private and never sent
  // to Shodan -- and the destination coverage stat beside them says so.
  { key: 'shodan', label: 'Shodan (host enrichment)', table: 'suricata', widgets: [
    { type: 'stat', config: { metric: 'shodan_src_coverage' },                                            x: 0, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { metric: 'shodan_src_staleness' },                                           x: 3, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { metric: 'total' },                                                          x: 6, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique sources' },            x: 8, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'shodan_src_vuln', label: 'CVEs on sources' },  x: 10, y: 0, w: 2, h: 1 },
    { type: 'timeseries', config: { group_by: 'shodan_src_tag' },                x: 0, y: 1, w: 8, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_known', style: 'pie' },  x: 8, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_tag' },                  x: 0, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_vuln' },                 x: 4, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_cvss', style: 'pie' },   x: 8, y: 5, w: 4, h: 4 },
    // what the attacking hosts are themselves running -- one appliance model or
    // one exposed service across many addresses is a botnet's fingerprint
    { type: 'top',        config: { column: 'shodan_src_cpe' },                  x: 0, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_port' },                 x: 4, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip' },                          x: 8, y: 9, w: 4, h: 4 },
    { type: 'timeseries', config: { group_by: 'shodan_src_known' },              x: 0, y: 13, w: 12, h: 4 },
    // the far end
    { type: 'stat', config: { metric: 'shodan_dest_coverage' },                                              x: 0, y: 17, w: 4, h: 1 },
    { type: 'stat', config: { metric: 'shodan_dest_staleness' },                                             x: 4, y: 17, w: 4, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'dest_ip', label: 'Unique destinations' },         x: 8, y: 17, w: 4, h: 1 },
    { type: 'top',        config: { column: 'shodan_dest_tag' },                 x: 0, y: 18, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_dest_cpe' },                 x: 4, y: 18, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_dest_known', style: 'pie' }, x: 8, y: 18, w: 4, h: 4 },
    // The correlations: rules naming a CVE an end is cached as actually
    // vulnerable to (needs schema version 16, the suricata cves column), and
    // flows hitting a port Shodan confirms open at that end. Both ends of
    // each, since src and dest are the triggering packet's direction rather
    // than attacker and victim. 'Matched' is the loudest thing the
    // enrichment can say; the same comparisons badge the search rows.
    { type: 'top',        config: { column: 'shodan_dest_cve_match', style: 'pie' },  x: 0, y: 22, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_dest_port_match', style: 'pie' }, x: 4, y: 22, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_cve_match', style: 'pie' },   x: 8, y: 22, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_port_match', style: 'pie' },  x: 0, y: 26, w: 4, h: 4 },
    { type: 'timeseries', config: { group_by: 'shodan_dest_cve_match' },              x: 4, y: 26, w: 8, h: 4 },
    // the coverage stat over time: has the cache timer been keeping up
    { type: 'timeseries', config: { metric: 'shodan_src_coverage' },                  x: 0, y: 30, w: 12, h: 4 }
  ] },
  // Shodan × Baphomet -- the judgments cut by what Shodan knows about the
  // judged host. The score panels are the point: does Baphomet's own scoring
  // agree with Shodan's view of the host, per tag and per CVSS band? Judged
  // offenders are the src side, which is why there is no dest band here.
  { key: 'shodan_baphomet', label: 'Shodan × Baphomet', table: 'baphomet', widgets: [
    { type: 'stat', config: { metric: 'shodan_src_coverage' },                                   x: 0, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { metric: 'shodan_src_staleness' },                                  x: 3, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { metric: 'total', label: 'Judgments' },                             x: 6, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Judged addresses' }, x: 9, y: 0, w: 3, h: 1 },
    // the scoring cross-check: average judgment score per Shodan tag and per
    // CVSS band, with plain counts per tag beside them for scale
    { type: 'top',        config: { column: 'shodan_src_tag',  measure: 'avg_score' },               x: 0, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_cvss', measure: 'avg_score', style: 'pie' }, x: 4, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_tag' },                                      x: 8, y: 1, w: 4, h: 4 },
    { type: 'timeseries', config: { group_by: 'shodan_src_known' },                                  x: 0, y: 5, w: 8, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_known', style: 'pie' },                      x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_vuln' },                                     x: 0, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip', measure: 'max_score' },                        x: 4, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'shodan_src_cpe' },                                      x: 8, y: 9, w: 4, h: 4 },
    { type: 'timeseries', config: { metric: 'shodan_src_coverage' },                                 x: 0, y: 13, w: 12, h: 4 }
  ] },
  // Syslog (Allani log store).
  { key: 'syslog', label: 'Syslog', widgets: [
    { type: 'stat', config: { table: 'syslog', metric: 'total' },                                       x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'syslog', metric: 'distinct', column: 'host', label: 'Unique hosts' },       x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'syslog', metric: 'distinct', column: 'program', label: 'Unique programs' }, x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'syslog', metric: 'busiest', column: 'host', label: 'Busiest host' },        x: 6, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { table: 'syslog', metric: 'busiest', column: 'program', label: 'Busiest program' },  x: 9, y: 0, w: 3, h: 1 },
    { type: 'timeseries', config: { table: 'syslog', group_by: 'priority' },      x: 0, y: 1, w: 8, h: 4 },
    { type: 'top',        config: { table: 'syslog', column: 'priority', style: 'pie' }, x: 8, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { table: 'syslog', column: 'program' },  x: 0, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'syslog', column: 'facility', style: 'pie' }, x: 4, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'syslog', column: 'host' },     x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'syslog', column: 'host_from' },x: 0, y: 9, w: 6, h: 4 },
    { type: 'countries',  config: { table: 'syslog' },                     x: 6, y: 9, w: 6, h: 4 }
  ] },
  // HTTP -- a combined overview covering both access and error logs.
  { key: 'http', label: 'HTTP (access + error)', widgets: [
    { type: 'stat', config: { table: 'http', metric: 'total', label: 'Access rows' },        x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http_error', metric: 'total', label: 'Error rows' },   x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http', metric: 'distinct', column: 'vhost', label: 'Unique vhosts' },      x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http', metric: 'distinct', column: 'client_ip', label: 'Unique clients' }, x: 6, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http_error', metric: 'busiest', column: 'code', label: 'Top error code' }, x: 8, y: 0, w: 4, h: 1 },
    { type: 'timeseries', config: { table: 'http', group_by: 'status' },          x: 0, y: 1, w: 6, h: 4 },
    { type: 'timeseries', config: { table: 'http_error', group_by: 'loglevel' },  x: 6, y: 1, w: 6, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'status', style: 'pie' },   x: 0, y: 5, w: 3, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'vhost' },                  x: 3, y: 5, w: 5, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'loglevel', style: 'pie' }, x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'method', style: 'pie' },   x: 0, y: 9, w: 3, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'code', style: 'pie' }, x: 3, y: 9, w: 3, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'vhost', measure: 'bytes' },x: 6, y: 9, w: 6, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'client_ip' },              x: 0, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'client_ip' },        x: 4, y: 13, w: 4, h: 4 },
    { type: 'countries',  config: { table: 'http' },                                   x: 8, y: 13, w: 4, h: 4 },
    { type: 'timeseries', config: { table: 'http', measure: 'bytes' },                 x: 0, y: 17, w: 12, h: 4 }
  ] },
  // HTTP Access -- the access log on its own.
  { key: 'http_access', label: 'HTTP Access', widgets: [
    { type: 'stat', config: { table: 'http', metric: 'total' },                                          x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http', metric: 'distinct', column: 'vhost', label: 'Unique vhosts' },       x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http', metric: 'distinct', column: 'client_ip', label: 'Unique clients' },  x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http', metric: 'busiest', column: 'vhost', label: 'Busiest vhost' },        x: 6, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { table: 'http', metric: 'busiest', column: 'status', label: 'Top status' },          x: 9, y: 0, w: 3, h: 1 },
    { type: 'timeseries', config: { table: 'http', group_by: 'status' },        x: 0, y: 1, w: 8, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'status', style: 'pie' }, x: 8, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'vhost' },  x: 0, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'method', style: 'pie' }, x: 4, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'host' },   x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'vhost', measure: 'bytes' }, x: 0, y: 9, w: 6, h: 4 },
    { type: 'top',        config: { table: 'http', column: 'client_ip' }, x: 6, y: 9, w: 3, h: 4 },
    { type: 'countries',  config: { table: 'http' },                      x: 9, y: 9, w: 3, h: 4 },
    { type: 'timeseries', config: { table: 'http', measure: 'bytes' },    x: 0, y: 13, w: 12, h: 4 }
  ] },
  // HTTP Error -- the error log on its own.
  { key: 'http_error', label: 'HTTP Error', widgets: [
    { type: 'stat', config: { table: 'http_error', metric: 'total' },                                            x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http_error', metric: 'distinct', column: 'client_ip', label: 'Unique clients' }, x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http_error', metric: 'distinct', column: 'server', label: 'Unique servers' },    x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { table: 'http_error', metric: 'busiest', column: 'loglevel', label: 'Top level' },        x: 6, y: 0, w: 3, h: 1 },
    { type: 'stat', config: { table: 'http_error', metric: 'busiest', column: 'code', label: 'Top code' },             x: 9, y: 0, w: 3, h: 1 },
    { type: 'timeseries', config: { table: 'http_error', group_by: 'loglevel' },     x: 0, y: 1, w: 8, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'loglevel', style: 'pie' }, x: 8, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'server' }, x: 0, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'code', style: 'pie' }, x: 4, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'host' },   x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { table: 'http_error', column: 'client_ip' }, x: 0, y: 9, w: 6, h: 4 },
    { type: 'countries',  config: { table: 'http_error' },                      x: 6, y: 9, w: 6, h: 4 }
  ] }
];

  window.LilithDashboardPresets = PRESETS;
})();
