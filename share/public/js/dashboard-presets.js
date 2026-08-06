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
    { type: 'stat', config: { metric: 'total' },                                                     x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique sources' },       x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'signature', label: 'Unique signatures' }, x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'escalated' },                                                 x: 6, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'busiest', column: 'instance', label: 'Busiest sensor' },      x: 8, y: 0, w: 4, h: 1 },
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
    { type: 'stat', config: { metric: 'total', label: 'Total detonations' },              x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique sources' }, x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'target', label: 'Unique targets' }, x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'md5', label: 'Unique samples' },     x: 6, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'busiest', column: 'instance', label: 'Busiest sensor' }, x: 8, y: 0, w: 4, h: 1 },
    { type: 'timeseries', config: {},                             x: 0, y: 1, w: 8, h: 4 },
    { type: 'top',        config: { column: 'malscore', style: 'pie' }, x: 8, y: 1, w: 4, h: 4 },
    { type: 'top',        config: { column: 'target' },       x: 0, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'pkg', style: 'pie' }, x: 4, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'url_hostname' }, x: 8, y: 5, w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip' },       x: 0, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'md5' },          x: 4, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'sha256' },       x: 8, y: 9, w: 4, h: 4 },
    { type: 'top',        config: { column: 'target', measure: 'max_malscore' }, x: 0, y: 13, w: 6, h: 4 },
    { type: 'top',        config: { column: 'instance' },     x: 6, y: 13, w: 3, h: 4 },
    { type: 'countries',  config: {},                         x: 9, y: 13, w: 3, h: 4 },
    { type: 'timeseries', config: { measure: 'sum_size' },    x: 0, y: 17, w: 12, h: 4 }
  ] },
  // Baphomet -- its own judgment log (found/banish/noted/alert/sighting/sighted).
  { key: 'baphomet', label: 'Baphomet (judgments overview)', table: 'baphomet', widgets: [
    { type: 'stat', config: { metric: 'total', label: 'Total judgments' },                       x: 0, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'src_ip', label: 'Unique offenders' }, x: 2, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'distinct', column: 'subject', label: 'Unique subjects' }, x: 4, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'escalated' },                                             x: 6, y: 0, w: 2, h: 1 },
    { type: 'stat', config: { metric: 'busiest', column: 'kur', label: 'Busiest kur' },          x: 8, y: 0, w: 4, h: 1 },
    { type: 'timeseries', config: { group_by: 'event_type' },              x: 0,  y: 1, w: 10, h: 4 },
    { type: 'top',        config: { column: 'event_type', style: 'pie' },  x: 10, y: 1, w: 2,  h: 4 },
    { type: 'top',        config: { column: 'classification' },        x: 0, y: 5,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'signature' },             x: 4, y: 5,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'severity', style: 'pie' },x: 8, y: 5,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip' },                x: 0, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'subject' },               x: 4, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'kur' },                   x: 8, y: 9,  w: 4, h: 4 },
    { type: 'top',        config: { column: 'country', style: 'pie' }, x: 0, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'instance' },              x: 4, y: 13, w: 4, h: 4 },
    { type: 'countries',  config: {},                                  x: 8, y: 13, w: 4, h: 4 },
    { type: 'top',        config: { column: 'src_ip', measure: 'max_score' }, x: 0, y: 17, w: 6, h: 4 },
    { type: 'timeseries', config: { measure: 'avg_score' },                   x: 6, y: 17, w: 6, h: 4 }
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
