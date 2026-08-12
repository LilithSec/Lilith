/*
 * The /dashboard page: the widget grid, its chart renderers, the widget config
 * modal, and the board (saved dashboard) management.
 *
 * Widgets are laid out with Gridstack and drawn with Chart.js, both vendored.
 * A board's widget layout and its view state (table, window, GPCD, bucket) are
 * saved together, so switching boards restores that board's whole view. The
 * grid is locked outside edit mode, so a change event is either a programmatic
 * rebuild or nothing at all -- only edit mode persists.
 *
 * A widget reads either an alert table (/api/dashboard/*) or an Allani log
 * source (/api/logs/*); apiBase picks between them.
 *
 * The page publishes window.LilithDashboard.{table,minutes,showGpcd}, the view
 * to open with. The presets the Reset menu offers come from
 * window.LilithDashboardPresets (/js/dashboard-presets.js).
 *
 * Requires lilith-util.js, time-range.js, Chart.js and gridstack.
 */
(function() {
  Chart.defaults.color = '#adb5bd';
  Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';
  Chart.defaults.font.size = 11;

  var GROUP_COL = { suricata: 'classification', sagan: 'classification', cape: 'target', baphomet: 'event_type' };
  // Allani log sources a widget may target alongside the alert tables; such a
  // widget fetches from /api/logs/* (source=) instead of /api/dashboard/* (table=).
  var LOG_SOURCES = { syslog: 1, http: 1, http_error: 1 };
  function isLogSource(source) { return !!LOG_SOURCES[source]; }
  function apiBase(source) { return isLogSource(source) ? '/api/logs' : '/api/dashboard'; }
  var PALETTE = ['#dc3545','#0d6efd','#fd7e14','#20c997','#6f42c1','#ffc107','#0dcaf0','#d63384','#198754','#adb5bd'];
  // The Shodan stat metrics and the titles they default to. Each reads as a
  // "percent (of)" string rather than a number, so none of them abbreviates.
  var SHODAN_METRIC = {
    shodan_src_coverage:   'Shodan coverage (sources)',
    shodan_src_staleness:  'Shodan staleness (sources)',
    shodan_dest_coverage:  'Shodan coverage (destinations)',
    shodan_dest_staleness: 'Shodan staleness (destinations)'
  };

  // Built-in dashboard presets the Reset menu offers. Each is a list of ordinary
  // widgets, so anything seeded can still be reconfigured, moved, or removed. An
  // alert preset sets the board's Default table; a log preset pins each widget's
  // own Allani source, so it reads that log regardless of the Default table. A
  // panel whose column does not exist for its table just notes so.
  var PRESETS = window.LilithDashboardPresets || [];
  var PRESET = {}; PRESETS.forEach(function(preset) { PRESET[preset.key] = preset; });

  var boot    = window.LilithDashboard || {};
  var state   = {
    board:  'default',
    table:  boot.table || 'suricata',
    mins:   boot.minutes || 1440,
    start:  '',
    end:    '',
    showGpcd: !!boot.showGpcd,
    bucket: 'auto'
  };
  var widgets = [];      // [{ id, type, config, x, y, w, h }]
  var charts  = {};      // widget id -> Chart
  // per-source option lists for the widget picker, fetched from the server
  var metaCache = { columns: {}, measures: {} };  // kind -> source -> list
  var suppressSave = false;
  var editing = false;   // edit mode: only then can widgets move/add/remove and only then does a change persist

  function uid() { return 'w' + Math.random().toString(36).slice(2, 9); }

  // shared helpers (see /js/lilith-util.js)
  var util    = window.LilithUtil;
  var fmtNum  = util.fmtNum;
  var findById = util.findById;
  var flag    = util.flagFor;
  var pad     = util.pad2;
  var getJSON = util.getJSON;
  var postJSON = util.postJSON;

  function baseOpts(extra) {
    var options = { responsive: true, maintainAspectRatio: false, animation: false };
    for (var key in (extra || {})) { options[key] = extra[key]; }
    return options;
  }
  function resizeAllCharts() { Object.keys(charts).forEach(function(id) { if (charts[id]) { charts[id].resize(); } }); }
  function destroyChart(id) { if (charts[id]) { charts[id].destroy(); delete charts[id]; } }

  function bucketLabel(epoch, unit) {
    var date = new Date(epoch * 1000);
    var hourMin = pad(date.getHours()) + ':' + pad(date.getMinutes());
    var monthDay = pad(date.getMonth() + 1) + '-' + pad(date.getDate());
    if (unit === 'month') { return date.getFullYear() + '-' + pad(date.getMonth() + 1); }
    if (unit === 'week' || unit === 'day') { return monthDay; }
    // minute / hour: prepend the date when the window spans more than a day
    return state.mins <= 1440 ? hourMin : (monthDay + ' ' + hourMin);
  }
  // 'auto' sizes the bucket to the window, matching the log reader's thresholds
  // (minute <=3h, hour <=2d, day <=90d, week <=~2y, else month).
  function bucketUnit() {
    var mins = state.mins;
    if (state.start && state.end) {
      var span = (new Date(state.end.replace(' ', 'T')) - new Date(state.start.replace(' ', 'T'))) / 60000;
      if (span > 0) { mins = span; }
    }
    if (mins <= 180)     { return 'minute'; }
    if (mins <= 2880)    { return 'hour'; }
    if (mins <= 129600)  { return 'day'; }
    if (mins <= 1051200) { return 'week'; }
    return 'month';
  }
  // A widget's own bucket wins, else the board bucket, else auto; 'auto' resolves
  // to a concrete unit here so the API never has to.
  function resolveBucket(widget) {
    var bucket = (widget && widget.config && widget.config.bucket) || state.bucket || 'auto';
    return (bucket === 'auto') ? bucketUnit() : bucket;
  }

  function qsFor(source, extra) {
    var log = isLogSource(source);
    var query = '?' + (log ? 'source' : 'table') + '=' + encodeURIComponent(source) + '&go_back_minutes=' + encodeURIComponent(state.mins);
    if (!log && state.showGpcd) { query += '&show_gpcd=1'; }   // GPCD exclude is alert-only
    if (state.start) { query += '&start=' + encodeURIComponent(state.start); }
    if (state.end)   { query += '&end=' + encodeURIComponent(state.end); }
    for (var key in (extra || {})) { if (extra[key] !== undefined && extra[key] !== '') { query += '&' + key + '=' + encodeURIComponent(extra[key]); } }
    return query;
  }
  function showError(msg) { var element = document.getElementById('db-error'); element.textContent = 'Error: ' + msg; element.style.display = ''; }
  function clearError() { document.getElementById('db-error').style.display = 'none'; }

  // ---- widget DOM ----
  function measureLabel(table, name) {
    if (!name || name === 'count') { return ''; }
    var measures = metaCache.measures[table] || [];
    for (var i = 0; i < measures.length; i++) { if (measures[i].name === name) { return measures[i].label; } }
    return name.replace(/_/g, ' ');
  }
  function widgetTitle(widget) {
    var widgetTable = widget.config.table || state.table;
    var measure = measureLabel(widgetTable, widget.config.measure);
    // note the table only when the widget pins one different from the board's
    var suffix = widget.config.table ? (' · ' + widgetTable) : '';
    if (widget.type === 'timeseries') {
      return (measure || 'Alerts') + ' over time' + (widget.config.group_by ? ' (by ' + widget.config.group_by + ')' : '') + suffix;
    }
    if (widget.type === 'top')       { return 'Top ' + (widget.config.column || '') + (measure ? ' by ' + measure : '') + suffix; }
    if (widget.type === 'countries') { return 'Source countries' + suffix; }
    if (widget.type === 'stat') {
      if (widget.config.label) { return widget.config.label; }
      var metric = widget.config.metric || 'total';
      var shodanMetric = SHODAN_METRIC[metric];
      var label = metric === 'distinct'  ? ('Unique ' + (widget.config.column || '')) :
                metric === 'escalated' ? 'Escalated' :
                metric === 'busiest'   ? ('Busiest ' + (widget.config.column || '')) :
                shodanMetric ? shodanMetric :
                (isLogSource(widgetTable) ? 'Total rows' : 'Total alerts');
      return label + suffix;
    }
    return 'Widget';
  }
  function widgetEl(widget) {
    var element = document.createElement('div');
    element.className = 'grid-stack-item';
    element.setAttribute('gs-id', widget.id);
    element.setAttribute('gs-x', widget.x); element.setAttribute('gs-y', widget.y);
    element.setAttribute('gs-w', widget.w); element.setAttribute('gs-h', widget.h);
    var isStat = widget.type === 'stat';
    element.innerHTML =
      '<div class="grid-stack-item-content">'
      + '<div class="card border-secondary h-100 mb-0 db-card' + (isStat ? ' db-stat' : '') + '"><div class="card-body p-2 d-flex flex-column">'
      +   '<div class="d-flex align-items-center' + (isStat ? '' : ' mb-1') + '">'
      +     '<h6 class="card-title db-handle mb-0 flex-grow-1 text-truncate" data-role="title"></h6>'
      +     '<a href="#" class="db-wbtn db-edit-only text-secondary ms-2" data-act="config" title="Configure">&#9881;</a>'
      +     '<a href="#" class="db-wbtn db-edit-only text-secondary ms-2" data-act="remove" title="Remove">&times;</a>'
      +   '</div>'
      +   '<div class="text-muted small" data-role="note" style="display:none"></div>'
      +   (isStat
            ? '<div class="flex-grow-1 d-flex align-items-center"><div class="fw-bold text-truncate" data-role="stat-value">&ndash;</div></div>'
            : '<div class="db-chart"><canvas data-role="canvas"></canvas></div>')
      + '</div></div>'
      + '</div>';
    element.querySelector('[data-role=title]').textContent = widgetTitle(widget);
    var canvas = element.querySelector('canvas'); if (canvas) { canvas.id = 'chart-' + widget.id; }
    return element;
  }
  function itemFor(id) { return document.querySelector('.grid-stack-item[gs-id="' + id + '"]'); }
  function showNote(widget, msg) {
    var item = itemFor(widget.id); if (!item) { return; }
    item.querySelector('[data-role=note]').textContent = msg;
    item.querySelector('[data-role=note]').style.display = '';
    var body = item.querySelector('canvas') || item.querySelector('[data-role=stat-value]');
    if (body) { body.style.display = 'none'; }
    destroyChart(widget.id);
  }
  function clearNote(widget) {
    var item = itemFor(widget.id); if (!item) { return; }
    item.querySelector('[data-role=note]').style.display = 'none';
    var body = item.querySelector('canvas') || item.querySelector('[data-role=stat-value]');
    if (body) { body.style.display = ''; }
  }

  // ---- chart renderers ----
  function renderTop(widget, canvas, rows) {
    destroyChart(widget.id);
    var labels = rows.map(function(row) { return row.value; });
    var counts = rows.map(function(row) { return row.count; });
    if ((widget.config && widget.config.style) === 'pie') {
      charts[widget.id] = new Chart(canvas, {
        type: 'pie',
        data: { labels: labels,
                datasets: [{ data: counts, backgroundColor: rows.map(function(_, index) { return PALETTE[index % PALETTE.length]; }) }] },
        options: baseOpts({ plugins: { legend: { display: true, position: 'right' } } })
      });
    } else {
      charts[widget.id] = new Chart(canvas, {
        type: 'bar',
        data: { labels: labels, datasets: [{ data: counts, backgroundColor: PALETTE[0] }] },
        options: baseOpts({
          indexAxis: 'y',
          scales: { x: { beginAtZero: true, ticks: { callback: fmtNum } } },
          plugins: { legend: { display: false } }
        })
      });
    }
  }
  function renderTimeseries(widget, canvas, data, unit) {
    var id = widget.id;
    destroyChart(id);
    var rows = data.rows || [], bucketSet = {}, groupSet = {};
    rows.forEach(function(row) { bucketSet[row.bucket] = 1; if (row.group !== undefined) { groupSet[row.group] = 1; } });
    var buckets = Object.keys(bucketSet).map(Number).sort(function(a, b) { return a - b; });
    var bucketIndex = {}; buckets.forEach(function(bucket, index) { bucketIndex[bucket] = index; });
    var groups = Object.keys(groupSet), datasets;
    if (data.grouped && groups.length) {
      datasets = groups.map(function(group, index) {
        var seriesData = buckets.map(function() { return 0; });
        rows.forEach(function(row) { if (row.group === group) { seriesData[bucketIndex[row.bucket]] = row.count; } });
        var color = PALETTE[index % PALETTE.length];
        return { label: group, data: seriesData, backgroundColor: color, borderColor: color, stack: 's' };
      });
    } else {
      var seriesData = buckets.map(function() { return 0; });
      rows.forEach(function(row) { seriesData[bucketIndex[row.bucket]] = row.count; });
      datasets = [{ label: 'alerts', data: seriesData, backgroundColor: PALETTE[1], borderColor: PALETTE[1] }];
    }
    charts[id] = new Chart(canvas, {
      type: 'bar', data: { labels: buckets.map(function(bucket) { return bucketLabel(bucket, unit); }), datasets: datasets },
      options: baseOpts({
        interaction: { mode: 'index', intersect: false },
        scales: { x: { stacked: true, ticks: { maxRotation: 0, autoSkip: true } },
                  y: { stacked: true, beginAtZero: true, ticks: { callback: fmtNum } } },
        plugins: { legend: { display: datasets.length > 1, position: 'bottom' } }
      })
    });
  }
  function renderCountries(widget, canvas, data) {
    if (!data.enabled) { showNote(widget, 'GeoIP is not configured on this server.'); return; }
    clearNote(widget);
    destroyChart(widget.id);
    var rows = data.rows || [];
    charts[widget.id] = new Chart(canvas, {
      type: 'bar',
      data: { labels: rows.map(function(row) { return (flag(row.country) + ' ' + row.country).trim(); }),
              datasets: [{ data: rows.map(function(row) { return row.count; }), backgroundColor: PALETTE[3] }] },
      options: baseOpts({ indexAxis: 'y', scales: { x: { beginAtZero: true } }, plugins: { legend: { display: false } } })
    });
  }

  // ---- data loading ----
  function loadStat(widget, base, widgetTable) {
    var item = itemFor(widget.id); if (!item) { return; }
    var valueEl = item.querySelector('[data-role=stat-value]'); if (!valueEl) { return; }
    getJSON(base + '/stat' + qsFor(widgetTable, { metric: widget.config.metric, column: widget.config.column }))
      .then(function(data) {
        clearNote(widget);
        var value = data.value;
        var formatted = (typeof value === 'number')
          ? (widget.config.abbrev ? fmtNum(value) : value.toLocaleString())
          : String(value);
        valueEl.textContent = (value === undefined || value === null) ? '–' : formatted;
        valueEl.title = valueEl.textContent;
      })
      .catch(function(error) { showNote(widget, error.message); });
  }
  function loadWidget(widget) {
    var widgetTable = widget.config.table || state.table;
    var base = apiBase(widgetTable);
    if (widget.type === 'stat') { return loadStat(widget, base, widgetTable); }
    var canvas = document.getElementById('chart-' + widget.id);
    if (!canvas) { return; }
    if (widget.type === 'top') {
      getJSON(base + '/top' + qsFor(widgetTable, { column: widget.config.column, limit: widget.config.limit || 10, measure: widget.config.measure }))
        .then(function(data) { clearNote(widget); renderTop(widget, canvas, data.rows || []); })
        .catch(function(error) { showNote(widget, error.message); });
    } else if (widget.type === 'timeseries') {
      var unit = resolveBucket(widget);
      getJSON(base + '/timeseries' + qsFor(widgetTable, { bucket: unit, group_by: widget.config.group_by, top_groups: 6, measure: widget.config.measure }))
        .then(function(data) {
          // log timeseries buckets are ISO strings; the renderer wants epoch seconds
          if (isLogSource(widgetTable)) { (data.rows || []).forEach(function(row) { row.bucket = Math.floor(new Date(row.bucket).getTime() / 1000); }); }
          clearNote(widget); renderTimeseries(widget, canvas, data, unit);
        })
        .catch(function(error) { showNote(widget, error.message); });
    } else if (widget.type === 'countries') {
      getJSON(base + '/countries' + qsFor(widgetTable))
        .then(function(data) { renderCountries(widget, canvas, data); })
        .catch(function(error) { showNote(widget, error.message); });
    }
  }
  function refresh() {
    clearError();
    widgets.forEach(loadWidget);
  }

  // ---- Gridstack ----
  var grid = GridStack.init({ column: 12, cellHeight: 70, margin: 6, float: false,
                              handle: '.db-handle', resizable: { handles: 'se' } });

  function rebuildGrid() {
    suppressSave = true;
    Object.keys(charts).forEach(destroyChart);
    grid.removeAll();
    widgets.forEach(function(widget) { var element = widgetEl(widget); grid.el.appendChild(element); grid.makeWidget(element); });
    setTimeout(function() { suppressSave = false; }, 0);
  }
  function currentLayout() {
    return (grid.save(false) || []).map(function(node) {
      var widget = findById(widgets, node.id) || {};
      return { id: node.id, type: widget.type, config: widget.config || {}, x: node.x, y: node.y, w: node.w, h: node.h };
    }).filter(function(node) { return node.type; });
  }
  // The board's view state travels with its layout, so switching to a board
  // restores its own table / time range / GPCD setting.
  function currentSettings() { return { table: state.table, go_back_minutes: state.mins, show_gpcd: state.showGpcd ? 1 : 0, bucket: state.bucket }; }
  function postLayout(layout) {
    return fetch('/api/dashboard/layout', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ name: state.board, layout: layout, settings: currentSettings() }) });
  }
  var saveTimer;
  function saveLayout() {
    var layout = currentLayout();
    widgets = layout.map(function(node) { return { id: node.id, type: node.type, config: node.config, x: node.x, y: node.y, w: node.w, h: node.h }; });
    postLayout(layout).catch(function() {});
  }
  // Only persist while editing: out of edit mode the grid is locked, so a change
  // event is either a programmatic rebuild (suppressSave) or nothing at all.
  grid.on('change', function() { if (suppressSave || !editing) { return; } clearTimeout(saveTimer); saveTimer = setTimeout(saveLayout, 800); });
  grid.on('resize', resizeAllCharts);
  grid.on('resizestop', resizeAllCharts);

  // Enter/leave edit mode: unlock the grid, reveal the edit-only controls (via
  // the body class the CSS keys off), and relabel the toggle.
  function setEditing(on) {
    editing = !!on;
    document.body.classList.toggle('db-editing', editing);
    grid.setStatic(!editing);
    var button = document.getElementById('db-edit');
    button.classList.toggle('active', editing);
    button.textContent = editing ? 'Done' : 'Edit';
  }

  // config / remove buttons (event-delegated on the grid). The buttons are
  // hidden outside edit mode, but guard anyway.
  grid.el.addEventListener('click', function(event) {
    var button = event.target.closest('[data-act]'); if (!button) { return; }
    event.preventDefault();
    if (!editing) { return; }
    var item = button.closest('.grid-stack-item'); var id = item && item.getAttribute('gs-id'); if (!id) { return; }
    if (button.getAttribute('data-act') === 'remove') {
      destroyChart(id); grid.removeWidget(item);
      widgets = widgets.filter(function(candidate) { return candidate.id !== id; });
      saveLayout();
    } else {
      openModal(id);
    }
  });

  // ---- widget config modal ----
  var modal, editingId = null;
  function getModal() { modal = modal || new bootstrap.Modal(document.getElementById('widget-modal')); return modal; }
  // One option list for a source: its aggregatable columns or its measures.
  // Both endpoints answer the same shape and are keyed the same way, so they
  // share a fetch. Cached per source, since a picker reopens far more often
  // than the lists change.
  //
  // kind is 'columns' or 'measures', which is both the endpoint suffix and the
  // key the response carries the list under.
  function loadMeta(kind, source) {
    var cache = metaCache[kind];
    if (cache[source]) { return Promise.resolve(cache[source]); }
    var key = isLogSource(source) ? 'source' : 'table';
    return getJSON(apiBase(source) + '/' + kind + '?' + key + '=' + encodeURIComponent(source)).then(function(data) {
      cache[source] = data[kind] || []; return cache[source];
    });
  }
  function syncModalFields() {
    var type = document.getElementById('wm-type').value;
    var metric = document.getElementById('wm-metric').value;
    var isStat = (type === 'stat');
    var statNeedsColumn = isStat && (metric === 'distinct' || metric === 'busiest');
    document.getElementById('wm-metric-wrap').style.display = isStat ? '' : 'none';
    document.getElementById('wm-label-wrap').style.display  = isStat ? '' : 'none';
    // abbreviation only applies to numeric metrics; busiest is a "value (count)"
    // string and the Shodan ones "percent (of)" ones
    var isTextMetric = (metric === 'busiest' || !!SHODAN_METRIC[metric]);
    document.getElementById('wm-abbrev-wrap').style.display = (isStat && !isTextMetric) ? '' : 'none';
    document.getElementById('wm-column-wrap').style.display = (type === 'top' || statNeedsColumn) ? '' : 'none';
    document.getElementById('wm-style-wrap').style.display   = (type === 'top') ? '' : 'none';
    document.getElementById('wm-limit-wrap').style.display   = (type === 'top') ? '' : 'none';
    document.getElementById('wm-group-wrap').style.display   = (type === 'timeseries') ? '' : 'none';
    document.getElementById('wm-bucket-wrap').style.display  = (type === 'timeseries') ? '' : 'none';
    document.getElementById('wm-measure-wrap').style.display = (type === 'top' || type === 'timeseries') ? '' : 'none';
  }
  // Fill the column/group/measure pickers from $table's columns/measures. With a
  // widget, its saved selections are restored; without one (e.g. after the Table
  // picker changes) they reset to that table's defaults.
  function populateFields(table, widget) {
    return Promise.all([loadMeta('columns', table), loadMeta('measures', table)]).then(function(results) {
      var columns = results[0], measures = results[1];
      var columnSelect = document.getElementById('wm-column'), groupSelect = document.getElementById('wm-group');
      var measureSelect = document.getElementById('wm-measure');
      columnSelect.innerHTML = ''; groupSelect.innerHTML = '<option value="">(none)</option>'; measureSelect.innerHTML = '';
      columns.forEach(function(column) {
        var columnOption = document.createElement('option'); columnOption.value = column; columnOption.textContent = column; columnSelect.appendChild(columnOption);
        var groupOption = document.createElement('option'); groupOption.value = column; groupOption.textContent = column; groupSelect.appendChild(groupOption);
      });
      measures.forEach(function(measure) {
        var option = document.createElement('option'); option.value = measure.name; option.textContent = measure.label; measureSelect.appendChild(option);
      });
      if (widget && (widget.type === 'top' || widget.type === 'stat')) { columnSelect.value = widget.config.column || ''; }
      if (widget && widget.type === 'timeseries') { groupSelect.value = widget.config.group_by || ''; }
      document.getElementById('wm-style').value = (widget && widget.config.style) ? widget.config.style : 'bar';
      document.getElementById('wm-limit').value = (widget && widget.config.limit) ? widget.config.limit : 10;
      measureSelect.value = (widget && widget.config.measure) ? widget.config.measure : 'count';
    });
  }
  function openModal(id) {
    editingId = id || null;
    var widget = id ? findById(widgets, id) : null;
    document.getElementById('widget-modal-title').textContent = id ? 'Configure widget' : 'Add widget';
    // '' = follow the board default (unpinned); a concrete table pins the widget
    var pinned = (widget && widget.config.table) || '';
    document.getElementById('wm-table').value = pinned;
    document.getElementById('wm-type').value = widget ? widget.type : 'timeseries';
    document.getElementById('wm-metric').value = (widget && widget.config.metric) ? widget.config.metric : 'total';
    document.getElementById('wm-label').value = (widget && widget.config.label) ? widget.config.label : '';
    document.getElementById('wm-abbrev').checked = !!(widget && widget.config.abbrev);
    document.getElementById('wm-bucket').value = (widget && widget.config.bucket) ? widget.config.bucket : '';
    populateFields(pinned || state.table, widget).catch(function() {}).then(function() { syncModalFields(); getModal().show(); });
  }
  document.getElementById('wm-type').addEventListener('change', syncModalFields);
  document.getElementById('wm-metric').addEventListener('change', syncModalFields);
  // Changing the widget's table re-loads its columns/measures (using the board
  // default when set to Follow) and resets column/group/measure to that table's.
  document.getElementById('wm-table').addEventListener('change', function() { populateFields(this.value || state.table, null); });
  document.getElementById('wm-save').addEventListener('click', function() {
    var type = document.getElementById('wm-type').value, config = {};
    var measure = document.getElementById('wm-measure').value;
    if (type === 'top') {
      config.column = document.getElementById('wm-column').value;
      config.style = document.getElementById('wm-style').value;
      var limit = parseInt(document.getElementById('wm-limit').value, 10);
      if (isNaN(limit) || limit < 1) { limit = 1; }
      if (limit > 50) { limit = 50; }
      config.limit = limit;
    }
    if (type === 'timeseries') {
      var group = document.getElementById('wm-group').value; if (group) { config.group_by = group; }
      var bucket = document.getElementById('wm-bucket').value; if (bucket) { config.bucket = bucket; }
    }
    if ((type === 'top' || type === 'timeseries') && measure && measure !== 'count') { config.measure = measure; }
    if (type === 'stat') {
      var metric = document.getElementById('wm-metric').value;
      config.metric = metric;
      if (metric === 'distinct' || metric === 'busiest') { config.column = document.getElementById('wm-column').value; }
      var label = document.getElementById('wm-label').value.trim();
      if (label) { config.label = label; }
      if (metric !== 'busiest' && !SHODAN_METRIC[metric]
          && document.getElementById('wm-abbrev').checked) { config.abbrev = 1; }
    }
    // a concrete table pins the widget (even if it equals the current default);
    // the empty "Follow default table" option leaves it following the board
    var widgetTable = document.getElementById('wm-table').value;
    if (widgetTable) { config.table = widgetTable; }
    if (editingId) {
      var widget = findById(widgets, editingId);
      if (widget) { widget.type = type; widget.config = config; }
    } else {
      widgets.push({ id: uid(), type: type, config: config, x: 0, y: 1000, w: 4, h: 4 });
    }
    getModal().hide();
    rebuildGrid();
    refresh();
    setTimeout(saveLayout, 50);
  });

  // ---- controls ----
  // The shared time-range control: read its window into state on any change. An
  // absolute range is transient -- it drives the view but is not saved with the
  // board (currentSettings persists only the relative go_back_minutes).
  var trRoot = document.querySelector('.time-range');
  function readTimeRange() {
    var range = window.LilithTimeRange && window.LilithTimeRange.read(trRoot);
    if (!range) { return; }
    if (range.start || range.end) { state.start = range.start; state.end = range.end; }
    else { state.mins = Number(range.go_back_minutes) || state.mins; state.start = ''; state.end = ''; }
  }
  // A view control changed: always re-pull; when editing, persist it to the board.
  function viewChanged() { refresh(); if (editing) { clearTimeout(saveTimer); saveTimer = setTimeout(saveLayout, 400); } }
  document.getElementById('db-table').addEventListener('change', function() { state.table = this.value; viewChanged(); });
  if (trRoot) { trRoot.addEventListener('timerange:change', function() { readTimeRange(); viewChanged(); }); }
  document.getElementById('db-gpcd').addEventListener('change', function() { state.showGpcd = this.checked; viewChanged(); });
  document.getElementById('db-bucket').addEventListener('change', function() { state.bucket = this.value; viewChanged(); });
  document.getElementById('db-refresh').addEventListener('click', refresh);
  document.getElementById('db-add-widget').addEventListener('click', function() { openModal(null); });
  // Reset menu: replace the board with a named preset. An alert preset also sets
  // the board's Default table; a log preset leaves it (its widgets pin a source).
  Array.prototype.forEach.call(document.querySelectorAll('[data-preset]'), function(element) {
    element.addEventListener('click', function(event) {
      event.preventDefault();
      var preset = PRESET[this.getAttribute('data-preset')]; if (!preset) { return; }
      if (!window.confirm("Replace this dashboard's widgets with the " + preset.label + " preset?")) { return; }
      widgets = seedPreset(preset.key); rebuildGrid(); refresh(); setTimeout(saveLayout, 50);
    });
  });
  document.getElementById('db-edit').addEventListener('click', function() { setEditing(!editing); });

  // ---- dashboards (boards) ----
  function applySettings(settings) {
    settings = settings || {};
    if (settings.table && /^(?:suricata|sagan|cape|baphomet|syslog|http|http_error)$/.test(settings.table)) { state.table = settings.table; }
    if (settings.go_back_minutes) { state.mins = Number(settings.go_back_minutes); }
    if (settings.show_gpcd !== undefined) { state.showGpcd = !!settings.show_gpcd; }
    state.bucket = (settings.bucket && /^(?:auto|minute|hour|day|week|month)$/.test(settings.bucket)) ? settings.bucket : 'auto';
    state.start = ''; state.end = '';
    document.getElementById('db-table').value = state.table;
    document.getElementById('db-gpcd').checked = state.showGpcd;
    document.getElementById('db-bucket').value = state.bucket;
    if (window.LilithTimeRange) { window.LilithTimeRange.set(trRoot, { go_back_minutes: state.mins }); }
  }
  // (Re)load the board list into the picker; select `want` (or the default).
  function loadBoards(want) {
    return getJSON('/api/dashboard/boards').then(function(data) {
      var boards = data.boards || [];
      var select = document.getElementById('db-board');
      select.innerHTML = '';
      boards.forEach(function(board) {
        var option = document.createElement('option');
        option.value = board.name;
        option.textContent = board.name + (board.is_default ? ' ★' : '');
        select.appendChild(option);
      });
      var target = want || data.default || (boards[0] && boards[0].name) || 'default';
      select.value = target; state.board = target;
      return target;
    });
  }
  // Load one board: apply its saved view state, then its widgets. An unsaved
  // default board seeds the built-in set; other empty boards start blank.
  function loadBoard(name) {
    return getJSON('/api/dashboard/layout?name=' + encodeURIComponent(name)).then(function(data) {
      state.board = data.name || name;
      applySettings(data.settings);
      var layout = (data && Array.isArray(data.layout)) ? data.layout.filter(function(widget) { return widget && widget.type; }) : [];
      widgets = layout.length
        ? layout.map(function(widget) { return { id: widget.id || uid(), type: widget.type, config: widget.config || {}, x: widget.x || 0, y: widget.y || 0, w: widget.w || 4, h: widget.h || 4 }; })
        : (data.is_default ? seedWidgets(PRESET.suricata.widgets) : []);
      rebuildGrid(); refresh();
    });
  }
  document.getElementById('db-board').addEventListener('change', function() {
    if (editing) { setEditing(false); }
    clearError();
    loadBoard(this.value).catch(function(error) { showError(error.message); });
  });

  // New and Rename share one modal.
  var boardModal, boardModalMode = 'new';
  function getBoardModal() { boardModal = boardModal || new bootstrap.Modal(document.getElementById('board-modal')); return boardModal; }
  function openBoardModal(mode) {
    boardModalMode = mode;
    document.getElementById('board-modal-title').textContent = (mode === 'rename') ? 'Rename dashboard' : 'New dashboard';
    var input = document.getElementById('board-name');
    input.value = (mode === 'rename') ? state.board : '';
    document.getElementById('board-modal-error').style.display = 'none';
    getBoardModal().show();
  }
  document.getElementById('db-new').addEventListener('click', function(event) { event.preventDefault(); openBoardModal('new'); });
  document.getElementById('db-rename').addEventListener('click', function(event) { event.preventDefault(); openBoardModal('rename'); });
  document.getElementById('board-modal-save').addEventListener('click', function() {
    var name = document.getElementById('board-name').value.trim();
    var errorEl = document.getElementById('board-modal-error');
    if (!name) { errorEl.textContent = 'A name is required.'; errorEl.style.display = ''; return; }
    var request = (boardModalMode === 'rename')
      ? postJSON('/api/dashboard/rename', { name: state.board, to: name })
      : postJSON('/api/dashboard/boards', { name: name });
    request.then(function(data) {
      getBoardModal().hide();
      var newName = data.name || name;
      return loadBoards(newName).then(function() { return loadBoard(newName); });
    }).catch(function(error) { errorEl.textContent = error.message; errorEl.style.display = ''; });
  });
  document.getElementById('db-set-default').addEventListener('click', function(event) {
    event.preventDefault(); clearError();
    postJSON('/api/dashboard/default', { name: state.board })
      .then(function() { return loadBoards(state.board); })
      .catch(function(error) { showError(error.message); });
  });
  document.getElementById('db-delete').addEventListener('click', function(event) {
    event.preventDefault(); clearError();
    if (!window.confirm('Delete dashboard "' + state.board + '"? This cannot be undone.')) { return; }
    postJSON('/api/dashboard/delete', { name: state.board })
      .then(function() { return loadBoards().then(function(name) { return loadBoard(name); }); })
      .catch(function(error) { showError(error.message); });
  });

  // ---- boot ----
  function seedWidgets(list) { return list.map(function(widget) { return { id: uid(), type: widget.type, config: widget.config, x: widget.x, y: widget.y, w: widget.w, h: widget.h }; }); }
  // Seed a named preset; alert presets also point the board's Default table at
  // their table so the widgets that follow it read the right annal.
  function seedPreset(key) {
    var preset = PRESET[key] || PRESET.suricata;
    if (preset.table) { state.table = preset.table; document.getElementById('db-table').value = state.table; }
    return seedWidgets(preset.widgets);
  }
  setEditing(false);
  loadBoards().then(function(name) { return loadBoard(name); }).catch(function() {
    widgets = seedWidgets(PRESET.suricata.widgets); rebuildGrid(); refresh();
  });
})();
