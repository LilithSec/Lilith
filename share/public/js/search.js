/*
 * The /search page: the table-dependent parts of the filter form, the view
 * toggles that persist in localStorage, the click-to-filter cells in the
 * results, and the shared auto-refresh.
 *
 * The sortable columns per table are not kept here: the page publishes them as
 * window.LilithSearch.orderByColumns (from the server's order_by_columns
 * helper), so this cannot drift from what Lilith::search accepts.
 * window.LilithSearch.orderBy is the column the current results are sorted by.
 *
 * Requires lilith-util.js, lilith-table.js, and auto-refresh.js.
 */
(function () {
// The sortable columns per table, from the order_by_columns helper, which
// derives them from %Lilith::alert_columns -- so this cannot drift from what
// Lilith::search accepts. Each list leads with that table's default.
var _orderByCols = (window.LilithSearch || {}).orderByColumns || {};

function syncOrderBy(keepVal) {
  var table = document.getElementById('table-sel').value;
  var orderBy = document.getElementById('order-by');
  var prev = keepVal ? orderBy.value : null;
  var cols = _orderByCols[table] || _orderByCols.suricata;
  orderBy.innerHTML = '';
  cols.forEach(function(column) {
    var option = document.createElement('option');
    option.value = column; option.textContent = column;
    orderBy.appendChild(option);
  });
  // Restore previous value if still valid, otherwise use table default
  if (prev && cols.indexOf(prev) !== -1) {
    orderBy.value = prev;
  } else {
    orderBy.value = cols[0];
  }
  var instanceHostField = document.getElementById('instance-host-field');
  instanceHostField.style.display = (table === 'sagan' || table === 'cape') ? '' : 'none';
  var capeFilters = document.getElementById('cape-filters');
  capeFilters.style.display = (table === 'cape') ? '' : 'none';
  var ruleFilters = document.getElementById('rule-filters');
  ruleFilters.style.display = (table === 'cape') ? 'none' : '';
  var classFilter = document.getElementById('class-filter');
  classFilter.style.display = (table === 'cape') ? 'none' : 'flex';
  // Baphomet has no gid/sid/rev and no port columns, so hide those inputs for
  // it. The Signature, Event ID, and classification filters stay, as baphomet
  // does have those columns.
  var missingForBaphomet = ['gid-field', 'sid-field', 'rev-field',
                            'src-port-field', 'dest-port-field', 'port-field'];
  missingForBaphomet.forEach(function(fieldId) {
    var fieldEl = document.getElementById(fieldId);
    if (fieldEl) { fieldEl.style.display = (table === 'baphomet') ? 'none' : ''; }
  });
}
function applyHostCol(show) {
  document.querySelectorAll('.col-host').forEach(function(el) {
    el.style.display = show ? '' : 'none';
  });
}

// Toggle the GeoIP city label shown next to each IP's country flag.
function applyGeoCity(show) {
  document.querySelectorAll('#search-results .geoip-city').forEach(function(el) {
    el.style.display = show ? '' : 'none';
  });
}

// Bind a class of clickable result cells to a filter input + submit.
function bindFilter(selector, inputId, dataKey) {
  document.querySelectorAll(selector).forEach(function(el) {
    el.addEventListener('click', function(event) {
      event.preventDefault();
      document.getElementById(inputId).value = this.dataset[dataKey];
      document.getElementById('search-form').submit();
    });
  });
}

// (Re)wire all handlers and view state inside the results container. Safe to
// call again after the results HTML is swapped in by an auto-refresh.
function initResults() {
  var hostCheckbox = document.getElementById('show-host-col');
  applyHostCol(hostCheckbox && hostCheckbox.checked);

  var cityCheckbox = document.getElementById('show-city');
  applyGeoCity(!cityCheckbox || cityCheckbox.checked);

  bindFilter('.host-filter',          'host-input',          'host');
  bindFilter('.instance-host-filter', 'instance-host-input', 'instanceHost');
  bindFilter('.instance-filter',      'instance-input',      'instance');
  bindFilter('.iface-filter',         'in-iface-input',      'iface');
  bindFilter('.ip-filter',            'ip-input',            'ip');
  bindFilter('.sig-filter',           'signature-input',     'sig');
  bindFilter('.gid-filter',           'gid-input',           'gid');
  bindFilter('.sid-filter',           'sid-input',           'sid');
  bindFilter('.rev-filter',           'rev-input',           'rev');
  bindFilter('.port-filter',          'port-input',          'port');
  bindFilter('.proto-filter',         'proto-input',         'proto');
  bindFilter('.aproto-filter',        'app-proto-input',     'aproto');

  LilithTable.initSort(document.querySelector('#search-results table.table'));

  // The IP info modal + lookup lives in the layout; just wire the buttons.
  document.querySelectorAll('#search-results .ip-info-btn').forEach(function(el) {
    el.addEventListener('click', function() { window.showIpInfo(this.dataset.ip); });
  });
}

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('table-sel').addEventListener('change', function() { syncOrderBy(false); });
  syncOrderBy(false);
  var wantedOrderBy = (window.LilithSearch || {}).orderBy;
  if (wantedOrderBy) { document.getElementById('order-by').value = wantedOrderBy; }
  var hostCheckbox = document.getElementById('show-host-col');
  var storedHostCol = localStorage.getItem('showHostCol') === 'true';
  hostCheckbox.checked = storedHostCol;
  applyHostCol(storedHostCol);
  hostCheckbox.addEventListener('change', function() {
    localStorage.setItem('showHostCol', this.checked);
    applyHostCol(this.checked);
  });

  // GeoIP city: show the city label next to each IP's country flag. Defaults on
  // when the user has not made an explicit choice.
  var cityCheckbox  = document.getElementById('show-city');
  var storedCity    = localStorage.getItem('showGeoCity');
  cityCheckbox.checked = ( storedCity === null ) ? true : ( storedCity === 'true' );
  applyGeoCity(cityCheckbox.checked);
  cityCheckbox.addEventListener('change', function() {
    localStorage.setItem('showGeoCity', this.checked);
    applyGeoCity(this.checked);
  });

  // Auto-FC: keep the filter panel collapsed on load (overriding the server's
  // auto-expand when filters are set) until the Filters button is clicked.
  var autoFcCheckbox = document.getElementById('auto-fc');
  var filterPanel  = document.getElementById('filter-panel');
  var storedAutoFc = localStorage.getItem('autoFc');
  // default on when the user has not made an explicit choice
  autoFcCheckbox.checked = ( storedAutoFc === null ) ? true : ( storedAutoFc === 'true' );
  if (autoFcCheckbox.checked) { filterPanel.classList.remove('show'); }
  autoFcCheckbox.addEventListener('change', function() {
    localStorage.setItem('autoFc', this.checked);
    if (this.checked) {
      bootstrap.Collapse.getOrCreateInstance(filterPanel, { toggle: false }).hide();
    }
  });

  // Bind everything inside the results container. Re-run after an auto-refresh
  // swaps in fresh rows so the new elements get their handlers.
  initResults();

  // Auto-refresh (shared module): fetch fresh results every N seconds and swap
  // them in place, with no full page reload (so scroll position and form state
  // are kept). State is kept in localStorage so it persists across navigation.
  LilithAutoRefresh.init({
    checkboxId:     'auto-refresh',
    secondsInputId: 'auto-refresh-secs',
    statusId:       'ar-status',
    containerId:    'search-results',
    storagePrefix:  'autoRefresh',
    afterSwap:      initResults
  });
});
})();
