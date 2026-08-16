/*
 * The /search page: the table-dependent parts of the filter form, the view
 * toggles that persist in localStorage, the click-to-filter cells in the
 * results, and the shared auto-refresh.
 *
 * Markup contract: the table <select> is #table-sel, and every filter field
 * that only applies to some tables carries class .search-filter-field with a
 * data-tables list of the tables it belongs to. Fields that do not match the
 * selected table get .filter-hidden. A text filter is a .token-filter-field
 * <select multiple> (upgraded by the shared token-fields.js module), and one
 * whose dropdown offers the values that occur names its column in data-column.
 *
 * The sortable columns per table are not kept here: the page publishes them as
 * window.LilithSearch.orderByColumns (from the server's order_by_columns
 * helper), so this cannot drift from what Lilith::search accepts.
 * window.LilithSearch.orderBy is the column the current results are sorted by.
 *
 * Requires lilith-util.js, lilith-table.js, token-fields.js, and
 * auto-refresh.js.
 */
(function () {
// The sortable columns per table, from the order_by_columns helper, which
// derives them from %Lilith::alert_columns -- so this cannot drift from what
// Lilith::search accepts. Each list leads with that table's default.
var _orderByCols = (window.LilithSearch || {}).orderByColumns || {};

// Repopulate the Order by picker for the selected table, selecting that
// table's default (the first entry).
function syncOrderBy() {
  var table = document.getElementById('table-sel').value;
  var orderBy = document.getElementById('order-by');
  var cols = _orderByCols[table] || _orderByCols.suricata;
  orderBy.innerHTML = '';
  cols.forEach(function(column) {
    var option = document.createElement('option');
    option.value = column; option.textContent = column;
    orderBy.appendChild(option);
  });
  orderBy.value = cols[0];
}

// What /api/search/values is asked for a field: the column named in its
// data-column, on the selected table, over the window the search itself runs
// with -- so what is offered describes the rows the page is showing.
function valueSuggestionQuery(selectEl) {
  var params = new URLSearchParams();
  params.set('table',  document.getElementById('table-sel').value);
  params.set('column', selectEl.dataset.column);

  var form = document.getElementById('search-form');
  ['go_back_minutes', 'start', 'end'].forEach(function(name) {
    var field = form.elements[name];
    if (field && field.value) { params.set(name, field.value); }
  });

  return params.toString();
}

// Upgrade the filter panel's multi-selects into type-to-filter fields with a
// removable chip per value. The text filters are the shared token fields
// (token-fields.js); the classification pickers, which choose from a fixed
// list rather than taking what is typed, are this page's own.
//
// This is enhancement only: Tom Select keeps the original <select multiple> as
// the form control and just drives it, so the page submits the same one
// parameter per value either way. If the vendored file is missing the fields
// stay the plain multi-selects they are in the markup -- usable, if only for
// dropping values rather than adding them -- which is why nothing else here
// depends on TomSelect being defined.
function initFilterPickers() {
  LilithTokenFields.init({
    valuesUrl:   '/api/search/values',
    valuesQuery: valueSuggestionQuery
  });

  if (!window.TomSelect) { return; }

  document.querySelectorAll('#filter-panel select[multiple]:not(.token-filter-field)').forEach(function(selectEl) {
    new TomSelect(selectEl, {
      plugins:     ['remove_button'],
      placeholder: 'type to filter…',
      // there are more classifications than Tom Select's default cap of 50, and
      // a silently truncated dropdown is worse than a scrolling one
      maxOptions:  null
    });
  });

  // the ctrl/cmd-click hint is about the control we just replaced
  document.querySelectorAll('.multi-select-hint').forEach(function(hintEl) {
    hintEl.style.display = 'none';
  });
}

// Show only the filter fields that apply to the selected table. Which table a
// field belongs to lives in the markup, as a data-tables list on each
// .search-filter-field, so a new table needs no change here.
function syncFilterFields() {
  var table = document.getElementById('table-sel').value;
  document.querySelectorAll('.search-filter-field').forEach(function(fieldEl) {
    var fieldTables = (fieldEl.dataset.tables || '').split(/\s+/);
    fieldEl.classList.toggle('filter-hidden', fieldTables.indexOf(table) === -1);
  });
}
// Show or hide everything a view toggle governs.
function applyDisplay(selector, show) {
  document.querySelectorAll(selector).forEach(function(el) {
    el.style.display = show ? '' : 'none';
  });
}

// The view toggles that persist in localStorage: the Host column, the GeoIP
// city label beside each IP's country flag, and the cached Shodan badges after
// each IP's geo annotation. Display only -- the city and badges are rendered
// with the rest of the row either way, since they come from queries the page
// has already made. defaultOn is what applies until the user makes an explicit
// choice: the annotations show, the extra column does not.
var VIEW_TOGGLES = [
  { checkboxId: 'show-host-col', storageKey: 'showHostCol',      defaultOn: false, selector: '.col-host' },
  { checkboxId: 'show-city',     storageKey: 'showGeoCity',      defaultOn: true,  selector: '#search-results .geoip-city' },
  { checkboxId: 'show-shodan',   storageKey: 'showShodanBadges', defaultOn: true,  selector: '#search-results .shodan-badges' }
];

// Bind a class of clickable result cells to a filter field + submit. Clicking
// replaces the field's values with the clicked one (LilithTokenFields.setValue)
// rather than adding to them, so the search narrows to what was clicked.
function bindFilter(selector, inputId, dataKey) {
  document.querySelectorAll(selector).forEach(function(el) {
    el.addEventListener('click', function(event) {
      event.preventDefault();
      LilithTokenFields.setValue(document.getElementById(inputId), this.dataset[dataKey]);
      document.getElementById('search-form').submit();
    });
  });
}

// (Re)wire all handlers and view state inside the results container. Safe to
// call again after the results HTML is swapped in by an auto-refresh.
function initResults() {
  VIEW_TOGGLES.forEach(function(toggle) {
    var checkbox = document.getElementById(toggle.checkboxId);
    applyDisplay(toggle.selector, checkbox ? checkbox.checked : toggle.defaultOn);
  });

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
  bindFilter('.user-filter',          'username-input',      'user');

  LilithTable.initSort(document.querySelector('#search-results table.table'));

  // The IP info modal + lookup lives in the layout; just wire the buttons.
  document.querySelectorAll('#search-results .ip-info-btn').forEach(function(el) {
    el.addEventListener('click', function() { window.showIpInfo(this.dataset.ip); });
  });
}

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('table-sel').addEventListener('change', function() {
    syncOrderBy();
    syncFilterFields();
  });
  syncOrderBy();
  syncFilterFields();
  initFilterPickers();
  var wantedOrderBy = (window.LilithSearch || {}).orderBy;
  if (wantedOrderBy) { document.getElementById('order-by').value = wantedOrderBy; }

  // Restore each view toggle from localStorage, apply it, and persist changes.
  VIEW_TOGGLES.forEach(function(toggle) {
    var checkbox = document.getElementById(toggle.checkboxId);
    var stored   = localStorage.getItem(toggle.storageKey);
    checkbox.checked = ( stored === null ) ? toggle.defaultOn : ( stored === 'true' );
    applyDisplay(toggle.selector, checkbox.checked);
    checkbox.addEventListener('change', function() {
      localStorage.setItem(toggle.storageKey, this.checked);
      applyDisplay(toggle.selector, this.checked);
    });
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
