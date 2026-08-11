/*
 * The /search page: the table-dependent parts of the filter form, the view
 * toggles that persist in localStorage, the click-to-filter cells in the
 * results, and the shared auto-refresh.
 *
 * Markup contract: the table <select> is #table-sel, and every filter field
 * that only applies to some tables carries class .search-filter-field with a
 * data-tables list of the tables it belongs to. Fields that do not match the
 * selected table get .filter-hidden. A text filter is a .search-token-field
 * <select multiple>, and one whose dropdown offers the values that occur names
 * its column in data-column.
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

// Repopulate the Order by picker for the selected table, keeping the current
// column when the new table also has it and falling back to that table's
// default (the first entry) when it does not.
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
  if (prev && cols.indexOf(prev) !== -1) {
    orderBy.value = prev;
  } else {
    orderBy.value = cols[0];
  }
}

// What /api/search/values is asked for a field: the column named in its
// data-column, on the selected table, over the window the search itself runs
// with -- so what is offered describes the rows the page is showing. Returned
// as a query string, which doubles as the cache key for what a field last
// loaded: change the table or the window and it no longer matches, so the next
// focus fetches again.
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

// Fetch a field's values and hand them to Tom Select. A column the selected
// table cannot be grouped by answers 400, and an unreachable database answers
// 400 as well; either way the field is left as the free text one it already
// is, since a filter that cannot suggest is not a filter that cannot be typed.
function fetchValueSuggestions(selectEl, callback) {
  fetch('/api/search/values?' + selectEl.dataset.suggestQuery)
    .then(function(response) { return response.ok ? response.json() : { values: [] }; })
    .then(function(data) {
      callback((data.values || []).map(function(row) {
        return { value: String(row.value), text: String(row.value), count: row.count };
      }));
    })
    .catch(function() { callback([]); });
}

// Load a field's values if what it holds is not already the right list. Called
// on focus, so a field is only ever fetched for once it is used, and the table
// or window having changed since is what makes it fetch again. clearOptions
// keeps the values currently selected, so refetching never drops a chip.
function loadValueSuggestions(selectEl) {
  if (!selectEl.dataset.column || !selectEl.tomselect) { return; }

  var query = valueSuggestionQuery(selectEl);
  if (selectEl.dataset.suggestQuery === query) { return; }
  selectEl.dataset.suggestQuery = query;

  selectEl.tomselect.clearOptions();
  selectEl.tomselect.load('');
}

// Upgrade the filter panel's multi-selects into type-to-filter fields with a
// removable chip per value. Two kinds, differing only in where their values
// come from: the classification pickers choose from a fixed list, while the
// text filters (.search-token-field) take whatever is typed.
//
// This is enhancement only: Tom Select keeps the original <select multiple> as
// the form control and just drives it, so the page submits the same one
// parameter per value either way. If the vendored file is missing the fields
// stay the plain multi-selects they are in the markup -- usable, if only for
// dropping values rather than adding them -- which is why nothing else here
// depends on TomSelect being defined.
function initFilterPickers() {
  if (!window.TomSelect) { return; }

  document.querySelectorAll('#filter-panel select[multiple]:not(.search-token-field)').forEach(function(selectEl) {
    new TomSelect(selectEl, {
      plugins:     ['remove_button'],
      placeholder: 'type to filter…',
      // there are more classifications than Tom Select's default cap of 50, and
      // a silently truncated dropdown is worse than a scrolling one
      maxOptions:  null
    });
  });

  document.querySelectorAll('#filter-panel select.search-token-field').forEach(function(selectEl) {
    new TomSelect(selectEl, {
      plugins:     ['remove_button'],
      placeholder: 'any',
      create:      true,
      // The dropdown offers the values that actually occur (see
      // loadValueSuggestions), which is a fetch on focus rather than one per
      // keystroke: the whole list arrives at once and Tom Select filters it
      // here. shouldLoad therefore refuses the per-keystroke load Tom Select
      // would otherwise do.
      shouldLoad: function() { return false; },
      load:       function(query, callback) { fetchValueSuggestions(selectEl, callback); },
      onFocus:    function() { loadValueSuggestions(selectEl); },
      // the fetched values arrive most common first, which is the order to
      // show them in when nothing has been typed to rank them by
      sortField:  [ { field: '$score' }, { field: '$order' } ],
      // a column with more values than the dropdown's default cap is exactly
      // one worth scrolling rather than silently truncating
      maxOptions: null,
      render: {
        option: function(data) {
          var row = document.createElement('div');
          row.textContent = data.text;
          if (data.count !== undefined) {
            var count = document.createElement('span');
            count.className   = 'text-muted small ms-2';
            count.textContent = data.count;
            row.appendChild(count);
          }
          return row;
        }
      },
      // a value typed but not entered would otherwise be dropped on the floor
      // when the search is submitted, silently running a different search than
      // the one on screen
      createOnBlur: true,
      // comma is how these fields took several values before they were tokens,
      // and how a pasted list is written
      delimiter:   ',',
      // a removed value should leave the dropdown with it rather than hang
      // around as a suggestion
      persist:     false
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

// Toggle the cached Shodan badges shown after each IP's geo annotation. Only
// the display: the badges are rendered with the rest of the row either way,
// since they come from one query the page has already made.
function applyShodanBadges(show) {
  document.querySelectorAll('#search-results .shodan-badges').forEach(function(el) {
    el.style.display = show ? '' : 'none';
  });
}

// Make a filter field hold one value and nothing else. The fields are token
// fields, so what a click-to-filter cell wants is a replacement rather than an
// addition: clicking a second instance would otherwise widen the search to both
// rather than narrow it to the one clicked. Handles the field either as Tom
// Select left it or as the plain <select multiple> it is without Tom Select.
function setFilterValue(fieldEl, value) {
  if (fieldEl.tomselect) {
    fieldEl.tomselect.clear(true);
    fieldEl.tomselect.addOption({ value: value, text: value });
    fieldEl.tomselect.addItem(value, true);
    return;
  }

  fieldEl.innerHTML = '';
  var option = document.createElement('option');
  option.value = value;
  option.textContent = value;
  option.selected = true;
  fieldEl.appendChild(option);
}

// Bind a class of clickable result cells to a filter field + submit.
function bindFilter(selector, inputId, dataKey) {
  document.querySelectorAll(selector).forEach(function(el) {
    el.addEventListener('click', function(event) {
      event.preventDefault();
      setFilterValue(document.getElementById(inputId), this.dataset[dataKey]);
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

  var shodanCheckbox = document.getElementById('show-shodan');
  applyShodanBadges(!shodanCheckbox || shodanCheckbox.checked);

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
    syncOrderBy(false);
    syncFilterFields();
  });
  syncOrderBy(false);
  syncFilterFields();
  initFilterPickers();
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

  // Shodan badges: the cached tags, port count, and CVE count after each IP's
  // geo annotation. Defaults on when the user has not made an explicit choice.
  var shodanCheckbox = document.getElementById('show-shodan');
  var storedShodan   = localStorage.getItem('showShodanBadges');
  shodanCheckbox.checked = ( storedShodan === null ) ? true : ( storedShodan === 'true' );
  applyShodanBadges(shodanCheckbox.checked);
  shodanCheckbox.addEventListener('change', function() {
    localStorage.setItem('showShodanBadges', this.checked);
    applyShodanBadges(this.checked);
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
