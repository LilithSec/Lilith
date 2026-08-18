/*
 * The /logs page: show only the filter fields that apply to the selected
 * Allani source, upgrade them into the shared token filter fields, wire the
 * click-to-filter cells in the results, and drive the shared auto-refresh over
 * them.
 *
 * Markup contract: the source <select> is #source-sel, and each filter field
 * wrapper carries class .log-filter-field with a data-sources list of the
 * sources it belongs to. The fields themselves are .token-filter-field
 * <select multiple>s (see token-fields.js), ids named after their filter
 * (underscores to hyphens, '-input' appended). A clickable result cell is an
 * a.log-filter-cell with data-filter naming the filter and data-value the
 * value; they are bound by delegation, so an auto-refresh swapping the results
 * needs no rebinding.
 *
 * Requires token-fields.js, auto-refresh.js, and lilith-table.js. Self-guards
 * on the source selector being present.
 */
(function() {
// Show only the filter fields that apply to the selected source.
function syncFilters() {
  var selectedSource = document.getElementById('source-sel').value;
  document.querySelectorAll('.log-filter-field').forEach(function(fieldEl) {
    var fieldSources = (fieldEl.dataset.sources || '').split(/\s+/);
    fieldEl.style.display = (fieldSources.indexOf(selectedSource) !== -1) ? '' : 'none';
  });
}

// What /api/logs/values is asked for a field: the column named in its
// data-column, on the selected source, over the window the search itself runs
// with -- so what is offered describes the rows the page is showing.
function valueSuggestionQuery(selectEl) {
  var params = new URLSearchParams();
  params.set('source', document.getElementById('source-sel').value);
  params.set('column', selectEl.dataset.column);

  var form = document.getElementById('logs-form');
  ['go_back_minutes', 'start', 'end'].forEach(function(name) {
    var field = form.elements[name];
    if (field && field.value) { params.set(name, field.value); }
  });

  return params.toString();
}

// Client-side sorting on the results table's headers (shared module). Bound
// to the table element itself, so unlike the delegated filter cells it has to
// be rebound after an auto-refresh swaps fresh results in.
function initResultsSort() {
  LilithTable.initSort(document.querySelector('#log-results table.table'));
}

document.addEventListener('DOMContentLoaded', function() {
  var sourceEl = document.getElementById('source-sel');
  if (!sourceEl) { return; }
  sourceEl.addEventListener('change', syncFilters);
  syncFilters();
  initResultsSort();

  LilithTokenFields.init({
    valuesUrl:   '/api/logs/values',
    valuesQuery: valueSuggestionQuery
  });

  // Click-to-filter cells, by delegation. Clicking replaces the field's values
  // with the clicked one rather than adding to it, so the search narrows to
  // what was clicked.
  document.addEventListener('click', function(event) {
    var cell = event.target.closest('a.log-filter-cell');
    if (!cell) { return; }
    event.preventDefault();

    var fieldEl = document.getElementById(cell.dataset.filter.replace(/_/g, '-') + '-input');
    if (!fieldEl) { return; }
    LilithTokenFields.setValue(fieldEl, cell.dataset.value);
    document.getElementById('logs-form').submit();
  });

  // Auto-refresh (shared module): fetch fresh results every N seconds and swap
  // #log-results in place. State is kept in localStorage so it persists.
  LilithAutoRefresh.init({
    checkboxId:     'logs-auto-refresh',
    secondsInputId: 'logs-auto-refresh-secs',
    statusId:       'logs-ar-status',
    containerId:    'log-results',
    storagePrefix:  'logsAutoRefresh',
    afterSwap:      initResultsSort
  });
});
})();
