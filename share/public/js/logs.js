/*
 * The /logs page: show only the filter fields that apply to the selected
 * Allani source, and drive the shared auto-refresh over the results.
 *
 * Markup contract: the source <select> is #source-sel, and each filter field
 * carries class .log-filter-field with a data-sources list of the sources it
 * belongs to.
 *
 * Requires auto-refresh.js. Self-guards on the source selector being present.
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

document.addEventListener('DOMContentLoaded', function() {
  var sourceEl = document.getElementById('source-sel');
  if (!sourceEl) { return; }
  sourceEl.addEventListener('change', syncFilters);
  syncFilters();

  // Auto-refresh (shared module): fetch fresh results every N seconds and swap
  // #log-results in place. State is kept in localStorage so it persists.
  LilithAutoRefresh.init({
    checkboxId:     'logs-auto-refresh',
    secondsInputId: 'logs-auto-refresh-secs',
    statusId:       'logs-ar-status',
    containerId:    'log-results',
    storagePrefix:  'logsAutoRefresh'
  });
});
})();
