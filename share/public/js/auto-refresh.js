/*
 * Reusable auto-refresh control shared by the search and logs pages.
 *
 * Markup contract: the page supplies an enable checkbox, an interval
 * <input type=number> (seconds), a status <span>, and a results container
 * that the server can re-render on its own via the partial=1 query param.
 * Rows inside the container carry .event-link anchors whose text is the row
 * ID; that is used to spot (and flash) rows that are new since the last load.
 *
 * LilithAutoRefresh.init({
 *   checkboxId:     enable/disable checkbox
 *   secondsInputId: number input holding the refresh interval in seconds
 *   statusId:       span showing 'updated HH:MM:SS' or the failure notice
 *   containerId:    results fragment swapped in place (e.g. 'search-results')
 *   storagePrefix:  localStorage keys <prefix> (on/off) and <prefix>Secs
 *   afterSwap:      optional callback run after fresh results are swapped in
 *                   (used to rebind handlers on the new elements)
 * });
 *
 * Each tick fetches the current URL with partial=1 and swaps the container's
 * innerHTML, so scroll position and form state are kept. On any failure the
 * existing content is left untouched. Polling pauses while the tab is hidden
 * (to avoid needless server load and bandwidth) and, on return, refreshes
 * immediately when the data is older than the interval. Rows whose event ID
 * was not present before a refresh get the .row-new flash class.
 */
(function () {
  function pad2(value) { return (value < 10 ? '0' : '') + value; }

  function init(options) {
    var checkboxEl     = document.getElementById(options.checkboxId);
    var secondsInputEl = document.getElementById(options.secondsInputId);
    if (!checkboxEl || !secondsInputEl) { return; }

    var storageEnabledKey = options.storagePrefix;
    var storageSecondsKey = options.storagePrefix + 'Secs';
    var refreshTimer      = null;
    var lastRefresh       = Date.now();   // the page load is itself a "refresh"

    // Show the outcome of the latest refresh next to the auto-refresh control.
    function setRefreshStatus(ok) {
      var statusEl = document.getElementById(options.statusId);
      if (!statusEl) { return; }
      var now = new Date();
      var timeStr = pad2(now.getHours()) + ':' + pad2(now.getMinutes()) + ':' + pad2(now.getSeconds());
      if (ok) {
        statusEl.textContent = 'updated ' + timeStr;
        statusEl.className = 'small text-muted';
      } else {
        statusEl.textContent = '⚠ refresh failed ' + timeStr + ' (showing stale data)';
        statusEl.className = 'small text-warning';
      }
      statusEl.style.whiteSpace = 'nowrap';
    }

    // Collect the set of event IDs currently shown in the results container.
    function currentRowIds() {
      var ids = new Set();
      var container = document.getElementById(options.containerId);
      if (container) {
        container.querySelectorAll('tbody tr .event-link').forEach(function (link) { ids.add(link.textContent.trim()); });
      }
      return ids;
    }

    // Fetch just the results fragment (partial=1) and swap the container in
    // place, then rebind and flash any rows whose event ID was not present
    // before. On any failure the existing content is left untouched. Calls
    // done() when finished.
    function refreshResults(done) {
      var priorIds = currentRowIds();
      var url = new URL(window.location.href);
      url.searchParams.set('partial', '1');
      fetch(url.toString(), { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function (response) { if (!response.ok) { throw new Error('HTTP ' + response.status); } return response.text(); })
        .then(function (html) {
          var fresh   = new DOMParser().parseFromString(html, 'text/html').getElementById(options.containerId);
          var current = document.getElementById(options.containerId);
          if (fresh && current) {
            current.innerHTML = fresh.innerHTML;
            current.querySelectorAll('tbody tr').forEach(function (tr) {
              var link = tr.querySelector('.event-link');
              if (link && !priorIds.has(link.textContent.trim())) { tr.classList.add('row-new'); }
            });
            if (options.afterSwap) { options.afterSwap(); }
            setRefreshStatus(true);
          } else {
            setRefreshStatus(false);   // response had no results fragment (e.g. an error page)
          }
        })
        .catch(function () { setRefreshStatus(false); /* keep the current results */ })
        .finally(function () { if (done) { done(); } });
    }

    function refreshIntervalSecs() {
      var secs = parseInt(secondsInputEl.value, 10);
      return (!secs || secs < 1) ? 30 : secs;
    }
    function stopAutoRefresh() {
      if (refreshTimer) { clearTimeout(refreshTimer); refreshTimer = null; }
    }
    function refreshThenReschedule() {
      refreshResults(function () { lastRefresh = Date.now(); scheduleNext(); });
    }
    // Schedule the next tick, unless disabled or the tab is hidden (polling is
    // paused while hidden to avoid needless server load and bandwidth).
    function scheduleNext() {
      stopAutoRefresh();
      if (!checkboxEl.checked || document.hidden) { return; }
      refreshTimer = setTimeout(refreshThenReschedule, refreshIntervalSecs() * 1000);
    }

    var storedRefreshSecs = localStorage.getItem(storageSecondsKey);
    if (storedRefreshSecs) { secondsInputEl.value = storedRefreshSecs; }
    checkboxEl.checked = localStorage.getItem(storageEnabledKey) === 'true';
    scheduleNext();
    checkboxEl.addEventListener('change', function () {
      localStorage.setItem(storageEnabledKey, this.checked);
      scheduleNext();
    });
    secondsInputEl.addEventListener('change', function () {
      localStorage.setItem(storageSecondsKey, this.value);
      scheduleNext();
    });
    // When the tab becomes visible again, refresh immediately if the data is
    // older than the refresh interval, then resume normal scheduling.
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        stopAutoRefresh();
      } else if (checkboxEl.checked) {
        if (Date.now() - lastRefresh >= refreshIntervalSecs() * 1000) {
          refreshThenReschedule();
        } else {
          scheduleNext();
        }
      }
    });

    // Seed the status with the load time so "updated HH:MM:SS" reflects the
    // data currently on screen, but only when results are actually shown.
    if (document.getElementById(options.containerId)) { setRefreshStatus(true); }
  }

  window.LilithAutoRefresh = { init: init };
})();
