/*
 * Virani PCAP tooling: the set loader shared with the event view, the PCAP
 * search modal, and the cached searches browser.
 *
 * Both modals self-guard on their markup being present, so this loads on every
 * page and simply does nothing when Virani is not enabled.
 *
 * Requires lilith-util.js.
 */
(function () {
  var util = window.LilithUtil;

  // Populate a <select> with the PCAP sets available on a Virani remote. Shared
  // by the event view and the Virani search modal. Keeps the first option
  // (the default set) in place.
  window.loadViraniSets = function (selectEl, remote) {
    while (selectEl.options.length > 1) { selectEl.remove(1); }
    if (!remote) { return; }
    fetch('/api/virani/sets/' + encodeURIComponent(remote))
      .then(function (response) { return response.json(); })
      .then(function (data) {
        (data.sets || []).forEach(function (setName) {
          var option = document.createElement('option');
          option.value = setName;
          option.textContent = (setName === data.default_set) ? setName + ' (default)' : setName;
          selectEl.appendChild(option);
        });
      })
      .catch(function () { /* leave just the default option */ });
  };

  document.addEventListener('DOMContentLoaded', function () {

    // ---- PCAP search modal -------------------------------------------------
    (function () {
      var modal = document.getElementById('virani-modal');
      if (!modal) { return; }
      var remoteEl  = document.getElementById('virani-remote');
      var setEl     = document.getElementById('virani-set');
      var startDate = document.getElementById('virani-start-date');
      var startTime = document.getElementById('virani-start-time');
      var endDate   = document.getElementById('virani-end-date');
      var endTime   = document.getElementById('virani-end-time');
      var filterEl  = document.getElementById('virani-filter');
      var errEl     = document.getElementById('virani-error');
      var cmdWrap   = document.getElementById('virani-cmd-wrap');
      var cmdEl     = document.getElementById('virani-cmd');

      // Combine a date field (YYYY-MM-DD) and a 24-hour HH:MM time field into an
      // epoch, interpreting them in the browser's local timezone. null if invalid.
      function epochOf(dateEl, timeEl) {
        if (!dateEl.value || !/^\d{1,2}:\d{2}$/.test(timeEl.value)) { return null; }
        var date = new Date(dateEl.value + 'T' + timeEl.value);
        return isNaN(date.getTime()) ? null : Math.floor(date.getTime() / 1000);
      }
      function setRange(minutes) {
        var pad = util.pad2;
        var now = new Date(), start = new Date(now.getTime() - minutes * 60000);
        startDate.value = start.getFullYear() + '-' + pad(start.getMonth() + 1) + '-' + pad(start.getDate());
        startTime.value = pad(start.getHours()) + ':' + pad(start.getMinutes());
        endDate.value   = now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate());
        endTime.value   = pad(now.getHours()) + ':' + pad(now.getMinutes());
      }
      document.querySelectorAll('.virani-range').forEach(function (rangeBtn) {
        rangeBtn.addEventListener('click', function () { setRange(parseInt(this.dataset.mins, 10)); });
      });

      modal.addEventListener('show.bs.modal', function () {
        if (!startDate.value || !endDate.value) { setRange(15); }
        window.loadViraniSets(setEl, remoteEl.value);
      });
      remoteEl.addEventListener('change', function () { window.loadViraniSets(setEl, this.value); });

      function query() {
        errEl.style.display = 'none';
        var startEpoch = epochOf(startDate, startTime), endEpoch = epochOf(endDate, endTime);
        if (!filterEl.value.trim()) { errEl.textContent = 'A BPF filter is required.'; errEl.style.display = ''; return null; }
        if (startEpoch === null || endEpoch === null) { errEl.textContent = 'Valid start and end times (HH:MM, 24h) are required.'; errEl.style.display = ''; return null; }
        if (startEpoch >= endEpoch) { errEl.textContent = 'Start must be before end.'; errEl.style.display = ''; return null; }
        return { remote: remoteEl.value, set: setEl.value, start: startEpoch, end: endEpoch, filter: filterEl.value.trim() };
      }

      document.getElementById('virani-show-cmd').addEventListener('click', function () {
        var params = query(); if (!params) { return; }
        cmdEl.textContent = 'virani -s ' + params.start + ' -e ' + params.end + (params.set ? ' --set ' + params.set : '')
          + " -w search.pcap -f '" + params.filter + "'";
        cmdWrap.style.display = '';
      });
      var downloadBtn = document.getElementById('virani-download');
      if (downloadBtn) {
        downloadBtn.addEventListener('click', function () {
          var params = query(); if (!params) { return; }
          window.location.href = '/api/virani/pcap?remote=' + encodeURIComponent(params.remote)
            + '&set=' + encodeURIComponent(params.set) + '&start=' + params.start + '&end=' + params.end
            + '&filter=' + encodeURIComponent(params.filter);
        });
      }
      document.getElementById('virani-copy').addEventListener('click', function () {
        if (navigator.clipboard) { navigator.clipboard.writeText(cmdEl.textContent); }
      });
    })();

    // ---- Cached searches modal ---------------------------------------------
    (function () {
      var modal = document.getElementById('virani-cache-modal');
      if (!modal) { return; }
      var remoteEl = document.getElementById('virani-cache-remote');
      var rowsEl   = document.getElementById('virani-cache-rows');
      var statusEl = document.getElementById('virani-cache-status');

      function load() {
        var remote = remoteEl.value;
        rowsEl.innerHTML = '';
        statusEl.textContent = 'Loading…';
        fetch('/api/virani/cached/' + encodeURIComponent(remote))
          .then(function (response) {
            return response.text().then(function (body) {
              var data = null;
              try { data = JSON.parse(body); } catch (err) { /* non-JSON error body */ }
              return { ok: response.ok, status: response.status, data: data };
            });
          })
          .then(function (result) {
            if (!result.ok) {
              statusEl.textContent = (result.data && result.data.error) ? result.data.error : ('request failed: HTTP ' + result.status);
              return;
            }
            var items = (result.data && result.data.cached) || [];
            statusEl.textContent = items.length + ' cached search' + (items.length === 1 ? '' : 'es')
              + (items.length >= 50 ? ' (newest 50)' : '');
            items.forEach(function (item) {
              var row = document.createElement('tr');
              row.appendChild(util.cell(util.fmtTime(item.start_s)));
              row.appendChild(util.cell(util.fmtTime(item.end_s)));
              row.appendChild(util.cell(util.fmtSize(item.final_size)));
              row.appendChild(util.cell(item.set));
              row.appendChild(util.cell(item.filter, 'font-monospace small'));
              row.appendChild(util.cell(item.found));
              row.appendChild(util.cell(item.success));
              var downloadCell = document.createElement('td');
              downloadCell.className = 'text-nowrap';
              if (item.has_pcap) {
                var pcapLink = document.createElement('a');
                pcapLink.className = 'btn btn-sm btn-outline-secondary py-0 me-1';
                pcapLink.textContent = 'PCAP';
                pcapLink.href = '/api/virani/cached/' + encodeURIComponent(remote) + '/pcap/' + encodeURIComponent(item.id);
                downloadCell.appendChild(pcapLink);
              }
              var jsonLink = document.createElement('a');
              jsonLink.className = 'btn btn-sm btn-outline-secondary py-0';
              jsonLink.textContent = 'JSON';
              jsonLink.href = '/api/virani/cached/' + encodeURIComponent(remote) + '/meta/' + encodeURIComponent(item.id);
              downloadCell.appendChild(jsonLink);
              row.appendChild(downloadCell);
              rowsEl.appendChild(row);
            });
          })
          .catch(function (err) { statusEl.textContent = 'Failed to load cached searches: ' + err; });
      }
      modal.addEventListener('show.bs.modal', load);
      remoteEl.addEventListener('change', load);
      document.getElementById('virani-cache-refresh').addEventListener('click', load);
    })();

  });
})();
