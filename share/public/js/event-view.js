/*
 * The /event/<table>/<id> view: the download buttons, the IP / domain lookup
 * buttons, the Virani PCAP controls, the CAPE detonation results panel, and
 * the escalation history plus its Escalate modal.
 *
 * Everything here is optional -- the PCAP controls need a Virani remote, the
 * CAPE panel a results endpoint, the escalation parts escalation_enable -- so
 * each section guards on its own anchor and simply does nothing when the
 * server did not render it.
 *
 * The page publishes window.LilithEvent.{table,id}, the event this view is of.
 *
 * Requires lilith-util.js and lilith-virani.js.
 */
(function () {
var EVENT = window.LilithEvent || {};
document.addEventListener('DOMContentLoaded', function() {
  var util = window.LilithUtil;

  document.querySelectorAll('.http-body-dl').forEach(function(btn) {
    btn.addEventListener('click', function() {
      util.downloadBase64(this.dataset.body, this.dataset.filename, this.dataset.type);
    });
  });

  // The Domain Info modal + lookup lives in the layout; just wire the buttons.
  document.querySelectorAll('.domain-info-btn').forEach(function(el) {
    el.addEventListener('click', function() {
      window.showDomainInfo(this.dataset.domain);
    });
  });

  var payloadBtn = document.getElementById('download-payload-btn');
  if (payloadBtn) {
    payloadBtn.addEventListener('click', function() {
      util.downloadBase64(this.dataset.payload, this.dataset.filename, 'application/octet-stream');
    });
  }

  var dlBtn = document.getElementById('download-json-btn');
  if (dlBtn) {
    dlBtn.addEventListener('click', function() {
      var json = document.querySelector('#raw-json-panel pre').textContent;
      util.downloadBlob(json, 'event-' + EVENT.table + '-' + EVENT.id + '.json', 'application/json');
    });
  }

  // The IP info modal + lookup lives in the layout; just wire the buttons.
  document.querySelectorAll('.ip-info-btn').forEach(function(el) {
    el.addEventListener('click', function() {
      window.showIpInfo(this.dataset.ip);
    });
  });

  // PCAP download controls
  (function() {
    var box = document.getElementById('pcap-controls');
    if (!box) { return; }
    var remoteEl = document.getElementById('pcap-remote');
    var setEl    = document.getElementById('pcap-set');

    // Set list comes from the shared loader in the layout.
    window.loadViraniSets(setEl, remoteEl.value);
    if (remoteEl.tagName === 'SELECT') {
      remoteEl.addEventListener('change', function() { window.loadViraniSets(setEl, this.value); });
    }

    // Download: fetch from the remote (streamed by the server).
    document.getElementById('pcap-dl').addEventListener('click', function() {
      var url = '/event/' + encodeURIComponent(box.dataset.table) + '/' + encodeURIComponent(box.dataset.id)
              + '/pcap?remote=' + encodeURIComponent(remoteEl.value)
              + '&set=' + encodeURIComponent(setEl.value);
      window.location.href = url;
    });

    // Local command: show the virani invocation to run on the box with the PCAPs.
    var reveal = document.getElementById('pcap-local-cmd');
    var cmdEl  = document.getElementById('pcap-cmd');
    document.getElementById('pcap-local').addEventListener('click', function(event) {
      event.preventDefault();
      var set = setEl.value;
      var cmd = 'virani -s ' + box.dataset.start + ' -e ' + box.dataset.end
              + (set ? ' --set ' + set : '')
              + ' -w event-' + box.dataset.id + '.pcap'
              + " -f '" + box.dataset.filter + "'";
      cmdEl.textContent = cmd;
      bootstrap.Collapse.getOrCreateInstance(reveal).show();
    });
    document.getElementById('pcap-copy').addEventListener('click', function() {
      if (navigator.clipboard) { navigator.clipboard.writeText(cmdEl.textContent); }
    });
    document.getElementById('pcap-cmd-close').addEventListener('click', function() {
      bootstrap.Collapse.getOrCreateInstance(reveal).hide();
    });
  })();
});

document.addEventListener('DOMContentLoaded', function() {
  var util = window.LilithUtil;
  var box = document.getElementById('cape-results');
  if (!box) { return; }
  var id       = box.dataset.id;
  var base     = '/event/cape/' + encodeURIComponent(id);
  var statusEl = document.getElementById('cape-results-status');
  var infoEl   = document.getElementById('cape-results-info');
  var shotsEl  = document.getElementById('cape-shots');

  statusEl.textContent = 'Loading…';

  // Render the malscore + signatures from lite.json as a compact card. The cape
  // row already carries the hashes/target/malscore, so this focuses on the
  // signatures, which are not otherwise stored in Lilith.
  function renderInfo(lite) {
    if (!lite || typeof lite !== 'object') { return; }

    if (lite.malscore != null) {
      var score = Number(lite.malscore);
      var badgeClass = score >= 8 ? 'bg-danger' : score >= 4 ? 'bg-warning text-dark' : 'bg-secondary';
      var line = document.createElement('div');
      line.className = 'mb-2';
      var label = document.createElement('span');
      label.className = 'text-muted small me-1';
      label.textContent = 'malscore';
      var badge = document.createElement('span');
      badge.className = 'badge ' + badgeClass;
      badge.textContent = lite.malscore;
      line.appendChild(label);
      line.appendChild(badge);
      infoEl.appendChild(line);
    }

    var sigs = Array.isArray(lite.signatures) ? lite.signatures.slice() : [];
    if (sigs.length) {
      // most severe first; unknown severities sort last
      sigs.sort(function(a, b) { return (Number(b.severity) || 0) - (Number(a.severity) || 0); });
      var table = document.createElement('table');
      table.className = 'table table-dark table-sm table-bordered mb-0';
      var thead = document.createElement('thead');
      thead.className = 'table-secondary';
      thead.innerHTML = '<tr><th style="width:60px">sev</th><th style="width:220px">name</th><th>description</th></tr>';
      table.appendChild(thead);
      var tbody = document.createElement('tbody');
      sigs.forEach(function(sig) {
        var row = document.createElement('tr');
        row.appendChild(util.cell(sig.severity, 'font-monospace'));
        row.appendChild(util.cell(sig.name, 'font-monospace'));
        row.appendChild(util.cell(sig.description));
        tbody.appendChild(row);
      });
      table.appendChild(tbody);
      var wrap = document.createElement('div');
      wrap.className = 'table-responsive mb-2';
      wrap.appendChild(table);
      infoEl.appendChild(wrap);
    }

    // Escape hatch to the full CAPE report, in a new tab. Prefer the box's
    // CAPEv2 web UI (full styled report) when a web_url is configured; otherwise
    // fall back to the report html streamed through Lilith (unstyled, since
    // nergal serves only the fixed result files, not the report's assets) so the
    // results key is not exposed in the browser URL.
    if (box.dataset.webReportUrl) {
      var webLink = document.createElement('a');
      webLink.href = box.dataset.webReportUrl;
      webLink.target = '_blank';
      webLink.rel = 'noopener';
      webLink.className = 'btn btn-sm btn-outline-secondary';
      webLink.textContent = 'Open full CAPE report ↗';
      infoEl.appendChild(webLink);
    } else if (box.dataset.reportAvailable === '1') {
      var link = document.createElement('a');
      link.href = base + '/cape_result/reports/report.html';
      link.target = '_blank';
      link.rel = 'noopener';
      link.className = 'btn btn-sm btn-outline-secondary';
      link.textContent = 'Open detonation report ↗';
      link.title = 'Report html from nergal (unstyled — no CAPEv2 web UI configured)';
      infoEl.appendChild(link);
    }
  }

  util.getJSON(base + '/cape_results')
    .then(function(data) {

      box.dataset.reportAvailable = data.report_available ? '1' : '0';
      if (data.web_report_url) { box.dataset.webReportUrl = data.web_report_url; }
      renderInfo(data.lite);

      var shots = data.shots || [];
      statusEl.textContent = shots.length + ' screenshot' + (shots.length === 1 ? '' : 's');
      shots.forEach(function(shot) {
        var anchor = document.createElement('a');
        anchor.href = base + '/cape_result/' + shot;
        anchor.target = '_blank';
        anchor.rel = 'noopener';
        var img = document.createElement('img');
        img.src = anchor.href;
        img.loading = 'lazy';
        img.className = 'rounded border border-secondary';
        img.style.maxHeight = '160px';
        img.alt = shot;
        anchor.appendChild(img);
        shotsEl.appendChild(anchor);
      });
      if (!shots.length) {
        var none = document.createElement('span');
        none.className = 'text-muted small';
        none.textContent = 'No screenshots.';
        shotsEl.appendChild(none);
      }
    })
    .catch(function(err) {
      statusEl.textContent = err.message || 'Failed to load results';
    });
});

document.addEventListener('DOMContentLoaded', function() {
  var util     = window.LilithUtil;
  if (!document.getElementById('esc-history-body')) { return; }
  var escTable = EVENT.table;
  var escId    = EVENT.id;
  var statusBadge = util.statusBadge;

  // Escalation history — one row per recorded escalation, with the raw
  // payload behind an expando.
  function loadHistory() {
    var body     = document.getElementById('esc-history-body');
    var statusEl = document.getElementById('esc-history-status');
    util.getJSON('/api/escalation/history/' + encodeURIComponent(escTable) + '/' + encodeURIComponent(escId))
      .then(function(data) {
        var rows = data.escalations || [];
        statusEl.textContent = rows.length + ' escalation' + (rows.length === 1 ? '' : 's');
        body.innerHTML = '';
        if (data.error) {
          var err = document.createElement('span');
          err.className = 'text-warning small';
          err.textContent = data.error;
          body.appendChild(err);
          return;
        }
        if (!rows.length) {
          var none = document.createElement('span');
          none.className = 'text-muted small';
          none.textContent = 'This event has not been escalated.';
          body.appendChild(none);
          return;
        }
        var table = document.createElement('table');
        table.className = 'table table-dark table-sm table-bordered mb-0';
        var thead = document.createElement('thead');
        thead.className = 'table-secondary';
        thead.innerHTML = '<tr><th>Time</th><th>Target</th><th>Status</th><th>Requested By</th>'
          + '<th>Note</th><th>Error</th><th>Raw</th></tr>';
        table.appendChild(thead);
        var tbody = document.createElement('tbody');
        rows.forEach(function(row) {
          var rowEl = document.createElement('tr');
          rowEl.appendChild(util.cell(row.timestamp));
          // target_name is snapshotted at attempt time; a null target_id
          // alongside a name means the target has since been deleted
          var targetLabel = row.target_name || '(unknown target)';
          if (row.target_name && !row.target_id) { targetLabel += ' (deleted)'; }
          rowEl.appendChild(util.cell(targetLabel));
          var statusCell = document.createElement('td');
          statusCell.appendChild(statusBadge(row.status));
          rowEl.appendChild(statusCell);
          rowEl.appendChild(util.cell(row.requested_by));
          rowEl.appendChild(util.cell(row.note));
          var errorCell = util.cell(row.error);
          errorCell.className = row.error ? 'text-warning small' : '';
          rowEl.appendChild(errorCell);
          var rawCell = document.createElement('td');
          if (row.raw) {
            var details = document.createElement('details');
            var summary = document.createElement('summary');
            summary.className = 'text-muted small';
            summary.textContent = 'raw';
            var pre = document.createElement('pre');
            pre.className = 'small mb-0';
            pre.style.whiteSpace = 'pre-wrap';
            pre.style.maxHeight = '300px';
            pre.style.overflowY = 'auto';
            pre.textContent = JSON.stringify(row.raw, null, 2);
            details.appendChild(summary);
            details.appendChild(pre);
            rawCell.appendChild(details);
          }
          rowEl.appendChild(rawCell);
          tbody.appendChild(rowEl);
        });
        table.appendChild(tbody);
        var wrap = document.createElement('div');
        wrap.className = 'table-responsive';
        wrap.appendChild(table);
        body.appendChild(wrap);
      })
      .catch(function(err) {
        body.innerHTML = '';
        var errSpan = document.createElement('span');
        errSpan.className = 'text-warning small';
        errSpan.textContent = err.message || 'Failed to load escalations';
        body.appendChild(errSpan);
      });
  }
  loadHistory();

  // Escalate modal — target list is fetched when the modal opens so it is
  // always current.
  var modalEl = document.getElementById('escalate-modal');
  modalEl.addEventListener('show.bs.modal', function() {
    var box = document.getElementById('esc-targets');
    document.getElementById('esc-error').style.display   = 'none';
    document.getElementById('esc-results').style.display = 'none';
    box.innerHTML = '<span class="text-muted small">Loading…</span>';
    util.getJSON('/api/escalation/targets')
      .then(function(data) {
        var targets = (data.targets || []).filter(function(target) { return target.enabled; });
        box.innerHTML = '';
        if (!targets.length) {
          box.innerHTML = '<span class="text-muted small">No enabled escalation targets configured.'
            + ' Add one on the <a href="/escalation" class="text-danger">Escalation</a> page.</span>';
          return;
        }
        targets.forEach(function(target) {
          var wrap = document.createElement('div');
          wrap.className = 'form-check';
          var input = document.createElement('input');
          input.className = 'form-check-input esc-target-check';
          input.type = 'checkbox';
          input.value = target.id;
          input.id = 'esc-target-' + target.id;
          var label = document.createElement('label');
          label.className = 'form-check-label small';
          label.htmlFor = input.id;
          label.textContent = target.name + ' (' + target.type + ')' + (target.description ? ' — ' + target.description : '');
          wrap.appendChild(input);
          wrap.appendChild(label);
          box.appendChild(wrap);
        });
      })
      .catch(function(err) {
        // built as a node, not markup -- the message is whatever threw
        box.textContent = '';
        var failed = document.createElement('span');
        failed.className = 'text-warning small';
        failed.textContent = err.message || 'Failed to load targets';
        box.appendChild(failed);
      });
  });

  document.getElementById('esc-send-btn').addEventListener('click', function() {
    var errEl     = document.getElementById('esc-error');
    var resultsEl = document.getElementById('esc-results');
    errEl.style.display = 'none';
    var ids = [];
    document.querySelectorAll('.esc-target-check:checked').forEach(function(checkbox) { ids.push(checkbox.value); });
    if (!ids.length) {
      errEl.textContent = 'Select at least one target.';
      errEl.style.display = '';
      return;
    }
    var btn = this;
    btn.disabled = true;
    util.postResult('/api/escalation/escalate', {
      table:        escTable,
      id:           escId,
      target_ids:   ids,
      note:         document.getElementById('esc-note').value,
      requested_by: document.getElementById('esc-requested-by').value
    })
      .then(function(res) {
        btn.disabled = false;
        if (!res.ok || res.data.error) {
          errEl.textContent = res.data.error || 'escalation failed';
          errEl.style.display = '';
          return;
        }
        resultsEl.innerHTML = '';
        (res.data.results || []).forEach(function(result) {
          var line = document.createElement('div');
          line.appendChild(statusBadge(result.status));
          var text = document.createElement('span');
          text.className = 'ms-1';
          text.textContent = ' ' + (result.target_name || ('target #' + result.target_id))
            + (result.error ? ' — ' + result.error : '');
          line.appendChild(text);
          resultsEl.appendChild(line);
        });
        resultsEl.style.display = '';
        loadHistory();
      })
      .catch(function(err) {
        btn.disabled = false;
        errEl.textContent = err.message || 'escalation failed';
        errEl.style.display = '';
      });
  });
});

})();
