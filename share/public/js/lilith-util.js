/*
 * Small helpers shared by the Lilith pages and the other /js modules.
 *
 * These were previously copy pasted into the inline <script> of each template —
 * the JSON fetch/unwrap dance, the base64 download, the key/value detail row,
 * and the number/size/time formatters all existed in three or four places.
 *
 * Everything hangs off window.LilithUtil.
 */
(function () {

  // ---- formatting ----------------------------------------------------------

  function pad2(value) { return (value < 10 ? '0' : '') + value; }

  // epoch seconds -> 'YYYY-MM-DD HH:MM:SS' in the browser's local timezone
  function fmtTime(epoch) {
    if (!epoch) { return ''; }
    var date = new Date(epoch * 1000);
    return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate())
      + ' ' + pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
  }

  // byte count -> '1.5 MB'; binary units, so it steps at 1024
  function fmtSize(bytes) {
    if (bytes == null || bytes === '') { return ''; }
    var units = ['B', 'KB', 'MB', 'GB', 'TB'], unitIndex = 0;
    bytes = Number(bytes);
    while (bytes >= 1024 && unitIndex < units.length - 1) { bytes /= 1024; unitIndex++; }
    return (unitIndex === 0 ? bytes : bytes.toFixed(1)) + ' ' + units[unitIndex];
  }

  // compact number for axis ticks / large measures: 1500 -> 1.5K. Decimal units,
  // unlike fmtSize, since this labels counts rather than bytes.
  function fmtNum(value) {
    value = Number(value) || 0;
    var units = ['', 'K', 'M', 'G', 'T'], unitIndex = 0;
    while (Math.abs(value) >= 1000 && unitIndex < units.length - 1) { value /= 1000; unitIndex++; }
    return (unitIndex === 0 ? value : value.toFixed(value < 10 ? 1 : 0)) + units[unitIndex];
  }

  // two letter country code -> its flag emoji, '' when not a country code
  function flagFor(countryCode) {
    if (!/^[A-Za-z]{2}$/.test(countryCode)) { return ''; }
    return String.fromCodePoint.apply(null, countryCode.toUpperCase().split('').map(
      function (letter) { return 0x1F1E6 + letter.charCodeAt(0) - 65; }));
  }

  // ---- DOM -----------------------------------------------------------------

  // a <td> carrying text (never markup — textContent escapes)
  function cell(text, cssClass) {
    var cellEl = document.createElement('td');
    cellEl.textContent = (text == null ? '' : text);
    if (cssClass) { cellEl.className = cssClass; }
    return cellEl;
  }

  // One label/value row of a detail table. Skips blank values entirely, so
  // callers can list every possible field and let the absent ones drop out.
  function kvRow(tbody, label, value, cssClass) {
    if (value === undefined || value === null || value === '') { return; }
    var row = document.createElement('tr');
    var headerCell = document.createElement('th');
    headerCell.className = 'text-muted fw-normal ps-0';
    headerCell.style.width = '170px';
    headerCell.style.whiteSpace = 'nowrap';
    headerCell.textContent = label;
    var valueCell = document.createElement('td');
    valueCell.className = 'font-monospace small' + (cssClass ? (' ' + cssClass) : '');
    valueCell.style.wordBreak = 'break-all';
    valueCell.textContent = Array.isArray(value) ? value.join(', ') : value;
    row.appendChild(headerCell);
    row.appendChild(valueCell);
    tbody.appendChild(row);
  }

  // Replace a container's contents with a single badge; blank text clears it.
  function badge(container, text, cssClass) {
    container.innerHTML = '';
    if (text === undefined || text === null || text === '') { return; }
    var badgeEl = document.createElement('span');
    badgeEl.className = 'badge ' + cssClass;
    badgeEl.textContent = text;
    container.appendChild(badgeEl);
  }

  // Append a badge without clearing, for the summary lines that stack several.
  function appendBadge(container, text, ok) {
    var badgeEl = document.createElement('span');
    badgeEl.className = 'badge me-2 ' + (ok ? 'bg-success' : 'bg-danger');
    badgeEl.textContent = text;
    container.appendChild(badgeEl);
  }

  // The sent/failed/pending badge used by the escalation views.
  function statusBadge(status) {
    var badgeClass = { sent: 'bg-success', failed: 'bg-danger', pending: 'bg-secondary' }[status] || 'bg-secondary';
    var badgeEl = document.createElement('span');
    badgeEl.className = 'badge ' + badgeClass;
    badgeEl.textContent = status;
    return badgeEl;
  }

  // The inline "saved / failed" line above the management tables.
  function showStatus(statusEl, message, succeeded) {
    if (!statusEl) { return; }
    statusEl.textContent = message;
    statusEl.className = 'small mb-2 ' + (succeeded ? 'text-success' : 'text-warning');
    statusEl.style.display = '';
  }

  // ---- fetch ---------------------------------------------------------------
  //
  // Two shapes, because both are wanted: getJSON/postJSON reject on a non-2xx
  // (the caller has a .catch that shows the message), while unwrap/postResult
  // resolve with { ok, data } (the caller renders the server's error into the
  // page rather than treating it as an exception).

  // The fetch options for a JSON POST body.
  function jsonPost(body) {
    return {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    };
  }

  // Response -> its parsed body, throwing the server's error message on a
  // non-2xx. Shared by getJSON and postJSON.
  function throwOnError(response) {
    return response.json().then(function (data) {
      if (!response.ok) { throw new Error(data && data.error ? data.error : ('HTTP ' + response.status)); }
      return data;
    });
  }

  // GET JSON, rejecting with the server's error message on a non-2xx.
  function getJSON(url) { return fetch(url).then(throwOnError); }

  // POST JSON, rejecting with the server's error message on a non-2xx.
  function postJSON(url, body) { return fetch(url, jsonPost(body)).then(throwOnError); }

  // Turn a Response into { ok, data }, for the callers that render the server's
  // error into the page instead of throwing. Use as `.then(LilithUtil.unwrap)`.
  function unwrap(response) {
    return response.json().then(function (data) { return { ok: response.ok, data: data }; });
  }

  // POST JSON and resolve with { ok, data } rather than rejecting.
  function postResult(url, body) { return fetch(url, jsonPost(body)).then(unwrap); }

  // ---- misc ----------------------------------------------------------------

  // Find an entry whose `key` matches `value`, comparing as strings since ids
  // and the like arrive both as numbers and as strings.
  function findBy(list, key, value) {
    for (var index = 0; index < (list || []).length; index++) {
      if (String(list[index][key]) === String(value)) { return list[index]; }
    }
    return null;
  }

  // The common case: find an entry by its id.
  function findById(list, id) { return findBy(list, 'id', id); }

  // Hand the browser a generated file. `data` is a string or a Uint8Array.
  // The object URL is revoked on the next tick rather than immediately: the
  // click only queues the download, and revoking in the same turn can pull the
  // blob out from under a browser that has not started reading it yet.
  function downloadBlob(data, filename, type) {
    var blob = new Blob([data], { type: type || 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var downloadLink = document.createElement('a');
    downloadLink.href = url;
    downloadLink.download = filename;
    downloadLink.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  // Same, for a base64 payload carried in a data attribute. The content type may
  // arrive with parameters attached (charset), which Blob does not want.
  function downloadBase64(base64, filename, type) {
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    var cleanType = (type || '').split(';')[0].trim() || 'application/octet-stream';
    downloadBlob(bytes, filename, cleanType);
  }

  window.LilithUtil = {
    pad2: pad2, fmtTime: fmtTime, fmtSize: fmtSize, fmtNum: fmtNum, flagFor: flagFor,
    cell: cell, kvRow: kvRow, badge: badge, appendBadge: appendBadge,
    statusBadge: statusBadge, showStatus: showStatus,
    getJSON: getJSON, postJSON: postJSON, unwrap: unwrap, postResult: postResult,
    findById: findById, findBy: findBy,
    downloadBlob: downloadBlob, downloadBase64: downloadBase64
  };
})();
