/*
 * The /cape_submit page: upload one file to a configured CAPEv2 box and show
 * what came back.
 *
 * The submission is multipart rather than JSON (it carries the file itself),
 * so it uses fetch directly with LilithUtil.unwrap rather than postResult.
 * The result table is filled from whatever the response carries even when the
 * submission was rejected, since the hashes and magic are worked out before
 * the push and are worth seeing either way.
 *
 * Requires lilith-util.js. Self-guards on its form being present.
 */
(function () {
  var form   = document.getElementById('cape-submit-form');
  if (!form) { return; }
  var btn    = document.getElementById('cape-submit-btn');
  var status = document.getElementById('cape-submit-status');
  var result = document.getElementById('cape-submit-result');

  function setStatus(cls, text) {
    status.style.display = '';
    status.className = 'small mt-3 text-' + cls;
    status.textContent = text;
  }

  function setCell(id, value) {
    document.getElementById(id).textContent = (value === undefined || value === null) ? '' : value;
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();

    var fileInput = document.getElementById('cape-file');
    if (!fileInput.files.length) { setStatus('warning', 'Pick a file to submit.'); return; }

    var data = new FormData();
    data.append('file', fileInput.files[0]);
    var server = document.getElementById('cape-server');
    if (server) { data.append('server', server.value); }
    data.append('slug', document.getElementById('cape-slug').value);

    btn.disabled = true;
    result.style.display = 'none';
    setStatus('muted', 'Submitting ' + fileInput.files[0].name + ' …');

    fetch('/api/cape_submit/submit', { method: 'POST', body: data })
      .then(window.LilithUtil.unwrap)
      .then(function (res) {
        btn.disabled = false;
        var body = res.data || {};
        if (res.ok && body.status === 'ok') {
          setStatus('success', 'Submitted as ' + body.name);
        } else {
          setStatus('danger', 'Failed: ' + (body.error || ('HTTP ' + (body.http_status || 'error'))));
        }
        // show whatever facts came back, even on a rejected submission
        setCell('cape-res-status', body.status);
        setCell('cape-res-server', body.server);
        setCell('cape-res-name',   body.name);
        setCell('cape-res-http',   body.http_status);
        setCell('cape-res-magic',  body.magic);
        setCell('cape-res-size',   body.size);
        setCell('cape-res-md5',    body.md5);
        setCell('cape-res-sha1',   body.sha1);
        setCell('cape-res-sha256', body.sha256);
        if (body.name || body.sha256) { result.style.display = ''; }
      })
      .catch(function (err) {
        btn.disabled = false;
        setStatus('danger', 'Request failed: ' + err);
      });
  });
})();
