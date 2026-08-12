/*
 * The navbar lookup tools and the modals they drive: IP info, Domain info,
 * HTTPS info and Mail info (SPF / DMARC / DKIM), plus the "Go to Event" jump.
 *
 * The modal markup lives in the layout (partials/_modal). showIpInfo and
 * showDomainInfo are exposed globally because the search results and the event
 * view trigger them from their own "?" buttons.
 *
 * Requires lilith-util.js.
 */
(function () {
  var util = window.LilithUtil;

  // Every lookup modal is the same shape: a loading line, a hidden content
  // block, and a title rewritten to whatever is being looked up. This drives
  // that sequence and hands the parsed response to a fill function.
  //
  // A non-2xx goes to onError with the server's message rather than to fill:
  // the endpoints answer a bad or failed lookup with a 4xx/5xx carrying
  // { error }, and handing that to fill would render an empty-looking success.
  function runLookup(prefix, title, url, fill, onError) {
    document.getElementById(prefix + '-modal-title').textContent = title;
    document.getElementById(prefix + '-loading').style.display = '';
    document.getElementById(prefix + '-content').style.display = 'none';
    util.getJSON(url)
      .then(function (data) { fill(data); })
      .catch(function (error) { onError(error && error.message ? error.message : 'Error fetching data'); })
      .finally(function () {
        document.getElementById(prefix + '-loading').style.display = 'none';
        document.getElementById(prefix + '-content').style.display = '';
      });
  }

  // Show or hide a warning line, setting its text when there is one.
  function setError(el, message) {
    if (message) { el.textContent = message; el.style.display = ''; }
    else { el.style.display = 'none'; }
  }

  // ---- Shodan ----------------------------------------------------------
  //
  // Only reached when enable_shodan is set; see showIpInfo below.

  // The tags that change what an alert means, colored so they are not lost in a
  // row of grey chips. Everything else Shodan tags a host with is descriptive
  // (cloud, cdn, starttls, ...) and stays grey.
  var SHODAN_TAG_CLASS = {
    compromised: 'bg-danger', malware: 'bg-danger', c2: 'bg-danger', doublepulsar: 'bg-danger',
    honeypot: 'bg-warning text-dark', scanner: 'bg-warning text-dark', tor: 'bg-warning text-dark',
    vpn: 'bg-warning text-dark', proxy: 'bg-warning text-dark', ics: 'bg-warning text-dark',
    'self-signed': 'bg-warning text-dark', 'eol-os': 'bg-warning text-dark',
    'eol-product': 'bg-warning text-dark', database: 'bg-warning text-dark'
  };

  // Append one badge to a container. Unlike util.appendBadge this takes the
  // class rather than a boolean, since these are not pass/fail.
  function chip(container, text, cssClass, title) {
    var chipEl = document.createElement('span');
    chipEl.className = 'badge me-1 mb-1 ' + (cssClass || 'bg-secondary');
    chipEl.textContent = text;
    if (title) { chipEl.title = title; }
    container.appendChild(chipEl);
    return chipEl;
  }

  // One CVE as a chip linking to its NVD entry, colored by severity and
  // carrying the detail that will not fit on it as its tooltip.
  //
  // Chips rather than a table because the count varies wildly — a long-lived
  // Apache host can carry over a hundred CVEs, and a hundred table rows would
  // be the whole modal.
  //
  // The score and summary come from Shodan on the API tier and from the CVEDB
  // cache otherwise; kev, ransomware, and epss come from the CVEDB cache alone
  // and are simply absent until `lilith cvedb_cache` has run. A CVE on the
  // CISA KEV list is red whatever its score — known-exploited outranks any
  // unexploited severity — and says KEV on the chip; EPSS and known ransomware
  // use go in the tooltip with the summary.
  function vulnChip(container, vuln) {
    var cssClass = 'bg-secondary';
    if (vuln.kev)                                { cssClass = 'bg-danger'; }
    else if (vuln.cvss !== '' && vuln.cvss >= 9) { cssClass = 'bg-danger'; }
    else if (vuln.cvss !== '' && vuln.cvss >= 7) { cssClass = 'bg-warning text-dark'; }

    var label = vuln.cve + (vuln.cvss !== '' ? ' ' + vuln.cvss : '')
      + (vuln.kev ? ' KEV' : '') + (vuln.verified ? ' ✓' : '');
    var linkEl = document.createElement('a');
    linkEl.className = 'badge me-1 mb-1 text-decoration-none ' + cssClass;
    linkEl.href = 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(vuln.cve);
    linkEl.target = '_blank';
    linkEl.rel = 'noopener noreferrer';
    linkEl.textContent = label;
    var tooltip = [];
    if (vuln.epss !== undefined && vuln.epss !== null && vuln.epss !== '') { tooltip.push('EPSS ' + vuln.epss); }
    if (vuln.ransomware) { tooltip.push('known ransomware use'); }
    if (vuln.summary)    { tooltip.push(vuln.summary); }
    if (tooltip.length)  { linkEl.title = tooltip.join(' — '); }
    container.appendChild(linkEl);
  }

  // One service block: the port as a heading, whatever the banner identified
  // under it, and the raw banner text itself.
  function serviceBlock(container, service) {
    var block = document.createElement('div');
    block.className = 'border-start border-secondary ps-2 mt-2';

    // "443/tcp — nginx 1.18.0", falling back to the crawler module that found
    // it when Shodan could not name the product.
    var name = [service.product, service.version].filter(Boolean).join(' ') || service.module;
    var headingEl = document.createElement('div');
    headingEl.className = 'small fw-semibold';
    headingEl.textContent = service.port + '/' + (service.transport || 'tcp') + (name ? ' — ' + name : '');
    block.appendChild(headingEl);

    var table = document.createElement('table');
    table.className = 'table table-dark table-sm table-borderless mb-0 mt-1';
    var tbody = document.createElement('tbody');
    table.appendChild(tbody);

    var http = service.http || {}, ssl = service.ssl || {}, ssh = service.ssh || {};
    util.kvRow(tbody, 'HTTP title', http.title);
    util.kvRow(tbody, 'HTTP server', http.server);
    util.kvRow(tbody, 'HTTP status', http.status);
    util.kvRow(tbody, 'WAF', http.waf);
    util.kvRow(tbody, 'Components', http.components);
    util.kvRow(tbody, 'Favicon hash', http.favicon_hash);
    util.kvRow(tbody, 'TLS versions', ssl.versions);
    util.kvRow(tbody, 'Cipher', ssl.cipher);
    util.kvRow(tbody, 'Certificate', ssl.cert_subject);
    util.kvRow(tbody, 'Issuer', ssl.cert_issuer);
    util.kvRow(tbody, 'Cert expires', ssl.cert_expires
      ? (ssl.cert_expires + (ssl.cert_expired ? ' (EXPIRED)' : '')) : undefined,
      ssl.cert_expired ? 'text-warning' : '');
    util.kvRow(tbody, 'Cert serial', ssl.cert_serial);
    util.kvRow(tbody, 'Cert SHA-256', ssl.cert_fingerprint);
    util.kvRow(tbody, 'JARM', ssl.jarm);
    util.kvRow(tbody, 'JA3S', ssl.ja3s);
    util.kvRow(tbody, 'SSH key type', ssh.type);
    util.kvRow(tbody, 'SSH fingerprint', ssh.fingerprint);
    util.kvRow(tbody, 'HASSH', ssh.hassh);
    util.kvRow(tbody, 'CPE', service.cpes);
    util.kvRow(tbody, 'CVEs', service.vulns);
    util.kvRow(tbody, 'Seen', service.timestamp);
    if (tbody.childNodes.length) { block.appendChild(table); }

    if (service.banner) {
      var bannerEl = document.createElement('pre');
      bannerEl.className = 'small mt-1 mb-0';
      bannerEl.style.whiteSpace = 'pre-wrap';
      bannerEl.style.maxHeight = '150px';
      bannerEl.style.overflowY = 'auto';
      bannerEl.textContent = service.banner;
      block.appendChild(bannerEl);
    }

    container.appendChild(block);
  }

  // Fill the IP info modal's Shodan section from an /api/ipinfo response, and
  // decide whether it is shown at all.
  //
  // The section stays hidden when the feature is off, which is the only case
  // where the response carries neither a result nor an error. An address that
  // was deliberately not looked up (private, reserved) and one Shodan simply
  // has nothing on both show the section with a note saying which, since "no
  // data" and "not asked" mean different things to whoever is triaging.
  function fillShodan(data) {
    var shodan = data.shodan || {};
    var section = document.getElementById('ipinfo-shodan-section');
    var tagsEl = document.getElementById('ipinfo-shodan-tags');
    var portsEl = document.getElementById('ipinfo-shodan-ports');
    var summaryEl = document.getElementById('ipinfo-shodan-summary');
    var vulnsEl = document.getElementById('ipinfo-shodan-vulns');
    var servicesEl = document.getElementById('ipinfo-shodan-services');
    var linkEl = document.getElementById('ipinfo-shodan-link');
    var noteEl = document.getElementById('ipinfo-shodan-note');

    tagsEl.innerHTML = ''; portsEl.innerHTML = ''; summaryEl.innerHTML = '';
    vulnsEl.innerHTML = ''; servicesEl.innerHTML = '';
    setError(document.getElementById('ipinfo-shodan-error'), data.shodan_error);
    document.getElementById('ipinfo-shodan-vulns-wrap').style.display = 'none';
    linkEl.style.display = 'none';
    noteEl.style.display = 'none';

    section.style.display = (shodan.source || shodan.skipped || data.shodan_error) ? '' : 'none';
    if (shodan.skipped) {
      noteEl.textContent = 'not queried — ' + shodan.skipped;
      noteEl.style.display = '';
      return;
    }
    if (!shodan.source) { return; }

    linkEl.href = shodan.url;
    linkEl.style.display = '';

    var ports = shodan.ports || [];
    if (!ports.length && !(shodan.services || []).length && !(shodan.tags || []).length) {
      noteEl.textContent = 'no data for this address';
      noteEl.style.display = '';
    }

    (shodan.tags || []).forEach(function (tag) { chip(tagsEl, tag, SHODAN_TAG_CLASS[tag]); });
    ports.forEach(function (port) { chip(portsEl, port, 'bg-secondary'); });

    // Whether this was served from the cache matters for the same reason
    // "Last seen" does — it says how old the answer on screen actually is.
    util.kvRow(summaryEl, 'Source',
      (shodan.source === 'api' ? 'Shodan host API' : 'InternetDB (no API key)')
        + (shodan.cached ? ' — cached' : ''));
    util.kvRow(summaryEl, 'Last seen', shodan.last_update);
    util.kvRow(summaryEl, 'OS', shodan.os);
    util.kvRow(summaryEl, 'Hostnames', shodan.hostnames);
    util.kvRow(summaryEl, 'Domains', shodan.domains);
    util.kvRow(summaryEl, 'CPE', shodan.cpes);

    var vulns = shodan.vulns || [];
    if (vulns.length) {
      document.getElementById('ipinfo-shodan-vulns-wrap').style.display = '';
      document.getElementById('ipinfo-shodan-vulns-label').textContent =
        'Vulnerabilities (' + vulns.length + ')';
      vulns.forEach(function (vuln) { vulnChip(vulnsEl, vuln); });
    }

    (shodan.services || []).forEach(function (service) { serviceBlock(servicesEl, service); });
  }

  document.addEventListener('DOMContentLoaded', function () {

    // ---- Go to Event -------------------------------------------------------
    document.getElementById('lookup-go-btn').addEventListener('click', function () {
      var lookupValue = document.getElementById('lookup-id').value.trim();
      var table = document.getElementById('lookup-table').value;
      var errEl = document.getElementById('lookup-error');
      if (!lookupValue) { errEl.style.display = ''; return; }
      errEl.style.display = 'none';
      if (/^\d+$/.test(lookupValue)) {
        window.location.href = '/event/' + encodeURIComponent(table) + '/' + encodeURIComponent(lookupValue);
      } else {
        window.location.href = '/search?search=1&table=' + encodeURIComponent(table)
                             + '&event_id=' + encodeURIComponent(lookupValue);
      }
    });
    document.getElementById('lookup-id').addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { document.getElementById('lookup-go-btn').click(); }
    });

    // ---- IP Info -----------------------------------------------------------
    // One modal and one lookup used everywhere (navbar, search, event).
    var ipInfoModal = new bootstrap.Modal(document.getElementById('ipinfo-modal'));
    window.showIpInfo = function (ip) {
      ipInfoModal.show();
      runLookup('ipinfo', ip, '/api/ipinfo/' + encodeURIComponent(ip), function (data) {
        document.getElementById('ipinfo-rdns').textContent     = data.rdns || '(none)';
        document.getElementById('ipinfo-ptr-name').textContent = data.ptr_name ? 'queried: ' + data.ptr_name : '';
        setError(document.getElementById('ipinfo-rdns-error'), data.rdns_error);

        var geoSection = document.getElementById('ipinfo-geo-section');
        var geoBody    = document.getElementById('ipinfo-geo');
        var geoKeys    = data.geo ? Object.keys(data.geo).sort() : [];
        geoBody.innerHTML = '';
        geoKeys.forEach(function (key) {
          var row = document.createElement('tr');
          var headerCell = document.createElement('th');
          headerCell.className = 'text-muted fw-normal ps-0';
          headerCell.style.width = '45%';
          headerCell.textContent = key;
          var valueCell = document.createElement('td');
          valueCell.className = 'font-monospace';
          valueCell.textContent = data.geo[key];
          row.appendChild(headerCell); row.appendChild(valueCell);
          geoBody.appendChild(row);
        });
        setError(document.getElementById('ipinfo-geo-error'), data.geo_error);
        geoSection.style.display = (geoKeys.length || data.geo_error) ? '' : 'none';

        fillShodan(data);

        setError(document.getElementById('ipinfo-error'), null);
        document.getElementById('ipinfo-whois').textContent = data.whois || '(none)';
      }, function (message) {
        setError(document.getElementById('ipinfo-error'), message);
        document.getElementById('ipinfo-rdns').textContent = '';
        document.getElementById('ipinfo-ptr-name').textContent = '';
        document.getElementById('ipinfo-geo-section').style.display = 'none';
        document.getElementById('ipinfo-shodan-section').style.display = 'none';
        document.getElementById('ipinfo-whois').textContent = '';
      });
    };
    document.getElementById('nav-ip-go-btn').addEventListener('click', function () {
      var ip    = document.getElementById('nav-ip-input').value.trim();
      var errEl = document.getElementById('nav-ip-error');
      if (!ip || !/^[0-9a-fA-F:.]+$/.test(ip)) { errEl.style.display = ''; return; }
      errEl.style.display = 'none';
      window.showIpInfo(ip);
    });
    document.getElementById('nav-ip-input').addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { document.getElementById('nav-ip-go-btn').click(); }
    });

    // ---- Domain Info -------------------------------------------------------
    // One modal and one lookup used everywhere (navbar, event).
    var navDomainModal = new bootstrap.Modal(document.getElementById('nav-domaininfo-modal'));
    window.showDomainInfo = function (domain) {
      navDomainModal.show();
      runLookup('nav-domaininfo', domain, '/api/domaininfo/' + encodeURIComponent(domain), function (data) {
        var dnsEl = document.getElementById('nav-domaininfo-dns');
        if (data.dns && Object.keys(data.dns).length) {
          var typeOrder = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR'];
          var recordTypes = Object.keys(data.dns).sort(function (typeA, typeB) {
            // an unlisted type sorts after every listed one
            var rankA = typeOrder.indexOf(typeA);
            var rankB = typeOrder.indexOf(typeB);
            if (rankA === -1) { rankA = 999; }
            if (rankB === -1) { rankB = 999; }
            return rankA - rankB;
          });
          // Built as nodes rather than markup: record values are DNS data of an
          // arbitrary looked-up domain (TXT especially can carry anything), and
          // textContent takes them as text whatever they hold.
          dnsEl.textContent = '';
          recordTypes.forEach(function (type) {
            data.dns[type].forEach(function (recordValue) {
              var line = document.createElement('div');
              var typeEl = document.createElement('strong');
              typeEl.textContent = type;
              line.appendChild(typeEl);
              line.appendChild(document.createTextNode(' ' + recordValue));
              dnsEl.appendChild(line);
            });
          });
        } else {
          dnsEl.textContent = '(none)';
        }
        setError(document.getElementById('nav-domaininfo-dns-error'), data.dns_error);
        document.getElementById('nav-domaininfo-whois-label').textContent =
          (data.whois_domain && data.whois_domain !== domain)
            ? 'WHOIS (' + data.whois_domain + ')' : 'WHOIS';
        document.getElementById('nav-domaininfo-whois').textContent = data.whois || '(none)';

        var dnstracerSection = document.getElementById('nav-domaininfo-dnstracer-section');
        if (data.dnstracer || data.dnstracer_error) {
          dnstracerSection.style.display = '';
          document.getElementById('nav-domaininfo-dnstracer').textContent = data.dnstracer || '';
          setError(document.getElementById('nav-domaininfo-dnstracer-error'), data.dnstracer_error);
        } else {
          dnstracerSection.style.display = 'none';
        }
        setError(document.getElementById('nav-domaininfo-error'), null);
      }, function (message) {
        setError(document.getElementById('nav-domaininfo-error'), message);
        document.getElementById('nav-domaininfo-dns').textContent = '';
        document.getElementById('nav-domaininfo-whois').textContent = '';
        document.getElementById('nav-domaininfo-dnstracer-section').style.display = 'none';
      });
    };
    document.getElementById('nav-domain-go-btn').addEventListener('click', function () {
      var domain = document.getElementById('nav-domain-input').value.trim();
      var errEl  = document.getElementById('nav-domain-error');
      if (!domain || !/^[A-Za-z0-9._-]+$/.test(domain)) { errEl.style.display = ''; return; }
      errEl.style.display = 'none';
      window.showDomainInfo(domain);
    });
    document.getElementById('nav-domain-input').addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { document.getElementById('nav-domain-go-btn').click(); }
    });

    // ---- HTTPS Info --------------------------------------------------------
    var httpsModal = new bootstrap.Modal(document.getElementById('httpsinfo-modal'));
    function showHttpsInfo(domain, port) {
      httpsModal.show();
      var url = '/api/httpsinfo/' + encodeURIComponent(domain) + '?port=' + encodeURIComponent(port);
      runLookup('httpsinfo', 'HTTPS — ' + domain + ':' + port, url, function (data) {
        var summaryEl = document.getElementById('httpsinfo-summary');
        var httpEl    = document.getElementById('httpsinfo-http');
        var certEl    = document.getElementById('httpsinfo-cert');
        var certWrap  = document.getElementById('httpsinfo-cert-wrap');
        summaryEl.innerHTML = ''; httpEl.innerHTML = ''; certEl.innerHTML = '';
        setError(document.getElementById('httpsinfo-error'), data.error);

        if (data.valid !== undefined)   { util.appendBadge(summaryEl, data.valid ? 'Certificate valid' : 'Certificate INVALID', !!data.valid); }
        if (data.expired !== undefined) { util.appendBadge(summaryEl, data.expired ? 'EXPIRED' : 'Not expired', !data.expired); }

        util.kvRow(httpEl, 'HTTP status', (data.http_status !== undefined ? data.http_status : '(no response)')
          + (data.http_reason ? ' ' + data.http_reason : ''));
        util.kvRow(httpEl, 'Redirects to', data.redirect_to);
        util.kvRow(httpEl, 'TCP connect',   data.tcp_connect_ms   !== undefined ? data.tcp_connect_ms + ' ms'   : undefined);
        util.kvRow(httpEl, 'TLS handshake', data.tls_handshake_ms !== undefined ? data.tls_handshake_ms + ' ms' : undefined);
        util.kvRow(httpEl, 'Response',      data.response_ms      !== undefined ? data.response_ms + ' ms'      : undefined);
        util.kvRow(httpEl, 'Total',         data.total_ms         !== undefined ? data.total_ms + ' ms'         : undefined);
        if (data.timed_out)   { util.kvRow(httpEl, 'Note', 'timed out (5s limit)', 'text-warning'); }
        if (data.read_capped) { util.kvRow(httpEl, 'Note', 'response truncated at 512 KB', 'text-warning'); }

        var cert = data.cert || {};
        certWrap.style.display = Object.keys(cert).length ? '' : 'none';
        util.kvRow(certEl, 'Common name', cert.cn);
        util.kvRow(certEl, 'Subject', cert.subject);
        util.kvRow(certEl, 'Issuer', cert.issuer);
        util.kvRow(certEl, 'SANs', cert.sans);
        util.kvRow(certEl, 'Not before', cert.not_before);
        util.kvRow(certEl, 'Not after', cert.not_after);
        util.kvRow(certEl, 'Serial', cert.serial);
        util.kvRow(certEl, 'Version', cert.version ? ('v' + cert.version) : undefined);
        util.kvRow(certEl, 'Signature alg', cert.sig_alg);
        util.kvRow(certEl, 'SHA-1 fingerprint', cert.fp_sha1);
        util.kvRow(certEl, 'SHA-256 fingerprint', cert.fp_sha256);
        if (data.valid === 0 && data.valid_error) { util.kvRow(certEl, 'Validation error', data.valid_error, 'text-warning'); }
      }, function (message) {
        setError(document.getElementById('httpsinfo-error'), message);
      });
    }
    document.getElementById('nav-https-btn').addEventListener('click', function () {
      var domain = document.getElementById('nav-domain-input').value.trim();
      var port   = document.getElementById('nav-https-port').value.trim() || '443';
      var errEl  = document.getElementById('nav-domain-error');
      if (!/^[A-Za-z0-9._-]+$/.test(domain)) { errEl.textContent = 'Please enter a valid domain.'; errEl.style.display = ''; return; }
      if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) { errEl.textContent = 'Please enter a valid port.'; errEl.style.display = ''; return; }
      errEl.style.display = 'none';
      showHttpsInfo(domain, port);
    });

    // ---- Mail Info (SPF / DMARC / DKIM) ------------------------------------
    var mailModal = new bootstrap.Modal(document.getElementById('mailinfo-modal'));
    function spfBadgeClass(code) {
      return ({ pass: 'bg-success', fail: 'bg-danger', softfail: 'bg-warning text-dark',
                neutral: 'bg-secondary', none: 'bg-secondary',
                permerror: 'bg-danger', temperror: 'bg-warning text-dark' })[code] || 'bg-secondary';
    }
    function dmarcBadgeClass(policy) {
      return ({ reject: 'bg-success', quarantine: 'bg-warning text-dark', none: 'bg-secondary' })[policy] || 'bg-secondary';
    }
    function showMailInfo(domain, ip, selector) {
      mailModal.show();
      var params = new URLSearchParams();
      if (ip)       { params.set('ip', ip); }
      if (selector) { params.set('selector', selector); }
      var query = params.toString();
      var url = '/api/mailinfo/' + encodeURIComponent(domain) + (query ? '?' + query : '');
      runLookup('mailinfo', 'Mail Info — ' + domain, url, function (data) {
        setError(document.getElementById('mailinfo-error'), data.error);

        // --- MX ---
        var mx = data.mx || [];
        util.badge(document.getElementById('mailinfo-mx-badge'),
          mx.length ? (mx.length + ' record' + (mx.length === 1 ? '' : 's')) : 'none', 'bg-secondary');
        var mxBody = document.getElementById('mailinfo-mx'); mxBody.innerHTML = '';
        if (mx.length) { mx.forEach(function (mxRecord) { util.kvRow(mxBody, mxRecord.preference, mxRecord.exchange); }); }
        else { util.kvRow(mxBody, 'MX', '(none)'); }

        // --- SPF ---
        var spf = data.spf || {}, spfSummary = spf.summary || {};
        util.badge(document.getElementById('mailinfo-spf-badge'),
          spf.result ? String(spf.result).toUpperCase() : (spfSummary.all ? spfSummary.all : null),
          spf.result ? spfBadgeClass(spf.result) : 'bg-secondary');
        var spfBody = document.getElementById('mailinfo-spf'); spfBody.innerHTML = '';
        util.kvRow(spfBody, 'Record', spf.record || '(none)');
        util.kvRow(spfBody, 'Default policy', spfSummary.all);
        util.kvRow(spfBody, 'DNS lookups', spfSummary.dns_lookups);
        util.kvRow(spfBody, 'Mechanisms', spfSummary.mechanisms);
        util.kvRow(spfBody, 'Modifiers', spfSummary.modifiers);
        util.kvRow(spfBody, 'Evaluated IP', spf.ip);
        util.kvRow(spfBody, 'Identity', spf.identity);
        util.kvRow(spfBody, 'Result', spf.result);
        util.kvRow(spfBody, 'Explanation', spf.explanation);

        // --- DMARC ---
        var dmarc = data.dmarc || {};
        util.badge(document.getElementById('mailinfo-dmarc-badge'),
          dmarc.p ? ('p=' + dmarc.p) : (dmarc.record ? null : 'no DMARC'),
          dmarc.p ? dmarcBadgeClass(dmarc.p) : 'bg-danger');
        var dmarcBody = document.getElementById('mailinfo-dmarc'); dmarcBody.innerHTML = '';
        util.kvRow(dmarcBody, 'Record', dmarc.record || dmarc.note || '(none)');
        util.kvRow(dmarcBody, 'Found at', dmarc.found_at);
        util.kvRow(dmarcBody, 'Policy (p)', dmarc.p);
        util.kvRow(dmarcBody, 'Subdomain policy (sp)', dmarc.sp);
        util.kvRow(dmarcBody, 'Percent (pct)', dmarc.pct);
        util.kvRow(dmarcBody, 'Aggregate reports (rua)', dmarc.rua);
        util.kvRow(dmarcBody, 'Forensic reports (ruf)', dmarc.ruf);
        util.kvRow(dmarcBody, 'DKIM alignment (adkim)', dmarc.adkim);
        util.kvRow(dmarcBody, 'SPF alignment (aspf)', dmarc.aspf);
        util.kvRow(dmarcBody, 'Failure options (fo)', dmarc.fo);

        // --- DKIM ---
        var dkim = data.dkim || {}, keys = dkim.keys || [];
        util.badge(document.getElementById('mailinfo-dkim-badge'),
          keys.length ? (keys.length + ' key' + (keys.length === 1 ? '' : 's')) : 'none found',
          keys.length ? 'bg-success' : 'bg-secondary');
        var dkimBody = document.getElementById('mailinfo-dkim'); dkimBody.innerHTML = '';
        if (dkim.probed) {
          var noteEl = document.createElement('div');
          noteEl.className = 'text-muted small mb-1';
          noteEl.textContent = 'probed common selectors' + (keys.length ? '' : ' — none found; supply a selector if known');
          dkimBody.appendChild(noteEl);
        }
        keys.forEach(function (dkimKey) {
          var table = document.createElement('table');
          table.className = 'table table-dark table-sm table-borderless mb-2';
          var tbody = document.createElement('tbody');
          table.appendChild(tbody);
          util.kvRow(tbody, 'Selector', dkimKey.selector);
          util.kvRow(tbody, 'Key type', dkimKey.key_type);
          util.kvRow(tbody, 'Key size', dkimKey.key_bits ? (dkimKey.key_bits + ' bits') : undefined);
          util.kvRow(tbody, 'Revoked', dkimKey.revoked ? 'yes' : undefined, dkimKey.revoked ? 'text-warning' : '');
          util.kvRow(tbody, 'Testing', dkimKey.testing ? 'yes' : undefined);
          util.kvRow(tbody, 'Hash algorithms', dkimKey.hash_algorithms);
          util.kvRow(tbody, 'Service types', dkimKey.service_types);
          util.kvRow(tbody, 'Granularity', dkimKey.granularity);
          util.kvRow(tbody, 'Notes', dkimKey.notes);
          util.kvRow(tbody, 'Record', dkimKey.record);
          dkimBody.appendChild(table);
        });
        if (!keys.length && dkim.note && !dkim.probed) {
          var fallbackNote = document.createElement('div');
          fallbackNote.className = 'text-muted small';
          fallbackNote.textContent = dkim.note;
          dkimBody.appendChild(fallbackNote);
        }
      }, function (message) {
        setError(document.getElementById('mailinfo-error'), message);
      });
    }
    document.getElementById('nav-mail-btn').addEventListener('click', function () {
      var domain   = document.getElementById('nav-domain-input').value.trim();
      var ip       = document.getElementById('nav-mail-ip').value.trim();
      var selector = document.getElementById('nav-mail-selector').value.trim();
      var errEl    = document.getElementById('nav-domain-error');
      if (!/^[A-Za-z0-9._-]+$/.test(domain)) { errEl.textContent = 'Please enter a valid domain.'; errEl.style.display = ''; return; }
      if (ip !== '' && !/^[0-9a-fA-F:.]+$/.test(ip)) {
        errEl.textContent = 'Please enter a valid IP for the SPF eval, or leave it blank.'; errEl.style.display = ''; return;
      }
      if (selector !== '' && !/^[A-Za-z0-9._-]+$/.test(selector)) {
        errEl.textContent = 'Please enter a valid DKIM selector, or leave it blank to probe.'; errEl.style.display = ''; return;
      }
      errEl.style.display = 'none';
      showMailInfo(domain, ip, selector);
    });

  });
})();
