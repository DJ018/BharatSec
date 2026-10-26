/* BharatSec scan report.
   /report?scan=pub_…   free scan by a signed-out visitor (runs it, then shows the result)
   /report?scan=scan_…  a signed-in user's scan
   /report?sample=1     the sample report
   Everything is rendered with DOM APIs; scan data is never assigned to innerHTML. */
(function () {
  'use strict';

  const root = document.getElementById('report-root');
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get('scan') || '';
  const isSample = params.has('sample');
  const isPublic = scanId.startsWith('pub_');
  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function link(href, className, text) {
    const a = el('a', className, text);
    a.href = href;
    return a;
  }

  function state(title, message, progress) {
    const box = el('div', 'rp-state');
    box.append(el('h2', null, title), el('p', null, message));
    if (progress !== undefined) {
      const bar = el('div', 'rp-progress');
      const fill = el('i');
      fill.style.width = Math.max(4, Math.min(100, progress)) + '%';
      bar.appendChild(fill);
      box.appendChild(bar);
    }
    root.replaceChildren(box);
  }

  function errorState(message, withScanLink) {
    state('We could not show this report', message);
    if (withScanLink) {
      const p = el('p');
      p.style.marginTop = '16px';
      p.appendChild(link('/#scan', 'ds-btn ds-btn--brand', 'Start a new scan'));
      root.firstChild.appendChild(p);
    }
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function getJSON(url, options) {
    const response = await fetch(url, Object.assign({ credentials: 'same-origin', headers: { Accept: 'application/json' } }, options));
    const data = await response.json().catch(() => ({}));
    return { response, data };
  }

  function levelColour(score) {
    if (score >= 85) return 'var(--ds-low)';
    if (score >= 65) return 'var(--ds-info)';
    if (score >= 45) return 'var(--ds-medium)';
    return 'var(--ds-critical)';
  }

  function badge(severity) {
    const sev = String(severity || 'INFO').toUpperCase();
    const cls = sev === 'INFO' ? 'ds-badge--info' : `ds-badge--${sev.toLowerCase()}`;
    return el('span', `ds-badge ${cls}`, sev);
  }

  function check(label, value, note, tone) {
    const box = el('div', 'rp-check');
    const b = el('b', tone ? `rp-${tone}` : null, value);
    box.append(el('span', null, label), b);
    if (note) box.appendChild(el('small', null, note));
    return box;
  }

  function finding(f) {
    const card = el('article', 'rp-finding');
    const head = el('header');
    head.append(badge(f.severity), el('h4', null, f.title));
    card.appendChild(head);
    if (f.description) card.appendChild(el('p', null, f.description));
    if (f.fix) {
      const fix = el('p', 'rp-fix');
      fix.append(el('b', null, 'Fix: '), document.createTextNode(f.fix));
      card.appendChild(fix);
    }
    return card;
  }

  function formatDate(iso) {
    const d = iso ? new Date(iso) : null;
    return d && !isNaN(d) ? d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }) : '';
  }

  function render(scan, mode) {
    const score = scan.score || {};
    const overall = Number(score.overall || 0);
    const frag = document.createDocumentFragment();

    const printHead = el('div', 'rp-print-head');
    printHead.append(el('b', null, 'BharatSec security report'), el('span', null, 'bharatsec.vercel.app'));
    frag.appendChild(printHead);

    if (mode === 'sample') frag.appendChild(el('span', 'rp-sample', 'SAMPLE REPORT · real passive scan of example.com'));

    const head = el('div', 'rp-head');
    const title = el('div');
    title.append(el('h2', null, scan.domain), el('p', null, `Passive scan · ${formatDate(scan.completed_at || scan.started_at)}`));
    const actions = el('div', 'rp-actions');
    const pdf = el('button', 'ds-btn ds-btn--secondary', 'Download PDF');
    pdf.type = 'button';
    pdf.addEventListener('click', () => window.print());
    actions.appendChild(pdf);
    if (mode === 'private') actions.appendChild(link(`/dashboard.html?scan=${encodeURIComponent(scan.scan_id)}`, 'ds-btn ds-btn--primary', 'Open in dashboard'));
    else actions.appendChild(link('/#scan', 'ds-btn ds-btn--primary', 'Scan another domain'));
    head.append(title, actions);
    frag.appendChild(head);

    const top = el('div', 'rp-top');
    const scoreBox = el('div', 'rp-score');
    const ring = el('div', 'rp-ring');
    ring.style.setProperty('--v', String(overall));
    ring.style.setProperty('--c', levelColour(overall));
    const num = el('b', null, String(overall));
    num.appendChild(el('small', null, 'out of 100'));
    ring.appendChild(num);
    const level = el('span', 'rp-level', score.level || '');
    level.style.color = levelColour(overall);
    scoreBox.append(ring, level);

    const summary = el('div', 'rp-summary');
    summary.append(el('h3', null, 'Summary'), el('p', null, scan.ai_summary || 'No summary available.'));
    const counts = el('div', 'rp-counts');
    [['CRITICAL', score.critical_count], ['HIGH', score.high_count], ['MEDIUM', score.medium_count], ['LOW', score.low_count]].forEach(([sev, n]) => {
      const b = badge(sev);
      b.textContent = `${n || 0} ${sev.toLowerCase()}`;
      counts.appendChild(b);
    });
    summary.appendChild(counts);
    top.append(scoreBox, summary);
    frag.appendChild(top);

    const dns = scan.dns || {}, ssl = scan.ssl || {}, web = scan.web || {};
    const emailOk = [dns.has_spf, dns.has_dkim, dns.has_dmarc].filter(Boolean).length;
    const missing = ((web.headers || {}).missing || []).length;
    const alive = (scan.subdomains || []).filter((s) => s.alive).length;
    const checks = el('div', 'rp-checks');
    checks.append(
      check('SSL / TLS', ssl.valid ? `Grade ${ssl.grade || 'N/A'}` : 'Problem', ssl.expires ? `${ssl.days_remaining} days left` : 'No certificate read',
        !ssl.valid ? 'bad' : /^A/.test(ssl.grade || '') ? 'ok' : 'warn'),
      check('Email security', `${emailOk} of 3`, 'SPF · DKIM · DMARC', emailOk === 3 ? 'ok' : emailOk ? 'warn' : 'bad'),
      check('Security headers', missing ? `${missing} missing` : 'All present', web.https_redirect ? 'HTTPS redirect on' : 'No HTTPS redirect', missing ? 'warn' : 'ok'),
      check('Subdomains', `${alive} live`, `${(scan.subdomains || []).length} found`, null),
    );
    frag.appendChild(checks);

    const priorities = scan.top_priorities || [];
    if (priorities.length) {
      const sec = el('section', 'rp-section');
      sec.appendChild(el('h3', null, 'Fix these first'));
      priorities.slice(0, 3).forEach((f) => sec.appendChild(finding(f)));
      frag.appendChild(sec);
    }

    const findings = (scan.findings || []).slice().sort((a, b) => SEVERITIES.indexOf(String(a.severity).toUpperCase()) - SEVERITIES.indexOf(String(b.severity).toUpperCase()));
    const all = el('section', 'rp-section');
    all.appendChild(el('h3', null, `All findings (${findings.length})`));
    if (findings.length) findings.forEach((f) => all.appendChild(finding(f)));
    else all.appendChild(el('p', null, 'No findings. This does not guarantee the domain is free of vulnerabilities.'));
    frag.appendChild(all);

    if (mode !== 'private') {
      const cta = el('div', 'rp-cta');
      const text = el('div');
      text.append(el('h3', null, 'Keep watching this domain'), el('p', null, 'Sign up free to save reports, track your score over time, monitor your sites and ask BharatSec AI about every finding.'));
      cta.append(text, link('/login.html', 'ds-btn ds-btn--brand', 'Sign up free'));
      frag.appendChild(cta);
    }

    frag.appendChild(el('p', 'rp-foot', 'BharatSec reads only public information (DNS, WHOIS, TLS certificates, HTTP headers, subdomains). A score is a starting point for prioritising fixes, not a guarantee of security. Generated by BharatSec · bharatsec.vercel.app'));
    root.replaceChildren(frag);
    document.title = `${scan.domain} security report | BharatSec`;
  }

  async function runPublic() {
    state('Scanning your domain…', 'Passive checks of DNS, email security, SSL/TLS, headers and subdomains. This takes about a minute.', 5);
    const base = `/api/public/scan/${encodeURIComponent(scanId)}`;
    fetch(`${base}/run`, { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    for (let i = 0; i < 150; i += 1) {
      await sleep(i ? 2000 : 800);
      const { response, data } = await getJSON(`${base}/status`);
      if (response.status === 404) return errorState('This free scan link has expired or is invalid.', true);
      if (!response.ok) continue;
      if (data.status === 'complete') break;
      if (data.status === 'error') return errorState(data.error || 'The scan could not finish.', true);
      state(`Scanning ${data.domain || 'your domain'}…`, 'Passive checks of DNS, email security, SSL/TLS, headers and subdomains. This takes about a minute.', data.progress || 5);
    }
    const { response, data } = await getJSON(`${base}/report`);
    if (!response.ok) return errorState('The report is not ready yet. Please refresh in a moment.', false);
    render(data, 'public');
  }

  async function runPrivate() {
    state('Loading report…', 'Fetching your scan results.');
    const { response, data } = await getJSON(`/api/scan/${encodeURIComponent(scanId)}/results`);
    if (response.status === 401) {
      window.location.href = `/login.html?return=${encodeURIComponent(window.location.href)}`;
      return;
    }
    if (!response.ok) return errorState(response.status === 202 ? 'This scan is still running.' : 'Scan not found.', true);
    render(data, 'private');
  }

  async function runSample() {
    const { response, data } = await getJSON('/assets/data/sample-report.json');
    if (!response.ok) return errorState('The sample report is unavailable.', true);
    render(data, 'sample');
  }

  if (!root) return;
  if (isSample) runSample();
  else if (isPublic) runPublic();
  else if (scanId) runPrivate();
  else errorState('No report selected.', true);
})();
