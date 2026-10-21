/* ============================================================
   BharatSec — Dashboard Controller
   Handles real-domain scan lifecycle, UI rendering, view switching
   ============================================================ */

const API = (() => {
  if (window.BHARATSEC_API_BASE) return window.BHARATSEC_API_BASE.replace(/\/$/, '');
  const isLocalFrontend = window.location.protocol === 'file:' ||
    (['localhost', '127.0.0.1'].includes(window.location.hostname) && window.location.port !== '8000');
  return isLocalFrontend ? 'http://127.0.0.1:8000' : '';
})();
let scanData    = null;
let scanId      = null;
let currentView = 'overview';
let currentMode = 'analyst';
let pollTimer   = null;

const DOMAIN_PATTERN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

// ── Static UI icons (constant markup only, never data) ────────
const ICON_PATHS = {
  check:   '<path d="M20 6 9 17l-5-5"/>',
  x:       '<path d="M18 6 6 18M6 6l12 12"/>',
  alert:   '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>',
  globe:   '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  zap:     '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8Z"/>',
  target:  '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  lock:    '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  user:    '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  gear:    '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>',
  key:     '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/>',
  sparkle: '<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3Z"/>',
  wrench:  '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9l-3.8 3.8Z"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  arrow:   '<path d="M5 12h14M13 6l6 6-6 6"/>',
  plug:    '<path d="M12 22v-5M9 8V2M15 8V2M18 8v5a6 6 0 0 1-12 0V8Z"/>',
  back:    '<path d="M19 12H5M11 18l-6-6 6-6"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4L21 8"/><path d="M21 3v5h-5"/>',
  chart:   '<path d="M3 3v18h18"/><path d="M7 15l4-4 3 3 5-6"/>',
  external:'<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
};
function icon(name, cls = '') {
  return `<svg class="ico${cls ? ' ' + cls : ''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;
}
// Severity → design-system badge variant (input is always allowlisted first).
function sevVariant(level) {
  return { CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low', INFO:'info', SECURE:'primary' }[level] || 'info';
}
function sevBadge(sev) {
  const s = oneOf(sev, SEVERITIES, 'MEDIUM');
  return `<span class="ds-badge ds-badge--dot ds-badge--${sevVariant(s)}">${s}</span>`;
}
// Pass / fail status pill. Labels are constant strings.
function statusPill(ok, okLabel, badLabel, badTone = 'critical') {
  return ok
    ? `<span class="ds-badge ds-badge--low">${icon('check', 'ico-xs')}${okLabel}</span>`
    : `<span class="ds-badge ds-badge--${badTone}">${icon(badTone === 'critical' ? 'x' : 'alert', 'ico-xs')}${badLabel}</span>`;
}

// ── Boot ──────────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  let domain = (params.get('domain') || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').split('/')[0];

  // Reject demo or malformed domains — redirect to homepage
  if (!domain || domain === 'demo' || !DOMAIN_PATTERN.test(domain)) {
    window.location.href = 'index.html';
    return;
  }

  document.getElementById('overlay-domain').textContent = domain;
  document.getElementById('topbar-domain').textContent  = domain;
  document.getElementById('sidebar-domain').textContent = domain;

  launchScan(domain);
});

// Sidebar nav items are divs with role="button"; let Enter/Space activate them.
document.addEventListener('keydown', (event) => {
  const item = event.target.closest?.('.nav-item[role="button"]');
  if (item && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    item.click();
  }
});

// ── Scan Launch ───────────────────────────────────────────────

async function launchScan(domain) {
  showOverlay(true);
  updateProgress(0, 'Connecting to BharatSec backend...');

  try {
    const res = await fetch(`${API}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, authorized: true, include_ports: false })
    });

    if (!res.ok) throw new Error(`Backend error: ${res.status}`);
    const data = await res.json();
    scanId = data.scan_id;

    if (data.status === 'complete') {
      updateProgress(100, 'Scan complete — rendering results...');
      await sleep(400);
      await fetchAndRender(scanId);
    } else {
      // The scan executes inside this request; keep it open while status is polled separately.
      fetch(`${API}/api/scan/${encodeURIComponent(scanId)}/run`, { method: 'POST' })
        .catch((error) => console.warn('[BharatSec] Scan run request ended early:', error.message));
      updateProgress(5, `Scan started for ${domain}...`);
      pollStatus(scanId, domain);
    }
  } catch (err) {
    console.error('[BharatSec] Backend unreachable:', err.message);
    showBackendError(domain, 'Could not connect to the scan API. Start the backend and confirm its health check responds before retrying.');
  }
}

// ── Poll scan status ──────────────────────────────────────────

const STEP_THRESHOLDS = [
  { id: 'step-dns',   min: 5,  label: 'DNS Record Analysis' },
  { id: 'step-whois', min: 20, label: 'WHOIS Lookup' },
  { id: 'step-web',   min: 40, label: 'Web Security Analysis' },
  { id: 'step-ssl',   min: 60, label: 'SSL/TLS Inspection' },
  { id: 'step-sub',   min: 80, label: 'Subdomain Enumeration' },
  { id: 'step-ai',    min: 90, label: 'AI Risk Analysis' },
];

const PROGRESS_MSGS = {
  5:   'Resolving DNS records...',
  10:  'DNS records collected...',
  20:  'Running WHOIS lookup...',
  40:  'Auditing HTTP security headers...',
  60:  'Inspecting SSL/TLS certificate...',
  80:  'Enumerating subdomains...',
  90:  'AI is analyzing all findings...',
  100: 'Scan complete — rendering dashboard...',
};

function pollStatus(id, domain) {
  let retryCount = 0;
  let pollInFlight = false;
  const scanStartedAt = Date.now();
  pollTimer = setInterval(async () => {
    if (pollInFlight) return;
    pollInFlight = true;

    try {
      if (Date.now() - scanStartedAt > 240000) {
        clearInterval(pollTimer);
        showBackendError(domain, 'This scan is taking longer than expected. The scan was not replaced with demo results. You can retry the scan or choose demo mode explicitly.');
        return;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      let res;
      try {
        res = await fetch(`${API}/api/scan/${id}/status`, { signal: controller.signal });
      } finally {
        clearTimeout(timeout);
      }
      if (!res.ok) {
        retryCount++;
        if (retryCount > 5) {
          clearInterval(pollTimer);
          showBackendError(domain, `Could not read scan status (HTTP ${res.status}). Please retry while the backend is running.`);
        }
        return;
      }
      retryCount = 0;

      const data = await res.json();
      const pct  = Number(data.progress) || 0;

      // Update progress UI
      const msg = PROGRESS_MSGS[pct] || `Scanning ${domain}... (${pct}%)`;
      updateProgress(pct, msg);

      // Tick off completed steps
      STEP_THRESHOLDS.forEach(s => {
        const el = document.getElementById(s.id);
        if (!el) return;
        if (pct >= s.min) {
          el.className = 'scan-step done';
          el.innerHTML = `<span class="step-icon">${icon('check')}</span> ${s.label}`;
        } else if (pct >= s.min - 15) {
          el.className = 'scan-step active';
        }
      });

      if (data.status === 'complete') {
        clearInterval(pollTimer);
        updateProgress(100, 'Scan complete — rendering dashboard...');
        await sleep(400);
        await fetchAndRender(id);
      } else if (data.status === 'error') {
        clearInterval(pollTimer);
        showBackendError(domain, data.error || 'Scan encountered an error. Please try again.');
      }
    } catch (err) {
      retryCount++;
      console.warn('[BharatSec] Poll error:', err.message, `(retry ${retryCount})`);
      if (retryCount > 5) {
        clearInterval(pollTimer);
        showBackendError(domain, 'Lost connection to the scan backend. No demo results were substituted. Check the backend and retry.');
      }
    } finally {
      pollInFlight = false;
    }
  }, 1500);
}

// ── Backend error screen ──────────────────────────────────────

function showBackendError(domain, extraMsg = '') {
  const overlay = document.getElementById('scan-overlay');
  if (overlay) {
    overlay.innerHTML = `
      <div class="scan-progress-card scan-error-card" role="alertdialog" aria-labelledby="scan-error-title">
        <div class="scan-card-head">
          <span class="scan-shield-icon is-error">${icon('plug')}</span>
          <div>
            <div class="ds-eyebrow">Scan interrupted</div>
            <h3 id="scan-error-title">Scan could not continue</h3>
          </div>
        </div>
        <p class="scan-error-text">
          BharatSec could not complete the scan for <strong class="ds-mono">${esc(domain)}</strong>. The local API should be available at <span class="ds-mono">http://127.0.0.1:8000</span>.
        </p>
        ${extraMsg ? `<p class="scan-error-detail">${icon('alert', 'ico-sm')}<span>${esc(extraMsg)}</span></p>` : ''}
        <div class="scan-error-help">
          <div class="scan-error-help-label">Start the backend in a second terminal</div>
          <pre class="scan-error-code"><span class="code-comment"># from the BharatSec project folder</span>
cd backend
python main.py</pre>
          <a class="scan-error-link" href="/api/health" target="_blank" rel="noopener">Check backend health ${icon('external', 'ico-xs')}</a>
        </div>
        <div class="scan-error-actions">
          <button type="button" class="ds-btn ds-btn--ghost" onclick="window.history.back()">${icon('back', 'ico-sm')}Go back</button>
          <button type="button" class="ds-btn ds-btn--secondary" id="demo-fallback-btn">${icon('chart', 'ico-sm')}Try demo mode</button>
          <button type="button" class="ds-btn ds-btn--primary" onclick="location.reload()">${icon('refresh', 'ico-sm')}Retry scan</button>
        </div>
      </div>`;
    document.getElementById('demo-fallback-btn').addEventListener('click', () => loadDemoFallback(domain));
    overlay.style.display = 'flex';
  }
  const dot = document.getElementById('status-dot');
  if (dot) {
    dot.className = 'ds-status ds-status--error scan-state';
    dot.textContent = 'Scan failed';
  }
}


// ── Fetch results & render ────────────────────────────────────

async function fetchAndRender(id) {
  try {
    const res = await fetch(`${API}/api/scan/${id}/results`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const raw = await res.json();

    // Normalise backend response to the shape renderAll() expects
    scanData = normaliseBackendResponse(raw);
    setCopilotScanId(id);
    renderAll(scanData);
    showOverlay(false);
  } catch(e) {
    console.error('[BharatSec] Failed to fetch results:', e);
    showBackendError('unknown', 'Failed to load scan results from backend.');
  }
}

// ── Normalise backend ScanResult → dashboard-friendly object ─

function normaliseBackendResponse(raw) {
  // Backend sends Pydantic model as JSON. Map it to what renderAll() needs.
  const dns   = raw.dns   || {};
  const ssl   = raw.ssl   || {};
  const web   = raw.web   || {};
  const whois = raw.whois || {};
  const score = raw.score || {};

  return {
    scan_id:      raw.scan_id,
    domain:       raw.domain,
    status:       raw.status,
    completed_at: raw.completed_at || new Date().toISOString(),
    score: {
      overall:          score.overall          ?? 50,
      attack_surface:   score.attack_surface   ?? 50,
      web_security:     score.web_security     ?? 50,
      identity_exposure:score.identity_exposure?? 50,
      configuration:    score.configuration    ?? 50,
      credential_risk:  score.credential_risk  ?? 50,
      level:            score.level            || 'HIGH',
      critical_count:   score.critical_count   || 0,
      high_count:       score.high_count       || 0,
      medium_count:     score.medium_count     || 0,
      low_count:        score.low_count        || 0,
    },
    dns: {
      a_records:     dns.a_records     || [],
      mx_records:    dns.mx_records    || [],
      txt_records:   dns.txt_records   || [],
      ns_records:    dns.ns_records    || [],
      cname_records: dns.cname_records || [],
      has_spf:       dns.has_spf       || false,
      has_dmarc:     dns.has_dmarc     || false,
      has_dkim:      dns.has_dkim      || false,
    },
    ssl: {
      valid:          ssl.valid          !== undefined ? ssl.valid : false,
      issuer:         ssl.issuer         || '—',
      subject:        ssl.subject        || raw.domain,
      expires:        ssl.expires        || '—',
      days_remaining: ssl.days_remaining || 0,
      protocol:       ssl.protocol       || '—',
      grade:          ssl.grade          || 'N/A',
      vulnerabilities:ssl.vulnerabilities|| [],
    },
    web: {
      status_code:     web.status_code     || 0,
      server:          web.server          || '—',
      technologies:    web.technologies    || [],
      https_redirect:  web.https_redirect  || false,
      response_time_ms:web.response_time_ms|| 0,
      headers: {
        present:     (web.headers || {}).present     || [],
        missing:     (web.headers || {}).missing     || [],
        all_headers: (web.headers || {}).all_headers || {},
      }
    },
    whois: {
      registrar:       whois.registrar        || '—',
      creation_date:   whois.creation_date    || '—',
      expiration_date: whois.expiration_date  || '—',
      days_until_expiry:whois.days_until_expiry||0,
      name_servers:    whois.name_servers     || [],
      privacy_protected:whois.privacy_protected||false,
    },
    subdomains:     (raw.subdomains || []).map(s => ({
      subdomain:   s.subdomain,
      ip:          s.ip || null,
      status_code: s.status_code || null,
      alive:       s.alive || false,
    })),
    findings: (raw.findings || []).map(f => ({
      id:          f.id,
      category:    f.category,
      severity:    f.severity || f.severity?.value || 'MEDIUM',
      title:       f.title,
      description: f.description,
      evidence:    f.evidence    || '',
      ai_analysis: f.ai_analysis || '',
      fix:         f.fix         || '',
      effort:      f.effort      || 'Medium',
      impact:      f.impact      || 'Medium',
    })),
    top_priorities: (raw.top_priorities || []).map(f => ({
      id:       f.id,
      title:    f.title,
      severity: f.severity || f.severity?.value || 'MEDIUM',
      category: f.category,
      effort:   f.effort || 'Medium',
      impact:   f.impact || 'Medium',
    })),
    attack_paths: raw.attack_paths || [],
    ai_summary:   raw.ai_summary   || '',
  };
}

// ── Demo fallback (client-side, no backend needed) ────────────

async function loadDemoFallback(domain) {
  const steps = ['step-dns','step-whois','step-web','step-ssl','step-sub','step-ai'];
  const msgs  = [
    'Resolving DNS records...','Running WHOIS lookup...',
    'Auditing HTTP headers...','Inspecting SSL/TLS...',
    'Enumerating subdomains...','AI analyzing findings...'
  ];

  for (let i = 0; i < steps.length; i++) {
    await sleep(380);
    updateProgress(Math.round((i + 1) * (100 / steps.length)), msgs[i]);
    const el = document.getElementById(steps[i]);
    if (el) {
      const label = STEP_THRESHOLDS[i]?.label || steps[i];
      el.innerHTML = `<span class="step-icon">${icon('check')}</span> ${label}`;
      el.className = 'scan-step done';
    }
  }
  await sleep(300);
  updateProgress(100, 'Loading demo results...');
  await sleep(300);

  const displayDomain = (domain && domain !== 'demo' && domain !== 'error') ? domain : 'example.com';
  scanData = buildDemoData(displayDomain);
  renderAll(scanData);
  showOverlay(false);
}

// ── Demo data ─────────────────────────────────────────────────

function buildDemoData(domain) {
  return {
    scan_id: 'demo_001',
    domain,
    status: 'complete',
    completed_at: new Date().toISOString(),
    score: {
      overall: 56, attack_surface: 62, web_security: 41,
      identity_exposure: 38, configuration: 70, credential_risk: 82,
      level: 'HIGH', critical_count: 3, high_count: 6, medium_count: 9, low_count: 12
    },
    dns: {
      a_records: ['93.184.216.34'], mx_records: ['0 mail.' + domain],
      txt_records: ['v=spf1 -all'], ns_records: ['a.iana-servers.net.','b.iana-servers.net.'],
      has_spf: true, has_dmarc: false, has_dkim: false
    },
    ssl: {
      valid: true, issuer: 'DigiCert Inc', subject: domain,
      expires: '2025-11-13', days_remaining: 92,
      protocol: 'TLSv1.3', grade: 'A', vulnerabilities: []
    },
    web: {
      status_code: 200, server: 'ECAcc (bsa/EB18)',
      technologies: ['Nginx','Cloudflare'], https_redirect: true,
      response_time_ms: 142.3,
      headers: {
        present: ['X-Content-Type-Options','Cache-Control'],
        missing: ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','Referrer-Policy','Permissions-Policy'],
        all_headers: { 'server':'ECAcc','x-content-type-options':'nosniff' }
      }
    },
    whois: {
      registrar: 'IANA', creation_date: '1995-08-14',
      expiration_date: '2026-08-13', days_until_expiry: 370,
      name_servers: ['a.iana-servers.net','b.iana-servers.net'],
      privacy_protected: false
    },
    subdomains: [
      { subdomain:'www.'+domain,     ip:'93.184.216.34', status_code:200, alive:true  },
      { subdomain:'dev.'+domain,     ip:'93.184.216.35', status_code:403, alive:true  },
      { subdomain:'api.'+domain,     ip:'93.184.216.36', status_code:200, alive:true  },
      { subdomain:'admin.'+domain,   ip:'93.184.216.37', status_code:200, alive:true  },
      { subdomain:'staging.'+domain, ip:'93.184.216.38', status_code:200, alive:true  },
      { subdomain:'mail.'+domain,    ip:null,            status_code:null,alive:false },
    ],
    findings: [
      { id:'f1', category:'Email Security', severity:'CRITICAL',
        title:'Missing DMARC Policy',
        description:'No DMARC DNS record found. Anyone can send spoofed emails from your domain.',
        evidence:`DNS query _dmarc.${domain} returned no record`,
        ai_analysis:'DMARC is the last line of defense against email spoofing. Without it, phishing emails sent from your domain are far more likely to reach their targets. This is one of the most exploited weaknesses in Business Email Compromise (BEC) attacks.',
        fix:`Add a TXT DNS record: _dmarc.${domain} → v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}`,
        effort:'Low', impact:'Critical' },
      { id:'f2', category:'Attack Surface', severity:'CRITICAL',
        title:`Exposed Admin Panel: admin.${domain}`,
        description:'An admin subdomain is publicly accessible without VPN or IP restriction.',
        evidence:`HTTP 200 at admin.${domain} (IP: 93.184.216.37)`,
        ai_analysis:'Publicly exposed admin panels are prime targets for credential stuffing, brute force, and privilege escalation attacks. Development teams often leave default passwords here.',
        fix:`Restrict admin.${domain} to specific IP ranges or VPN access. Add MFA.`,
        effort:'Medium', impact:'Critical' },
      { id:'f3', category:'Attack Surface', severity:'CRITICAL',
        title:`Exposed Staging Environment: staging.${domain}`,
        description:'Staging environment is publicly accessible.',
        evidence:`HTTP 200 at staging.${domain} (IP: 93.184.216.38)`,
        ai_analysis:'Staging environments often contain pre-release code, weaker auth, and shared credentials with production databases.',
        fix:`Restrict staging.${domain} to VPN. Remove if not actively in use.`,
        effort:'Low', impact:'Critical' },
      { id:'f4', category:'Security Headers', severity:'HIGH',
        title:'Missing Header: Strict-Transport-Security',
        description:'HSTS header not present. Enables SSL-stripping attacks on public networks.',
        evidence:"Header 'Strict-Transport-Security' absent from HTTP response",
        ai_analysis:'Without HSTS, a man-in-the-middle attacker on the same network can intercept traffic before the HTTPS redirect happens — downgrading the connection to plaintext.',
        fix:'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        effort:'Low', impact:'High' },
      { id:'f5', category:'Security Headers', severity:'HIGH',
        title:'Missing Header: Content-Security-Policy',
        description:'No CSP header. Site is vulnerable to XSS attacks.',
        evidence:"Header 'Content-Security-Policy' absent from HTTP response",
        ai_analysis:'A missing CSP means any injected JavaScript on your page can steal session cookies, keylog users, or redirect to phishing sites.',
        fix:"Start with: Content-Security-Policy: default-src 'self'; then refine.",
        effort:'Medium', impact:'High' },
      { id:'f6', category:'Security Headers', severity:'HIGH',
        title:'Missing Header: X-Frame-Options',
        description:'Site can be embedded in iframes — clickjacking risk.',
        evidence:"Header 'X-Frame-Options' absent",
        ai_analysis:'Clickjacking lets attackers overlay invisible iframes on your site, tricking users into clicking hidden malicious buttons.',
        fix:'Add header: X-Frame-Options: DENY',
        effort:'Low', impact:'High' },
      { id:'f7', category:'Email Security', severity:'HIGH',
        title:'DKIM Not Detected',
        description:'DKIM cryptographic signatures not found in DNS records.',
        evidence:'No DKIM TXT record found in DNS',
        ai_analysis:'DKIM adds a cryptographic signature to outgoing emails. Without it, email receivers cannot verify authenticity.',
        fix:`Configure DKIM in your email provider and add the public key as DNS TXT: default._domainkey.${domain}`,
        effort:'Medium', impact:'High' },
      { id:'f8', category:'Security Headers', severity:'MEDIUM',
        title:'Missing Header: Referrer-Policy',
        description:'No Referrer-Policy. URLs leak to third-party sites via Referer headers.',
        evidence:"Header 'Referrer-Policy' absent",
        ai_analysis:'Without a Referrer-Policy, full URLs (including sensitive path/query params) are sent to every external site users navigate to from your pages.',
        fix:'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        effort:'Low', impact:'Medium' },
      { id:'f9', category:'Configuration', severity:'MEDIUM',
        title:'WHOIS Privacy Not Enabled',
        description:'Domain registrant details are publicly visible in WHOIS records.',
        evidence:'Registrar: IANA — no privacy protection detected',
        ai_analysis:'Exposed WHOIS data enables targeted spear-phishing attacks using registrant name, email, and phone.',
        fix:'Enable WHOIS privacy/proxy with your domain registrar. Usually free.',
        effort:'Low', impact:'Medium' },
    ],
    top_priorities: [],
    attack_paths: [
      { name:'Email Spoofing → Business Compromise', risk:'CRITICAL',
        steps:[
          { node:domain,           type:'entry',    label:'Target Domain' },
          { node:'Missing DMARC',  type:'weakness', label:'No Email Auth' },
          { node:'Spoofed Email',  type:'attack',   label:'Attacker sends email as you' },
          { node:'Employee Clicks',type:'attack',   label:'Phishing / credential theft' },
          { node:'Business Impact',type:'impact',   label:'Account takeover / data breach' },
        ]},
      { name:'Admin Panel Exposure → Privilege Escalation', risk:'HIGH',
        steps:[
          { node:`admin.${domain}`,   type:'entry',    label:'Exposed Admin Panel' },
          { node:'No IP Restriction', type:'weakness', label:'Publicly accessible' },
          { node:'Brute Force Auth',  type:'attack',   label:'Credential stuffing' },
          { node:'Admin Access',      type:'impact',   label:'Full system compromise' },
        ]},
    ],
    ai_summary: `${domain} has a BharatSec Score of 56/100 — HIGH RISK. The most critical issues are the exposed admin and staging subdomains, and the complete absence of DMARC, leaving the domain open to email spoofing attacks. Five HTTP security headers are missing, creating XSS and clickjacking exposure points. Fixing the 3 critical findings alone would improve the score by approximately 15-20 points.`
  };
}

// ── Main render orchestrator ──────────────────────────────────

function renderAll(data) {
  const t = new Date(data.completed_at);
  const timeStr = isNaN(t) ? '—' : t.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });

  setEl('topbar-domain',  data.domain);
  setEl('sidebar-domain', data.domain);
  setEl('scan-time',      `Scanned ${timeStr}`);

  // Mark the scan state pill complete
  const dot = document.getElementById('status-dot');
  if (dot) {
    dot.className = 'ds-status ds-status--live scan-state';
    dot.textContent = 'Complete';
  }

  // Derive top priorities from findings if backend didn't send them
  if (!data.top_priorities || !data.top_priorities.length) {
    const sevOrder  = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
    const effortW   = { Low:3, Medium:2, High:1 };
    data.top_priorities = [...data.findings]
      .filter(f => f.severity !== 'INFO')
      .sort((a,b)=>{
        const sa = (4-sevOrder[a.severity])*2 + (effortW[a.effort]||2);
        const sb = (4-sevOrder[b.severity])*2 + (effortW[b.effort]||2);
        return sb - sa;
      })
      .slice(0, 5);
  }

  renderScore(data.score);
  renderAISummary(data.ai_summary);
  renderSeverityChips(data.score);
  renderCategoryBars(data.score);
  renderQuickStats(data);
  renderFindings(data.findings);
  renderAttackPaths(data.attack_paths);
  renderRemediation(data.top_priorities);
  renderDNS(data.dns, data.whois);
  renderSSL(data.ssl);
  renderHeaders(data.web.headers);
  renderSubdomains(data.subdomains);
  renderExecutiveView(data);
  updateSidebarBadge(data.score);

  setEl('findings-count',       data.findings.length);
  setEl('findings-total-badge', `${data.findings.length} findings`);
}

// ── Score & gauge ─────────────────────────────────────────────

function renderScore(score) {
  createGaugeChart(score.overall);
  updateGaugeColors(score.overall);
  animateCategoryBars(score);
}
function renderSeverityChips(score) {
  setEl('chip-critical', score.critical_count);
  setEl('chip-high',     score.high_count);
  setEl('chip-medium',   score.medium_count);
  setEl('chip-low',      score.low_count);
}
function renderAISummary(summary) {
  setEl('ai-summary-text', summary || 'AI analysis complete.');
  setEl('exec-ai-text',    summary || 'AI analysis complete.');
}
function renderCategoryBars(score) { animateCategoryBars(score); }

// ── Quick stats row ───────────────────────────────────────────

function renderQuickStats(data) {
  const ssl = data.ssl;
  const sslEl = document.getElementById('ssl-quick');
  if (sslEl) {
    const grade = ssl.grade || 'N/A';
    const days  = num(ssl.days_remaining);
    sslEl.innerHTML = `
      <div class="quick-value tone-${gradeTone(grade)}">${esc(grade)}</div>
      <div class="quick-meta">${statusPill(ssl.valid, 'Valid', 'Invalid')}<span class="ds-mono">${esc(ssl.protocol||'—')}</span></div>
      <div class="quick-sub${days < 30 ? ' tone-critical' : ''}">Expires in ${days} days</div>`;
  }

  const emailEl = document.getElementById('email-quick');
  if (emailEl) {
    const d = data.dns;
    const row = (ok, label) => `<div class="check-row"><span class="check-icon ${ok?'is-pass':'is-fail'}">${icon(ok?'check':'x')}</span><span class="check-label">${label}</span><span class="check-status ${ok?'pass':'fail'}">${ok?'Present':'Missing'}</span></div>`;
    emailEl.innerHTML = `<div class="check-list">${row(d.has_spf, 'SPF record')}${row(d.has_dmarc, 'DMARC policy')}${row(d.has_dkim, 'DKIM signing')}</div>`;
  }

  const subsEl = document.getElementById('subs-quick');
  if (subsEl) {
    const total = data.subdomains.length;
    const alive = data.subdomains.filter(s=>s.alive).length;
    subsEl.innerHTML = `
      <div class="quick-value">${num(total)}</div>
      <div class="quick-meta"><span class="ds-badge ds-badge--low ds-badge--dot">${num(alive)} active</span><span class="ds-badge">${num(total-alive)} inactive</span></div>`;
  }
}

// SSL grade → tone class used for colour (always shown alongside the grade text).
function gradeTone(grade) {
  const tones = { A:'good', 'A+':'good', B:'medium', C:'high', D:'critical', F:'critical' };
  return Object.prototype.hasOwnProperty.call(tones, grade) ? tones[grade] : 'info';
}

// ── Findings ──────────────────────────────────────────────────

function getSeverity(f) {
  // Backend may send severity as string or as { value: "HIGH" }
  const sev = (typeof f.severity === 'string') ? f.severity : f.severity?.value;
  return oneOf(sev, SEVERITIES, 'MEDIUM');
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  if (!container) return;
  if (!findings.length) {
    container.innerHTML = `<div class="no-findings">${icon('check', 'ico-lg tone-good')}<strong>No findings</strong>Excellent security posture.</div>`;
    return;
  }
  container.innerHTML = findings.map((f, i) => {
    const sev = getSeverity(f);
    return `
    <div class="finding-card sev-${sev.toLowerCase()}" id="card-${i}" data-severity="${sev}">
      <button type="button" class="finding-top" onclick="toggleFinding(${i})" aria-expanded="false" aria-controls="detail-${i}">
        <span class="finding-left">
          <span class="sev-bar" aria-hidden="true"></span>
          <span class="finding-main">
            <span class="finding-title">${esc(f.title)}</span>
            <span class="finding-meta">
              ${sevBadge(sev)}
              <span class="finding-cat">${esc(f.category)}</span>
            </span>
          </span>
        </span>
        <span class="finding-expand-icon">${icon('chevron')}</span>
      </button>
      <div class="finding-detail" id="detail-${i}">
        <p class="finding-desc">${esc(f.description)}</p>
        ${f.ai_analysis ? `<div class="ai-analysis-box"><div class="detail-label">${icon('sparkle', 'ico-xs')}AI analysis</div><div class="ai-analysis-text">${esc(f.ai_analysis)}</div></div>` : ''}
        ${f.fix ? `<div class="fix-box"><div class="detail-label">${icon('wrench', 'ico-xs')}Recommended fix</div><div class="fix-text">${esc(f.fix)}</div></div>` : ''}
        ${f.evidence ? `<div class="evidence-box"><div class="detail-label">Evidence</div><code class="evidence-text">${esc(f.evidence)}</code></div>` : ''}
        <div class="finding-tags">
          <span class="ds-badge">Effort: ${esc(f.effort||'Medium')}</span>
          <span class="ds-badge">Impact: ${esc(f.impact||'Medium')}</span>
        </div>
      </div>
    </div>`;
  }).join('');
}

function toggleFinding(id) {
  const card = document.getElementById('card-'+id);
  if (!card) return;
  const open = card.classList.toggle('expanded');
  const btn = card.querySelector('.finding-top');
  if (btn) btn.setAttribute('aria-expanded', String(open));
}

function filterFindings(severity) {
  document.querySelectorAll('.filter-btn').forEach(b=>{ b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); });
  const btn = document.getElementById('filter-'+severity);
  if (btn) { btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true'); }
  document.querySelectorAll('.finding-card').forEach(card=>{
    card.style.display = (severity==='ALL' || card.dataset.severity===severity) ? '' : 'none';
  });
}

// ── Attack Paths ──────────────────────────────────────────────

function renderAttackPaths(paths) {
  const container = document.getElementById('attack-paths-list');
  if (!container) return;
  if (!paths || !paths.length) {
    container.innerHTML = '<div class="no-findings">No significant attack paths detected for this domain.</div>';
    return;
  }
  container.innerHTML = paths.map((path, p)=>{
    const risk = oneOf(path.risk, SEVERITIES, 'MEDIUM');
    return `
    <div class="attack-path-card">
      <div class="ap-header">
        <span class="ap-name"><span class="ap-index">${String(p + 1).padStart(2, '0')}</span>${esc(path.name)}</span>
        <span class="ap-risk ds-badge ds-badge--dot ds-badge--${sevVariant(risk)}">${esc(path.risk)}</span>
      </div>
      <ol class="ap-steps">
        ${(path.steps || []).map((step,i)=>{
          const type = oneOf(step.type, STEP_TYPES, '');
          return `
          ${i>0?`<li class="ap-arrow" aria-hidden="true">${icon('arrow')}</li>`:''}
          <li class="ap-step-node ${type}">
            <span class="ap-step-type">${stepIcon(type)}${STEP_LABELS[type] || 'Step'}</span>
            <strong class="ap-step-title">${esc(step.node)}</strong>
            <span class="ap-step-label">${esc(step.label)}</span>
          </li>`;}).join('')}
      </ol>
    </div>`;}).join('');
}

const STEP_LABELS = { entry:'Entry point', weakness:'Weakness', attack:'Attack', impact:'Impact' };

function stepIcon(type) {
  const name = { entry:'globe', weakness:'alert', attack:'zap', impact:'target' }[oneOf(type, STEP_TYPES, '')];
  return name ? icon(name, 'ico-xs') : '';
}

// ── Remediation ───────────────────────────────────────────────

function renderRemediation(priorities) {
  const container = document.getElementById('remediation-list');
  if (!container) return;
  if (!priorities || !priorities.length) {
    container.innerHTML = `<div class="no-findings">${icon('check', 'ico-lg tone-good')}<strong>Nothing to remediate</strong>No critical findings for this domain.</div>`;
    return;
  }
  container.innerHTML = `<ol class="priority-list">${priorities.map((f,i)=>{
    const sev = getSeverity(f);
    return `
    <li class="priority-item">
      <div class="priority-rank">${i+1}</div>
      <div class="priority-content">
        <div class="priority-title">${esc(f.title)}</div>
        <div class="priority-chips">
          ${sevBadge(sev)}
          <span class="ds-badge ds-badge--${sevVariant(oneOf(String(f.impact||sev).toUpperCase(), SEVERITIES, sev))}">Impact: ${esc(f.impact||sev)}</span>
          <span class="ds-badge ${f.effort==='Low'?'ds-badge--low':'ds-badge--medium'}">Effort: ${esc(f.effort||'Medium')}</span>
          <span class="ds-badge p-chip-cat">${esc(f.category||'General')}</span>
        </div>
      </div>
    </li>`;
  }).join('')}</ol>`;
}

// ── DNS & WHOIS ───────────────────────────────────────────────

function renderDNS(dns, whois) {
  const dnsEl = document.getElementById('dns-records-display');
  if (dnsEl) {
    const rows = [
      { label:'A Records',     vals: dns.a_records     },
      { label:'MX Records',    vals: dns.mx_records    },
      { label:'NS Records',    vals: dns.ns_records    },
      { label:'TXT Records',   vals: dns.txt_records   },
      { label:'CNAME Records', vals: dns.cname_records },
    ].filter(r=>r.vals && r.vals.length);
    dnsEl.innerHTML = rows.length ? `
      <div class="ds-table-wrap"><table class="ds-table dns-table">
        <thead><tr><th scope="col">Type</th><th scope="col">Values</th></tr></thead>
        <tbody>${rows.map(r=>`
          <tr>
            <td class="ds-cell-strong rec-type">${r.label}</td>
            <td><ul class="rec-values">${r.vals.map(v=>`<li class="ds-mono">${esc(v)}</li>`).join('')}</ul></td>
          </tr>`).join('')}
        </tbody>
      </table></div>` : '<div class="no-findings">No DNS records found.</div>';
  }

  const whoisEl = document.getElementById('whois-display');
  if (whoisEl && whois) {
    const days = num(whois.days_until_expiry);
    whoisEl.innerHTML = `
      <dl class="kv-list">
        <div class="kv-row"><dt>Registrar</dt><dd class="ds-mono">${esc(whois.registrar||'—')}</dd></div>
        <div class="kv-row"><dt>Created</dt><dd class="ds-mono">${esc(whois.creation_date||'—')}</dd></div>
        <div class="kv-row"><dt>Expires</dt><dd class="ds-mono${days<90?' tone-high':''}">${esc(whois.expiration_date||'—')} <span class="kv-sub">(${days}d)</span></dd></div>
        <div class="kv-row"><dt>WHOIS privacy</dt><dd>${statusPill(whois.privacy_protected, 'Enabled', 'Disabled', 'medium')}</dd></div>
      </dl>`;
  }

  const emailEl = document.getElementById('email-security-display');
  if (emailEl && dns) {
    const tile = (label, ok, okText, badText, okSub, badSub, badTone) => `
        <div class="info-tile">
          <div class="info-tile-label">${label}</div>
          <div class="info-tile-value">${statusPill(ok, okText, badText, badTone)}</div>
          <div class="info-tile-sub">${ok ? okSub : badSub}</div>
        </div>`;
    emailEl.innerHTML = `
      <div class="info-grid">
        ${tile('SPF record', dns.has_spf, 'Present', 'Missing', 'Authorized senders defined', 'Domain can be spoofed', 'critical')}
        ${tile('DMARC policy', dns.has_dmarc, 'Present', 'Missing', 'Email spoofing policy active', 'No enforcement policy', 'critical')}
        ${tile('DKIM signing', dns.has_dkim, 'Detected', 'Not detected', 'Email signatures present', 'Configure with email provider', 'medium')}
      </div>`;
  }
}

// ── SSL Display ───────────────────────────────────────────────

function renderSSL(ssl) {
  const el = document.getElementById('ssl-display');
  if (!el || !ssl) return;
  const days     = num(ssl.days_remaining);
  const daysTone = days < 14 ? 'critical' : days < 30 ? 'high' : 'good';
  const protoNote = ssl.protocol==='TLSv1.3'
    ? `<span class="tone-good">${icon('check', 'ico-xs')}Recommended</span>`
    : ssl.protocol==='TLSv1.2'
      ? `<span class="tone-good">${icon('check', 'ico-xs')}Acceptable</span>`
      : `<span class="tone-medium">${icon('alert', 'ico-xs')}Outdated</span>`;
  el.innerHTML = `
    <div class="info-grid ssl-grid">
      <div class="info-tile"><div class="info-tile-label">Grade</div><div class="info-tile-value is-xl tone-${gradeTone(ssl.grade)}">${esc(ssl.grade||'N/A')}</div></div>
      <div class="info-tile"><div class="info-tile-label">Protocol</div><div class="info-tile-value ds-mono">${esc(ssl.protocol||'—')}</div><div class="info-tile-sub">${protoNote}</div></div>
      <div class="info-tile"><div class="info-tile-label">Issuer</div><div class="info-tile-value is-sm">${esc(ssl.issuer)||'—'}</div></div>
      <div class="info-tile"><div class="info-tile-label">Days remaining</div><div class="info-tile-value tone-${daysTone}">${days}</div><div class="info-tile-sub">Expires <span class="ds-mono">${esc(ssl.expires||'—')}</span></div></div>
    </div>
    <div class="check-list">
      <div class="check-row"><span class="check-icon ${ssl.valid?'is-pass':'is-fail'}">${icon(ssl.valid?'check':'x')}</span><span class="check-label">Certificate valid</span><span class="check-status ${ssl.valid?'pass':'fail'}">${ssl.valid?'Valid':'Invalid'}</span></div>
      ${ssl.vulnerabilities && ssl.vulnerabilities.length ? ssl.vulnerabilities.map(v=>`<div class="check-row"><span class="check-icon is-warn">${icon('alert')}</span><span class="check-label">${esc(v)}</span><span class="check-status fail">Issue</span></div>`).join('') : `<div class="check-row"><span class="check-icon is-pass">${icon('check')}</span><span class="check-label">No SSL vulnerabilities detected</span><span class="check-status pass">Clean</span></div>`}
    </div>`;
}

// ── HTTP Headers ──────────────────────────────────────────────

function renderHeaders(headers) {
  const el = document.getElementById('headers-display');
  if (!el || !headers) return;
  const HEADER_INFO = {
    'Strict-Transport-Security': { desc:'Forces HTTPS, blocks downgrade attacks', sev:'HIGH' },
    'Content-Security-Policy':   { desc:'Prevents XSS script injection', sev:'HIGH' },
    'X-Frame-Options':           { desc:'Blocks clickjacking attacks', sev:'MEDIUM' },
    'X-Content-Type-Options':    { desc:'Stops MIME type sniffing', sev:'MEDIUM' },
    'Referrer-Policy':           { desc:'Controls referrer header leakage', sev:'LOW' },
    'Permissions-Policy':        { desc:'Restricts access to browser APIs', sev:'LOW' },
  };
  const present = headers.present || [];
  const missing = headers.missing || [];
  const all = [...new Set([...missing, ...present])];
  const pct = all.length ? Math.round((present.length / all.length) * 100) : 0;
  el.innerHTML = `
    <div class="headers-summary">
      <div class="headers-summary-text">
        <strong>${present.length} of ${all.length}</strong> security headers present
        ${missing.length ? `<span class="ds-badge ds-badge--critical">${missing.length} missing</span>` : '<span class="ds-badge ds-badge--low">All secure</span>'}
      </div>
      <div class="headers-meter" aria-hidden="true"><span style="width:${pct}%"></span></div>
    </div>
    <div class="ds-table-wrap"><table class="ds-table headers-table">
      <thead><tr><th scope="col">Header</th><th scope="col">Purpose</th><th scope="col">Status</th></tr></thead>
      <tbody>${all.map(h=>{
        const isP  = present.includes(h);
        const info = Object.prototype.hasOwnProperty.call(HEADER_INFO, h) ? HEADER_INFO[h] : { desc:'Security header', sev:'MEDIUM' };
        return `<tr>
          <td><span class="check-icon ${isP?'is-pass':'is-fail'}">${icon(isP?'check':'x')}</span><span class="ds-mono header-name">${esc(h)}</span></td>
          <td class="header-desc">${info.desc}</td>
          <td>${isP ? '<span class="ds-badge ds-badge--low">Present</span>' : `<span class="ds-badge ds-badge--${info.sev==='HIGH'?'high':'medium'}">${info.sev} · Missing</span>`}</td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>`;
}

// ── Subdomains ────────────────────────────────────────────────

function renderSubdomains(subs) {
  const el   = document.getElementById('subdomains-display');
  const badge= document.getElementById('sub-count-badge');
  if (!el) return;
  const alive = subs.filter(s=>s.alive).length;
  if (badge) badge.textContent = `${subs.length} found · ${alive} active`;
  if (!subs.length) { el.innerHTML='<div class="no-findings">No subdomains discovered.</div>'; return; }
  el.innerHTML = `<div class="ds-table-wrap"><table class="ds-table subs-table">
    <thead><tr>
      <th scope="col">Subdomain</th>
      <th scope="col">IP address</th>
      <th scope="col">HTTP status</th>
      <th scope="col">Risk</th>
    </tr></thead>
    <tbody>${subs.map(s=>{
      const label = String(s.subdomain || '').toLowerCase().split('.')[0];
      const isSensitive = ['dev','test','staging','admin','old','backup','db','database'].includes(label);
      const risk = !s.alive ? '<span class="cell-muted">—</span>'
        : isSensitive ? '<span class="ds-badge ds-badge--dot ds-badge--high">HIGH</span>'
        : '<span class="ds-badge ds-badge--dot ds-badge--info">INFO</span>';
      return `<tr class="${s.alive ? 'is-alive' : 'is-inactive'}">
        <td class="ds-mono sub-name">${esc(s.subdomain)}</td>
        <td class="ds-mono">${esc(s.ip||'—')}</td>
        <td>${s.alive?`<span class="sub-status is-up">HTTP ${num(s.status_code)||200}</span>`:'<span class="sub-status">Inactive</span>'}</td>
        <td>${risk}</td>
      </tr>`;}).join('')}
    </tbody></table></div>`;
}

// ── Executive View ────────────────────────────────────────────

function renderExecutiveView(data) {
  const level = oneOf(data.score.level, RISK_LEVELS, 'HIGH');
  setEl('exec-score',    data.score.overall);
  setEl('exec-level',    `${data.score.level} risk`);
  const levelEl = document.getElementById('exec-level');
  if (levelEl) levelEl.className = `exec-score-label ds-badge ds-badge--dot ds-badge--${sevVariant(level)}`;
  setEl('exec-critical', data.score.critical_count);
  setEl('exec-high',     data.score.high_count);
  setEl('exec-medium',   data.score.medium_count);

  const actEl = document.getElementById('exec-actions-list');
  if (actEl && data.top_priorities.length) {
    actEl.innerHTML = `<ol class="exec-action-list">${data.top_priorities.slice(0,3).map((f,i)=>{
      const sev = getSeverity(f);
      return `<li class="exec-action-item">
        <span class="exec-action-rank">${i+1}</span>
        <span class="exec-action-text">${esc(f.title)}</span>
        <span class="exec-action-tags">${sevBadge(sev)}<span class="ds-badge ${f.effort==='Low'?'ds-badge--low':'ds-badge--medium'}">${esc(f.effort||'Medium')} effort</span></span>
      </li>`;}).join('')}</ol>`;
  }

  const riskEl = document.getElementById('exec-risk-summary');
  if (riskEl) {
    const s = data.score;
    riskEl.innerHTML = `<div class="exec-risk-list">${[
      ['globe', 'Attack surface',    s.attack_surface],
      ['lock',  'Web security',      s.web_security],
      ['user',  'Identity exposure', s.identity_exposure],
      ['gear',  'Configuration',     s.configuration],
      ['key',   'Credential risk',   s.credential_risk],
    ].map(([ico,label,val])=>{
      const v = Math.max(0, Math.min(100, num(val)));
      return `
      <div class="exec-risk-row">
        <span class="exec-risk-icon">${icon(ico)}</span>
        <span class="exec-risk-label">${label}</span>
        <span class="exec-risk-track" aria-hidden="true"><span class="${scoreTone(v)}" style="width:${v}%"></span></span>
        <span class="exec-risk-val ${v>=70?'pass':'fail'}">${v}<small>/100</small></span>
      </div>`;}).join('')}</div>`;
  }
}

// Category score (higher = safer) → bar tone class.
function scoreTone(v) {
  return v >= 75 ? 'high-score' : v >= 55 ? 'medium-score' : v >= 35 ? 'low-score' : 'critical-score';
}

// ── Sidebar risk badge ────────────────────────────────────────

const RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SECURE'];

function updateSidebarBadge(score) {
  const badge = document.getElementById('sidebar-risk-badge');
  const text  = document.getElementById('sidebar-risk-text');
  if (!badge || !text) return;
  const lvl   = oneOf(score.level, RISK_LEVELS, 'HIGH');
  badge.className = `risk-pill risk-pill--${lvl.toLowerCase()}`;
  text.textContent = `Risk: ${lvl}`;
}

// ── View switching ────────────────────────────────────────────

const VIEW_MAP = {
  overview:'view-overview', findings:'view-findings',
  'attack-paths':'view-attack-paths', remediation:'view-remediation',
  dns:'view-dns', ssl:'view-ssl', headers:'view-headers', subdomains:'view-subdomains',
};

const VIEW_TITLES = {
  overview:       ['Overview',        'Security score, risk breakdown and the AI read-out for this domain.'],
  findings:       ['Findings',        'Every issue found in this scan. Filter by severity and expand for evidence and fixes.'],
  'attack-paths': ['Attack paths',    'How an adversary could chain the weaknesses found into real impact.'],
  remediation:    ['Remediation',     'The highest-value fixes, ordered by impact and effort.'],
  dns:            ['DNS & WHOIS',     'Resolved records, registration details and email authentication.'],
  ssl:            ['SSL / TLS',       'Certificate validity, protocol and expiry.'],
  headers:        ['HTTP headers',    'Browser security headers returned by the site.'],
  subdomains:     ['Subdomains',      'Hosts discovered under this domain and their exposure.'],
  executive:      ['Executive summary', 'A one-screen view of risk and the most important actions.'],
};

function setPageHeading(key) {
  const t = VIEW_TITLES[key] || VIEW_TITLES.overview;
  setEl('view-title', t[0]);
  setEl('view-subtitle', t[1]);
}

function setView(view) {
  currentView = view;
  if (currentMode !== 'analyst') switchMode('analyst');
  document.querySelectorAll('.nav-item').forEach(el=>{ el.classList.remove('active'); el.removeAttribute('aria-current'); });
  const navEl = document.getElementById('nav-'+view);
  if (navEl) { navEl.classList.add('active'); navEl.setAttribute('aria-current', 'page'); }
  Object.values(VIEW_MAP).forEach(id=>{ const el=document.getElementById(id); if(el) el.style.display='none'; });
  const target = document.getElementById(VIEW_MAP[view]);
  if (target) target.style.display='';
  setPageHeading(view);
  if (document.body && document.body.classList) document.body.classList.remove('ds-drawer-open');
  // Keep the menu button's state in sync with the drawer it controls.
  document.querySelectorAll('[data-drawer-toggle]').forEach(btn => btn.setAttribute('aria-expanded', 'false'));
}

function switchMode(mode) {
  currentMode = mode;
  const analystBtn = document.getElementById('mode-analyst');
  const execBtn    = document.getElementById('mode-executive');
  analystBtn.classList.toggle('active',  mode==='analyst');
  execBtn.classList.toggle('active', mode==='executive');
  analystBtn.setAttribute('aria-pressed', String(mode==='analyst'));
  execBtn.setAttribute('aria-pressed', String(mode==='executive'));
  document.getElementById('analyst-view').style.display  = mode==='analyst'  ? '' : 'none';
  document.getElementById('executive-view').style.display= mode==='executive'? 'block' : 'none';
  document.querySelectorAll('.nav-item').forEach(el=>el.classList.toggle('is-dimmed', mode==='executive'));
  setPageHeading(mode==='executive' ? 'executive' : currentView);
}

// ── Overlay ───────────────────────────────────────────────────

function showOverlay(show) {
  const el = document.getElementById('scan-overlay');
  if (el) el.style.display = show ? 'flex' : 'none';
}

function updateProgress(pct, text) {
  const bar   = document.getElementById('progress-bar');
  const pctEl = document.getElementById('progress-pct');
  const txtEl = document.getElementById('scan-status-text');
  if (bar)   bar.style.width     = pct + '%';
  if (pctEl) pctEl.textContent   = pct;
  if (txtEl) txtEl.textContent   = text;
}

// ── Utilities ─────────────────────────────────────────────────

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// Every scan value is attacker-influenced (DNS, TLS, HTTP data from the scanned domain):
// escape text, coerce numbers, and allowlist values used as class names.
function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STEP_TYPES = ['entry', 'weakness', 'attack', 'impact'];

function sleep(ms) { return new Promise(r=>setTimeout(r,ms)); }
