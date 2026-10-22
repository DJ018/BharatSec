(async () => {
  const API = (() => {
    if (window.BHARATSEC_API_BASE) return window.BHARATSEC_API_BASE.replace(/\/$/, '');
    const localFrontend = window.location.protocol === 'file:' ||
      (['localhost', '127.0.0.1'].includes(window.location.hostname) && window.location.port !== '8000');
    return localFrontend ? 'http://127.0.0.1:8000' : '';
  })();
  const ASSUMPTIONS_KEY = 'bharatsec_risk_assumptions';
  const DEFAULTS = {
    records: 50000,
    recordCost: 1900,
    hourlyImpact: 550000,
    recoveryHours: 9,
    responseCost: 3500000,
    regulatoryCost: 6000000,
    fraudImpact: 12000000,
    breachLikelihood: 16,
    outageLikelihood: 11,
    fraudLikelihood: 8,
  };
  const SAMPLE_SCAN = {
    scan_id: 'illustrative',
    domain: 'example.com',
    completed_at: '',
    findings: [
      { category: 'Email Security', severity: 'HIGH', title: 'Missing DMARC policy', fix: 'Publish and enforce a DMARC policy for the organization domain.' },
      { category: 'Security Headers', severity: 'HIGH', title: 'Missing Content Security Policy', fix: 'Deploy a tested Content Security Policy to reduce script injection exposure.' },
      { category: 'SSL/TLS', severity: 'MEDIUM', title: 'Certificate renewal controls need review', fix: 'Verify certificate auto-renewal and expiry alerting.' },
      { category: 'Email Security', severity: 'MEDIUM', title: 'DKIM not detected', fix: 'Enable DKIM signing and publish the provider-issued DNS key.' },
      { category: 'Configuration', severity: 'MEDIUM', title: 'HTTP not redirected to HTTPS', fix: 'Configure a permanent redirect from HTTP to HTTPS.' },
      { category: 'Domain Security', severity: 'LOW', title: 'Domain ownership controls need review', fix: 'Review registrar access, renewal, and account recovery controls.' },
    ],
  };
  const state = { scans: [], scan: SAMPLE_SCAN, assumptions: { ...DEFAULTS }, toastTimer: null };
  const byId = (id) => document.getElementById(id);
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const likelihoodLift = { CRITICAL: 0.08, HIGH: 0.04, MEDIUM: 0.02, LOW: 0.008, INFO: 0 };
  const SEVERITY_CLASS = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
  const SCENARIO_CLASS = { breach: 'breach', outage: 'outage', fraud: 'fraud' };

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[character]);
  }

  function compactINR(value) {
    if (!Number.isFinite(value) || value < 0) return 'N/A';
    if (value >= 10000000) return `₹${(value / 10000000).toLocaleString('en-IN', { maximumFractionDigits: 1 })} Cr`;
    if (value >= 100000) return `₹${(value / 100000).toLocaleString('en-IN', { maximumFractionDigits: 1 })} L`;
    if (value >= 1000) return `₹${(value / 1000).toLocaleString('en-IN', { maximumFractionDigits: 0 })} K`;
    return `₹${Math.round(value).toLocaleString('en-IN')}`;
  }

  function percent(value) {
    return `${(value * 100).toLocaleString('en-IN', { maximumFractionDigits: 1 })}%`;
  }

  function fullINR(value) {
    return Number.isFinite(value) && value >= 0 ? `₹${Math.round(value).toLocaleString('en-IN')}` : '';
  }

  function updateService(status, message) {
    const element = byId('service-state');
    const modifier = status === 'connected' ? ' ds-status--live' : status === 'failed' ? ' ds-status--error' : ' ds-status--warn';
    element.className = `ds-status service-state ds-hide-sm ${status}${modifier}`;
    // The full failure message is shown in the banner; keep the top-bar pill short.
    element.lastChild.textContent = status === 'failed' ? 'Service unavailable' : message;
    element.title = message;
    byId('service-banner').hidden = status !== 'failed';
    if (status === 'failed') byId('service-message').textContent = message;
  }

  function setFormStatus(message, isError = false) {
    const status = byId('form-status');
    status.textContent = message;
    status.classList.toggle('error', isError);
  }

  function readAssumptions() {
    try {
      const saved = window.localStorage.getItem(ASSUMPTIONS_KEY);
      if (!saved) return { ...DEFAULTS };
      const parsed = JSON.parse(saved);
      const values = {};
      for (const [key, fallback] of Object.entries(DEFAULTS)) {
        const value = parsed[key];
        values[key] = Number.isFinite(value) && value >= 0 ? value : fallback;
      }
      return values;
    } catch (error) {
      setFormStatus(`Saved assumptions could not be read: ${error.message}`, true);
      return { ...DEFAULTS };
    }
  }

  function fillAssumptions() {
    const form = byId('assumptions-form');
    for (const [key, value] of Object.entries(state.assumptions)) form.elements.namedItem(key).value = value;
    updateHints();
  }

  // Readable INR / count echo under large numeric inputs (presentation only).
  function updateHints() {
    const form = byId('assumptions-form');
    document.querySelectorAll('[data-hint-for]').forEach((hint) => {
      const input = form.elements.namedItem(hint.dataset.hintFor);
      const raw = input ? input.value.trim() : '';
      const value = Number(raw);
      if (!raw || !Number.isFinite(value) || value < 0) { hint.textContent = ''; return; }
      hint.textContent = hint.dataset.hintKind === 'inr'
        ? `${fullINR(value)}${value >= 100000 ? ` · ${compactINR(value)}` : ''}`
        : `${Math.round(value).toLocaleString('en-IN')} records`;
    });
  }

  function likelihoodFor(findings, baseline, appliesTo) {
    const relevant = findings.filter((finding) => appliesTo.test(finding.category || ''));
    const probabilityNone = relevant.reduce((remaining, finding) => {
      const severity = String(finding.severity || 'MEDIUM').toUpperCase();
      return remaining * (1 - (likelihoodLift[severity] ?? likelihoodLift.MEDIUM));
    }, 1 - baseline / 100);
    return Math.min(0.99, Math.max(0, 1 - probabilityNone));
  }

  function buildScenarios(scan, assumptions) {
    const findings = Array.isArray(scan.findings) ? scan.findings : [];
    const breachImpact = assumptions.records * assumptions.recordCost + assumptions.responseCost + assumptions.regulatoryCost;
    const outageImpact = assumptions.hourlyImpact * assumptions.recoveryHours + assumptions.responseCost;
    const fraudImpact = assumptions.fraudImpact + assumptions.responseCost * 0.25;
    const scenarios = [
      {
        id: 'breach', name: 'Data breach & response', impact: breachImpact,
        likelihood: likelihoodFor(findings, assumptions.breachLikelihood, /email|identity|credential|security|ssl|web|subdomain|configuration|dns/i),
      },
      {
        id: 'outage', name: 'Business interruption', impact: outageImpact,
        likelihood: likelihoodFor(findings, assumptions.outageLikelihood, /ssl|configuration|availability|domain|attack surface|infrastructure/i),
      },
      {
        id: 'fraud', name: 'Fraud & impersonation', impact: fraudImpact,
        likelihood: likelihoodFor(findings, assumptions.fraudLikelihood, /email|identity|credential|domain|dns/i),
      },
    ];
    return scenarios.map((scenario) => ({ ...scenario, annualLoss: scenario.impact * scenario.likelihood }));
  }

  function businessContext(finding) {
    const category = String(finding.category || '').toLowerCase();
    if (category.includes('email')) return 'Raises the chance of trusted-domain spoofing, payment diversion, or customer trust loss.';
    if (category.includes('ssl') || category.includes('tls')) return 'Weakens secure customer access and can interrupt digital service if certificates lapse.';
    if (category.includes('domain')) return 'Creates a route to domain takeover, service interruption, or trusted-brand abuse.';
    if (category.includes('header') || category.includes('web')) return 'Increases exposure of customer sessions and data to browser-side attacks.';
    if (category.includes('identity') || category.includes('credential')) return 'Increases the chance of unauthorized access to business or customer information.';
    if (category.includes('configuration')) return 'Leaves a preventable control gap that can amplify disruption or data exposure.';
    return 'Adds technical exposure that may contribute to a security event or service disruption.';
  }

  function updateDrivers(findings) {
    const ordered = [...findings].sort((left, right) =>
      (severityOrder[String(left.severity || 'MEDIUM').toUpperCase()] ?? 3) -
      (severityOrder[String(right.severity || 'MEDIUM').toUpperCase()] ?? 3),
    ).slice(0, 8);
    byId('driver-count').textContent = `${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}`;
    byId('driver-rows').innerHTML = ordered.length
      ? ordered.map((finding) => {
        const severity = String(finding.severity || 'MEDIUM').toUpperCase();
        const tone = SEVERITY_CLASS[severity] || 'medium';
        return `<tr>
          <td data-label="Severity"><span class="severity-pill ds-badge ds-badge--dot ds-badge--${tone}">${escapeHtml(severity)}</span></td>
          <td data-label="Technical finding">${escapeHtml(finding.title || 'Untitled finding')}</td>
          <td data-label="Business interpretation">${escapeHtml(businessContext(finding))}</td>
          <td data-label="Recommended action">${escapeHtml(finding.fix || 'Review the control with the responsible security owner.')}</td>
        </tr>`;
      }).join('')
      : '<tr><td class="empty-drivers" colspan="4">No technical findings in this assessment. Confirm scan scope and coverage before interpreting this as low risk.</td></tr>';
  }

  function render() {
    const scan = state.scan;
    const findings = Array.isArray(scan.findings) ? scan.findings : [];
    const scenarios = buildScenarios(scan, state.assumptions);
    const totalAnnualLoss = scenarios.reduce((sum, scenario) => sum + scenario.annualLoss, 0);
    const highestImpact = scenarios.reduce((highest, scenario) => scenario.impact > highest.impact ? scenario : highest, scenarios[0]);
    const criticalHigh = findings.filter((finding) => ['CRITICAL', 'HIGH'].includes(String(finding.severity).toUpperCase())).length;
    const isSample = scan.scan_id === 'illustrative';

    byId('metric-annual-loss').textContent = compactINR(totalAnnualLoss);
    byId('metric-annual-loss').title = fullINR(totalAnnualLoss);
    byId('metric-event-loss').title = fullINR(highestImpact.impact);
    byId('metric-loss-context').textContent = `Across ${scenarios.length} modeled scenarios · expected per year`;
    byId('metric-event-loss').textContent = compactINR(highestImpact.impact);
    byId('metric-event-context').textContent = `${highestImpact.name} · impact if event occurs`;
    byId('metric-findings').textContent = findings.length.toLocaleString('en-IN');
    byId('metric-critical-context').textContent = `${criticalHigh} critical / high severity`;
    byId('metric-confidence').textContent = isSample ? 'Illustrative' : 'Scan-backed';
    byId('confidence-context').textContent = isSample ? 'Sample data · replace before use' : 'Directional estimate · validate assumptions';
    byId('illustrative-banner').hidden = !isSample || byId('dismiss-sample').dataset.dismissed === 'true';

    const maxAnnualLoss = Math.max(...scenarios.map((scenario) => scenario.annualLoss), 1);
    byId('exposure-chart').innerHTML = scenarios.map((scenario) => {
      const width = scenario.annualLoss > 0 ? Math.max(1, scenario.annualLoss / maxAnnualLoss * 100) : 0;
      const tone = SCENARIO_CLASS[scenario.id] || '';
      return `<div class="chart-row">
        <div class="chart-head">
          <span class="chart-label" title="${escapeHtml(scenario.name)}"><i class="scenario-dot ${tone}"></i>${escapeHtml(scenario.name)}</span>
          <span class="chart-value" title="${escapeHtml(fullINR(scenario.annualLoss))}">${escapeHtml(compactINR(scenario.annualLoss))}</span>
        </div>
        <span class="chart-track"><i class="chart-bar ${tone}" style="width:${width.toFixed(1)}%"></i></span>
        <span class="chart-meta">${escapeHtml(percent(scenario.likelihood))} annual likelihood × ${escapeHtml(compactINR(scenario.impact))} per event</span>
      </div>`;
    }).join('');
    byId('chart-maximum').textContent = compactINR(maxAnnualLoss);
    // Share of total expected loss, as one stacked bar + legend.
    byId('exposure-mix').innerHTML = scenarios.map((scenario) => {
      const share = totalAnnualLoss > 0 ? scenario.annualLoss / totalAnnualLoss * 100 : 0;
      return `<i class="${SCENARIO_CLASS[scenario.id] || ''}" style="width:${share.toFixed(1)}%"></i>`;
    }).join('');
    byId('exposure-mix-legend').innerHTML = scenarios.map((scenario) => {
      const share = totalAnnualLoss > 0 ? scenario.annualLoss / totalAnnualLoss * 100 : 0;
      return `<span><i class="scenario-dot ${SCENARIO_CLASS[scenario.id] || ''}"></i>${escapeHtml(scenario.name)} <b>${escapeHtml(share.toLocaleString('en-IN', { maximumFractionDigits: 0 }))}%</b></span>`;
    }).join('');
    byId('scenario-rows').innerHTML = scenarios.map((scenario) => `
      <tr>
        <td><span class="scenario-name"><i class="scenario-dot ${SCENARIO_CLASS[scenario.id] || ''}"></i>${escapeHtml(scenario.name)}</span></td>
        <td class="rk-num">${escapeHtml(percent(scenario.likelihood))}</td>
        <td class="rk-num" title="${escapeHtml(fullINR(scenario.impact))}">${escapeHtml(compactINR(scenario.impact))}</td>
        <td class="rk-num" title="${escapeHtml(fullINR(scenario.annualLoss))}">${escapeHtml(compactINR(scenario.annualLoss))}</td>
      </tr>`).join('') + `
      <tr class="rk-total-row">
        <td><span class="scenario-name">Total expected annual loss</span></td>
        <td class="rk-num"></td>
        <td class="rk-num"></td>
        <td class="rk-num" title="${escapeHtml(fullINR(totalAnnualLoss))}">${escapeHtml(compactINR(totalAnnualLoss))}</td>
      </tr>`;
    updateDrivers(findings);
    byId('last-updated').textContent = isSample
      ? `Illustrative model · ${scan.domain}`
      : `Scan completed ${scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'at an unknown time'} · ${scan.domain}`;
  }

  function updateAssessmentOptions() {
    const picker = byId('assessment-select');
    const selected = new URLSearchParams(window.location.search).get('scan_id');
    picker.innerHTML = '<option value="illustrative">Illustrative assessment</option>' +
      state.scans.map((scan) => `<option value="${escapeHtml(scan.scan_id)}">${escapeHtml(scan.domain)} · ${escapeHtml(scan.completed_at ? new Date(scan.completed_at).toLocaleDateString() : 'Completed scan')}</option>`).join('');
    const initialScan = state.scans.find((scan) => scan.scan_id === selected) || state.scans[0];
    if (initialScan) {
      picker.value = initialScan.scan_id;
      state.scan = initialScan;
    } else {
      picker.value = 'illustrative';
      state.scan = SAMPLE_SCAN;
    }
    render();
  }

  async function loadAssessments() {
    updateService('', 'Connecting');
    try {
      const response = await fetch(`${API}/api/scan/recent`, { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(`Assessment request failed (HTTP ${response.status}).`);
      const scans = await response.json();
      if (!Array.isArray(scans)) throw new Error('Assessment service returned an invalid response.');
      state.scans = scans.filter((scan) => scan && typeof scan.scan_id === 'string' && scan.status === 'complete');
      updateAssessmentOptions();
      updateService('connected', `${state.scans.length} completed`);
    } catch (error) {
      const message = error instanceof TypeError
        ? `Could not reach the scan service at ${API}; start the BharatSec backend and retry.`
        : error.message || 'Could not load completed scans.';
      updateService('failed', message);
    }
  }

  function applyAssumptions(event) {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const values = {};
    for (const key of Object.keys(DEFAULTS)) {
      const value = Number(form.elements.namedItem(key).value);
      if (!Number.isFinite(value) || value < 0) {
        setFormStatus('Enter valid non-negative values for each assumption.', true);
        return;
      }
      values[key] = value;
    }
    state.assumptions = values;
    try {
      window.localStorage.setItem(ASSUMPTIONS_KEY, JSON.stringify(values));
      setFormStatus('Assumptions saved · estimates recalculated.');
    } catch (error) {
      setFormStatus(`Could not save assumptions to this browser: ${error.message}`, true);
    }
    render();
  }

  function resetAssumptions() {
    state.assumptions = { ...DEFAULTS };
    fillAssumptions();
    try {
      window.localStorage.removeItem(ASSUMPTIONS_KEY);
      setFormStatus('Sample assumptions restored.');
    } catch (error) {
      setFormStatus(`Could not clear saved assumptions: ${error.message}`, true);
    }
    render();
  }

  byId('assessment-select').addEventListener('change', (event) => {
    const selected = event.currentTarget.value;
    state.scan = state.scans.find((scan) => scan.scan_id === selected) || SAMPLE_SCAN;
    render();
  });
  byId('assumptions-form').addEventListener('submit', applyAssumptions);
  byId('assumptions-form').addEventListener('input', updateHints);
  byId('reset-assumptions').addEventListener('click', resetAssumptions);
  byId('refresh-button').addEventListener('click', loadAssessments);
  byId('retry-button').addEventListener('click', loadAssessments);
  byId('dismiss-sample').addEventListener('click', (event) => {
    event.currentTarget.dataset.dismissed = 'true';
    byId('illustrative-banner').hidden = true;
  });
  byId('sign-out').addEventListener('click', async () => {
    try {
      await window.bsLogout?.();
      window.location.href = '/login.html';
    } catch (error) {
      alert(error.message);
    }
  });

  // Highlight the sidebar link for the section in view (presentation only).
  (() => {
    const links = [...document.querySelectorAll('[data-section-link]')];
    if (!('IntersectionObserver' in window) || !links.length) return;
    const setActive = (id) => links.forEach((link) => link.classList.toggle('active', link.dataset.sectionLink === id));
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (visible && window.innerHeight + window.scrollY < document.documentElement.scrollHeight - 4) setActive(visible.target.id);
    }, { rootMargin: '-80px 0px -60% 0px' });
    ['overview', 'scenarios', 'assumptions', 'drivers'].forEach((id) => byId(id) && observer.observe(byId(id)));
    window.addEventListener('scroll', () => {
      if (window.scrollY < 120) setActive('overview');
      else if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) setActive('drivers');
    }, { passive: true });
  })();

  await bsAuthReady;
  if (window.bsIsLoggedIn && !window.bsIsLoggedIn()) {
    window.location.href = `/login.html?return=${encodeURIComponent(window.location.href)}`;
    return;
  }
  const session = window.bsGetSession?.();
  if (session?.name) document.querySelectorAll('.user-display-name').forEach((element) => { element.textContent = session.name; });

  state.assumptions = readAssumptions();
  fillAssumptions();
  render();
  loadAssessments();
})();
