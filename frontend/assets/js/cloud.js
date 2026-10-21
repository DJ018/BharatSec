(async () => {
  const API = (() => {
    if (window.BHARATSEC_API_BASE) return window.BHARATSEC_API_BASE.replace(/\/$/, '');
    const localFrontend = window.location.protocol === 'file:' ||
      (['localhost', '127.0.0.1'].includes(window.location.hostname) && window.location.port !== '8000');
    return localFrontend ? 'http://127.0.0.1:8000' : '';
  })();
  const PROVIDER_NAMES = { aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud' };
  const PROVIDER_LOGOS = { aws: 'AWS', azure: 'Az', gcp: 'GCP' };
  const PROVIDER_IDS = ['aws', 'azure', 'gcp'];
  const SEVERITY_CLASS = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
  const STATUS_CLASS = { complete: 'success', running: 'info', error: 'critical' };
  // Static inline SVG icons (no dynamic data is ever interpolated into these strings).
  const svg = (paths, size = 16) => `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
  const ICONS = {
    play: svg('<path d="M7 4.5v15l12-7.5Z"/>'),
    check: svg('<path d="m5 12.5 4.5 4.5L19 7.5"/>', 14),
    arrow: svg('<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>', 14),
    spinner: '<svg class="cl-spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.2-8.6" /></svg>',
    alert: svg('<path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>', 20),
    alertSm: svg('<path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>', 16),
    radar: svg('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 18.5 5.5"/>', 20),
    key: svg('<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3"/><path d="m16 7 3 3"/>', 14),
    statusComplete: svg('<path d="m5 12.5 4.5 4.5L19 7.5"/>', 12),
    statusRunning: svg('<path d="M21 12a9 9 0 1 1-6.2-8.6"/>', 12),
    statusError: svg('<path d="m6 6 12 12M18 6 6 18"/>', 12),
  };
  const state = {
    providers: [],
    scans: [],
    selectedProvider: null,
    selectedScan: null,
    toastTimer: null,
    polling: new Set(),
  };
  const byId = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[character]);
  }

  function toast(message, isError = false) {
    const element = byId('cloud-toast');
    element.textContent = message;
    element.className = `ds-toast cl-toast show${isError ? ' is-error' : ''}`;
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => element.classList.remove('show'), 3500);
  }

  async function api(path, options = {}) {
    const response = await fetch(`${API}/api/cloud${path}`, {
      ...options,
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    });
    if (!response.ok) {
      let detail = `Cloud API request failed (HTTP ${response.status}).`;
      try { detail = ((d) => (Array.isArray(d) ? d.map((item) => item.msg).join(' ') : d))((await response.json()).detail) || detail; } catch { /* Retain the HTTP status. */ }
      throw new Error(detail);
    }
    return response.status === 204 ? null : response.json();
  }

  function setApiState(status, label, detail = '') {
    const element = byId('api-state');
    const modifier = status === 'connected' ? ' ds-status--live' : status === 'failed' ? ' ds-status--error' : ' ds-status--warn';
    element.className = `ds-status api-state ds-hide-sm ${status}${modifier}`;
    element.lastChild.textContent = label;
    byId('service-error').hidden = status !== 'failed';
    byId('service-error-message').textContent = detail;
  }

  function renderProviders() {
    for (const provider of state.providers) {
      const card = document.querySelector(`[data-provider="${provider.id}"]`);
      if (!card) continue;
      card.querySelector('.provider-setup').textContent = provider.setup;
      const total = provider.scans.complete || 0;
      const badge = card.querySelector('.provider-badge');
      badge.textContent = total ? `${total} scan${total === 1 ? '' : 's'}` : 'Not tested';
      badge.className = `provider-badge ds-badge${total ? ' ds-badge--success' : ''}`;
      badge.title = `Provider credentials are checked when a scan runs. ${provider.credential_chain}`;
    }
    byId('metric-providers').textContent = state.providers.length || '—';
  }

  function scanPayload(scan) {
    return scan && typeof scan.findings === 'object' && !Array.isArray(scan.findings)
      ? scan.findings
      : scan;
  }

  function providerName(id) {
    return PROVIDER_NAMES[id] || id;
  }

  function statusBadge(status) {
    const tone = STATUS_CLASS[status] || 'info';
    const icon = status === 'complete' ? ICONS.statusComplete : status === 'running' ? ICONS.statusRunning : status === 'error' ? ICONS.statusError : '';
    return `<span class="history-state ds-badge ds-badge--${tone} ${escapeHtml(status)}">${icon}${escapeHtml(status)}</span>`;
  }

  function renderHistory() {
    byId('metric-scans').textContent = state.scans.filter((scan) => scan.status === 'complete').length;
    const host = byId('history-list');
    if (!state.scans.length) {
      host.innerHTML = '<div class="cl-history-empty">No cloud scans yet. Run an authorized provider assessment to start the history.</div>';
      return;
    }
    const selectedId = state.selectedScan?.scan_id;
    host.innerHTML = state.scans.map((scan) => {
      const payload = scanPayload(scan);
      const summary = payload?.summary || {};
      const findingCount = scan.finding_count ?? (Array.isArray(payload?.findings) ? payload.findings.length : 0);
      const date = scan.completed_at || scan.started_at;
      const dateLabel = date && Number.isFinite(new Date(date).getTime()) ? new Date(date).toLocaleString() : 'Date unavailable';
      const providerId = PROVIDER_IDS.includes(scan.provider) ? scan.provider : 'unknown';
      const detail = scan.status === 'complete'
        ? `${findingCount} finding${findingCount === 1 ? '' : 's'}`
        : scan.status === 'running' ? 'Assessment in progress…' : (scan.error || `${summary.resources_scanned || '—'} resources`);
      const action = scan.status === 'complete'
        ? `<button class="history-action ds-btn ds-btn--ghost ds-btn--sm" type="button" data-open-scan="${escapeHtml(scan.scan_id)}">View findings ${ICONS.arrow}</button>`
        : scan.status === 'error'
          ? `<button class="history-action ds-btn ds-btn--ghost ds-btn--sm" type="button" data-open-scan="${escapeHtml(scan.scan_id)}">Details ${ICONS.arrow}</button>`
          : '<span class="history-action"></span>';
      return `<article class="history-row ${escapeHtml(scan.status)}${scan.scan_id === selectedId ? ' is-selected' : ''}">
        <div class="history-provider"><span class="provider-logo ${providerId}-logo">${escapeHtml(PROVIDER_LOGOS[scan.provider] || scan.provider)}</span>${escapeHtml(providerName(scan.provider))}</div>
        <span class="history-account" title="${escapeHtml(scan.account || '')}">${escapeHtml(scan.account || 'Account pending')}</span>
        <span class="history-findings" title="${escapeHtml(detail)}">${escapeHtml(detail)}</span>
        <span class="history-date">${escapeHtml(dateLabel)}</span>
        ${statusBadge(scan.status)}
        ${action}
      </article>`;
    }).join('');
  }

  function selectedFindings() {
    const payload = scanPayload(state.selectedScan);
    return Array.isArray(payload?.findings) ? payload.findings : [];
  }

  function getFilteredFindings() {
    const query = byId('finding-search').value.trim().toLowerCase();
    const provider = byId('provider-filter').value;
    const severity = byId('severity-filter').value;
    return selectedFindings().filter((finding) => {
      if (provider && finding.provider !== provider) return false;
      if (severity && finding.severity !== severity) return false;
      if (!query) return true;
      return [finding.resource, finding.title, finding.category, finding.description, finding.recommendation, finding.evidence]
        .some((value) => String(value || '').toLowerCase().includes(query));
    });
  }

  // Running / error panel shown in the findings card while the selected scan is not complete.
  function renderScanStatus(scan) {
    const host = byId('scan-status');
    if (!scan || (scan.status !== 'running' && scan.status !== 'error')) {
      host.hidden = true;
      host.innerHTML = '';
      return false;
    }
    const name = escapeHtml(providerName(scan.provider));
    if (scan.status === 'running') {
      host.innerHTML = `<div class="cl-state cl-state--running" role="status">
        <span class="cl-state-icon">${ICONS.radar}</span>
        <div><div class="cl-state-title">Assessing ${name}…</div>
          <p class="cl-state-text">Read-only API calls are inventorying storage, identity and network configuration. Results appear here automatically.</p></div>
        <div class="cl-progress" aria-hidden="true"><i></i></div>
      </div>`;
    } else {
      host.innerHTML = `<div class="cl-state cl-state--error" role="alert">
        <span class="cl-state-icon">${ICONS.alert}</span>
        <div><div class="cl-state-title">${name} scan could not complete</div>
          <p class="cl-state-text">BharatSec could not read this account with the backend's credential chain. Nothing in your cloud was changed.</p>
          <div class="cl-state-error">${escapeHtml(scan.error || 'Check provider credentials and access.')}</div></div>
        <ol class="cl-state-steps">
          <li>Configure ${name} credentials for the user running the BharatSec backend (no keys are entered here).</li>
          <li>Grant the read-only permissions listed in the provider's setup details.</li>
          <li>Select the provider again and start a new scan.</li>
        </ol>
        <div class="cl-state-actions">
          <button class="ds-btn ds-btn--secondary ds-btn--sm" type="button" data-show-setup="${escapeHtml(PROVIDER_IDS.includes(scan.provider) ? scan.provider : '')}">${ICONS.key} View setup requirements</button>
        </div>
      </div>`;
    }
    host.hidden = false;
    return true;
  }

  function renderFindings() {
    const scan = state.selectedScan;
    const payload = scanPayload(scan);
    const findings = getFilteredFindings();
    const hasComplete = scan?.status === 'complete';
    const allFindings = selectedFindings();
    byId('metric-findings').textContent = hasComplete ? allFindings.length : '—';
    byId('metric-critical').textContent = hasComplete ? allFindings.filter((item) => item.severity === 'CRITICAL').length : '—';
    byId('metric-severity-context').textContent = hasComplete
      ? `${allFindings.filter((item) => ['CRITICAL', 'HIGH'].includes(item.severity)).length} critical / high findings`
      : 'From the latest completed scan';
    byId('nav-finding-count').textContent = hasComplete ? allFindings.length : '0';
    byId('findings-caption').textContent = hasComplete
      ? `${providerName(scan.provider)} · ${scan.account || 'cloud account'} · ${payload?.summary?.resources_scanned || 0} resources assessed`
      : scan?.status === 'running' ? `${providerName(scan.provider)} scan in progress…`
        : scan?.status === 'error' ? `${providerName(scan.provider)} scan failed · see details below`
          : 'Run a scan to load cloud configuration findings.';
    byId('findings-rows').innerHTML = findings.map((finding) => {
      const evidence = finding.evidence ? `<details class="evidence-details"><summary>Evidence</summary><p>${escapeHtml(finding.evidence)}</p></details>` : '';
      const tone = SEVERITY_CLASS[finding.severity] || 'info';
      return `<tr>
        <td data-label="Severity"><span class="severity-pill ds-badge ds-badge--dot ds-badge--${tone}">${escapeHtml(finding.severity)}</span></td>
        <td data-label="Resource"><span class="resource-provider">${escapeHtml(providerName(finding.provider))}</span><span class="resource-name">${escapeHtml(finding.resource)}</span></td>
        <td data-label="Finding"><span class="finding-title">${escapeHtml(finding.title)}</span><span class="finding-description">${escapeHtml(finding.description)}</span>${evidence}</td>
        <td data-label="Recommendation">${escapeHtml(finding.recommendation)}</td>
      </tr>`;
    }).join('');
    const showingState = renderScanStatus(scan);
    byId('findings-empty').hidden = findings.length > 0 || showingState;
    byId('findings-table-wrap').hidden = findings.length === 0;
    byId('findings-count').textContent = `${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}${findings.length !== allFindings.length ? ` · filtered from ${allFindings.length}` : ''}`;
    const warnings = payload?.warnings || [];
    const warningsElement = byId('coverage-warnings');
    warningsElement.hidden = !hasComplete || warnings.length === 0;
    warningsElement.innerHTML = warnings.length
      ? `<strong>${ICONS.alertSm}Coverage limitations</strong>${warnings.map((warning) => `<span>${escapeHtml(warning)}</span>`).join('')}`
      : '';
  }

  async function loadData() {
    setApiState('', 'Connecting');
    try {
      const [providers, scans] = await Promise.all([api('/providers'), api('/scans')]);
      if (!Array.isArray(providers) || !Array.isArray(scans)) throw new Error('Cloud API returned an invalid response.');
      state.providers = providers;
      state.scans = scans;
      const previousId = state.selectedScan?.scan_id;
      const selectedSummary = scans.find((scan) => scan.scan_id === previousId)
        || scans.find((scan) => scan.status === 'complete')
        || scans[0]
        || null;
      state.selectedScan = selectedSummary
        ? await api(`/scans/${encodeURIComponent(selectedSummary.scan_id)}`)
        : null;
      renderProviders();
      renderHistory();
      renderFindings();
      setApiState('connected', 'API connected');
      for (const scan of scans.filter((item) => item.status === 'running')) pollScan(scan.scan_id);
    } catch (error) {
      setApiState('failed', 'API unavailable', error.message || 'Could not load cloud scan data. Start the backend and retry.');
    }
  }

  function setScanButtonLabel(mode) {
    const button = byId('scan-selected');
    if (mode === 'starting') button.innerHTML = `${ICONS.spinner}Starting scan…`;
    else if (mode === 'running') button.innerHTML = `${ICONS.spinner}Scan running…`;
    else button.innerHTML = `${ICONS.play}Start scan`;
    button.setAttribute('aria-busy', String(mode === 'starting' || mode === 'running'));
  }

  async function startScan() {
    if (!state.selectedProvider) {
      toast('Select a cloud provider before starting a scan.', true);
      return;
    }
    if (!byId('authorization-check').checked) {
      toast('Confirm that you are authorized to assess this cloud account.', true);
      return;
    }
    const button = byId('scan-selected');
    button.disabled = true;
    setScanButtonLabel('starting');
    try {
      const scan = await api('/scans', {
        method: 'POST',
        body: JSON.stringify({ provider: state.selectedProvider, authorized: true }),
      });
      state.selectedScan = scan;
      // The scan executes inside this request; progress is polled separately.
      api(`/scans/${encodeURIComponent(scan.scan_id)}/run`, { method: 'POST' })
        .catch((error) => console.warn('[BharatSec] Cloud scan run request ended early:', error.message));
      toast(`${PROVIDER_NAMES[scan.provider]} scan started. No resources will be changed.`);
      await loadData();
      state.selectedScan = state.scans.find((item) => item.scan_id === scan.scan_id) || scan;
      renderFindings();
      pollScan(scan.scan_id);
    } catch (error) {
      toast(error.message, true);
    } finally {
      setScanButtonLabel('idle');
      updateScanButton();
    }
  }

  function updateScanButton() {
    const button = byId('scan-selected');
    const busy = [...state.polling].some((scanId) => state.scans.some((scan) => scan.scan_id === scanId && scan.status === 'running'));
    button.disabled = !state.selectedProvider || !byId('authorization-check').checked || busy;
    if (button.getAttribute('aria-busy') !== 'true' || !busy) setScanButtonLabel(busy ? 'running' : 'idle');
  }

  function pollScan(scanId) {
    if (state.polling.has(scanId)) return;
    state.polling.add(scanId);
    updateScanButton();
    const started = Date.now();
    let failures = 0;
    let inFlight = false;
    const timer = window.setInterval(async () => {
      if (inFlight) return;
      if (Date.now() - started > 600000) {
        window.clearInterval(timer);
        state.polling.delete(scanId);
        toast('Cloud scan is taking longer than expected. Refresh scan history to check its status.', true);
        await loadData();
        updateScanButton();
        return;
      }
      inFlight = true;
      try {
        const scan = await api(`/scans/${encodeURIComponent(scanId)}`);
        failures = 0;
        // Only follow this scan if the user has not switched to another one meanwhile.
        if (!state.selectedScan || state.selectedScan.scan_id === scanId) state.selectedScan = scan;
        state.scans = [scan, ...state.scans.filter((item) => item.scan_id !== scanId)];
        renderHistory();
        renderFindings();
        if (scan.status === 'complete' || scan.status === 'error') {
          window.clearInterval(timer);
          state.polling.delete(scanId);
          updateScanButton();
          if (scan.status === 'complete') toast(`${PROVIDER_NAMES[scan.provider]} scan complete: ${Array.isArray(scan.findings) ? scan.findings.length : 0} findings.`);
          else toast(`Cloud scan failed: ${scan.error || 'Check provider credentials and permissions.'}`, true);
        }
      } catch (error) {
        failures += 1;
        if (failures >= 5) {
          window.clearInterval(timer);
          state.polling.delete(scanId);
          toast(error.message || 'Could not read cloud scan status.', true);
          updateScanButton();
        }
      } finally {
        inFlight = false;
      }
    }, 1600);
  }

  function selectProvider(providerId) {
    state.selectedProvider = providerId;
    document.querySelectorAll('.provider-card').forEach((card) => {
      const selected = card.dataset.provider === providerId;
      card.classList.toggle('selected', selected);
      card.querySelector('.provider-select').setAttribute('aria-pressed', String(selected));
      card.querySelector('.provider-select').innerHTML = selected ? `${ICONS.check}Selected` : `Select ${escapeHtml(PROVIDER_NAMES[card.dataset.provider])}`;
    });
    updateScanButton();
    if (!byId('authorization-check').checked) {
      byId('authorization-check').focus();
    }
  }

  async function selectScan(scanId) {
    try {
      state.selectedScan = await api(`/scans/${encodeURIComponent(scanId)}`);
      renderFindings();
      renderHistory();
      byId('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      toast(error.message, true);
    }
  }

  function showSetup(providerId) {
    const card = document.querySelector(`.provider-card[data-provider="${PROVIDER_IDS.includes(providerId) ? providerId : ''}"]`);
    if (!card) return;
    card.querySelector('.setup-details').open = true;
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  // Highlight the sidebar link for the section in view (presentation only).
  function watchSections() {
    const links = [...document.querySelectorAll('[data-section-link]')];
    if (!('IntersectionObserver' in window) || !links.length) return;
    const setActive = (id) => links.forEach((link) => link.classList.toggle('active', link.dataset.sectionLink === id));
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (visible && window.innerHeight + window.scrollY < document.documentElement.scrollHeight - 4) setActive(visible.target.id);
    }, { rootMargin: '-80px 0px -60% 0px' });
    ['providers', 'findings', 'history'].forEach((id) => byId(id) && observer.observe(byId(id)));
    window.addEventListener('scroll', () => {
      if (window.scrollY < 120) setActive('overview');
      else if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) setActive('history');
    }, { passive: true });
  }

  document.querySelectorAll('[data-provider-select]').forEach((button) => {
    button.addEventListener('click', () => selectProvider(button.dataset.providerSelect));
  });
  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const historyButton = target?.closest('[data-open-scan]');
    if (historyButton) selectScan(historyButton.dataset.openScan);
    const setupButton = target?.closest('[data-show-setup]');
    if (setupButton) showSetup(setupButton.dataset.showSetup);
  });
  ['finding-search', 'provider-filter', 'severity-filter'].forEach((id) => byId(id).addEventListener('input', renderFindings));
  byId('authorization-check').addEventListener('change', updateScanButton);
  byId('scan-selected').addEventListener('click', startScan);
  byId('refresh-button').addEventListener('click', loadData);
  byId('retry-button').addEventListener('click', loadData);
  byId('sign-out').addEventListener('click', async () => {
    try {
      await window.bsLogout?.();
      window.location.href = '/login.html';
    } catch (error) {
      toast(error.message, true);
    }
  });
  watchSections();

  await bsAuthReady;
  if (window.bsIsLoggedIn && !window.bsIsLoggedIn()) {
    window.location.href = `/login.html?return=${encodeURIComponent(window.location.href)}`;
    return;
  }
  const session = window.bsGetSession?.();
  if (session?.name) document.querySelectorAll('.user-display-name').forEach((element) => { element.textContent = session.name; });
  loadData();
})();
