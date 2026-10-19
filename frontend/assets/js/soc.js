(async () => {
  const API = '/api/soc';
  const state = { assets: [], alerts: [], incidents: [], view: 'overview', incidentId: null, toastTimer: null };
  const byId = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }

  function setApiState(status, label) {
    const element = byId('api-state');
    element.className = `api-state ${status}`;
    element.lastChild.textContent = label;
    byId('connection-banner').hidden = status !== 'failed';
  }

  async function api(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
      ...options,
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    });
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try { detail = ((d) => (Array.isArray(d) ? d.map((item) => item.msg).join(' ') : d))((await response.json()).detail) || detail; } catch { /* Keep the HTTP status fallback. */ }
      throw new Error(detail);
    }
    return response.status === 204 ? null : response.json();
  }

  function toast(message, isError = false) {
    const element = byId('soc-toast');
    element.textContent = message;
    element.className = `toast show${isError ? ' error' : ''}`;
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => element.classList.remove('show'), 3000);
  }

  function ago(value) {
    if (!value) return 'Never';
    const elapsed = Math.max(0, Date.now() - new Date(value).getTime());
    if (!Number.isFinite(elapsed)) return 'Unknown';
    if (elapsed < 60000) return 'Just now';
    if (elapsed < 3600000) return `${Math.floor(elapsed / 60000)}m ago`;
    if (elapsed < 86400000) return `${Math.floor(elapsed / 3600000)}h ago`;
    return `${Math.floor(elapsed / 86400000)}d ago`;
  }

  function dateTime(value) {
    if (!value) return 'Not checked';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
  }

  // Inline line icons (24x24, stroke=currentColor) for template strings.
  const ICON_PATHS = {
    check: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    server: '<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
    bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    refresh: '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 21v-5h5"/><path d="M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5"/>',
    pause: '<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>',
    play: '<path d="m7 4 13 8-13 8Z"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
    arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    note: '<path d="M4 20h4L19 9l-4-4L4 16Z"/><path d="m13.5 6.5 4 4"/>',
  };
  const icon = (name, size = 14) => `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;

  function statusMarkup(status) {
    const normalized = ['online', 'degraded', 'offline', 'blocked'].includes(status) ? status : 'unknown';
    return `<span class="status-label ${normalized}"><i></i>${escapeHtml(normalized)}</span>`;
  }

  function severityMarkup(severity) {
    const normalized = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity) ? severity : 'LOW';
    return `<span class="ds-badge ds-badge--${normalized.toLowerCase()} sev-badge"><i></i>${normalized}</span>`;
  }

  function stateMarkup(value, allowed) {
    const normalized = allowed.includes(value) ? value : 'unknown';
    return `<span class="state-chip state-${normalized}">${escapeHtml(normalized)}</span>`;
  }

  function emptyState(title, detail, action = '', glyph = 'check') {
    return `<div class="ds-empty empty-state"><span class="empty-mark">${icon(glyph, 20)}</span><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span>${action}</div>`;
  }

  function httpClass(code) {
    if (code == null) return '';
    return code < 400 ? 'ok' : code < 500 ? 'warn' : 'bad';
  }

  function assetRows(assets, limit = Infinity) {
    if (!assets.length) {
      return emptyState('No assets monitored yet', 'Add a public domain you own or are authorized to monitor. Its first check runs automatically.', `<button class="ds-btn ds-btn--primary ds-btn--sm" type="button" data-open="asset-dialog">${icon('plus')}Add first asset</button>`, 'server');
    }
    const compact = limit !== Infinity;
    const rows = assets.slice(0, limit).map((asset) => {
      const tls = asset.tls_days_remaining;
      const tlsClass = tls == null ? '' : tls < 7 ? 'bad' : tls < 21 ? 'warn' : '';
      return `
      <tr class="${asset.enabled ? '' : 'is-paused'}">
        <td><div class="asset-identity"><strong>${escapeHtml(asset.name)}</strong><span>${escapeHtml(asset.domain)}</span></div></td>
        <td>${statusMarkup(asset.enabled ? asset.status : 'unknown')}${asset.enabled ? '' : '<span class="paused-tag">Paused</span>'}</td>
        <td class="mono num ${httpClass(asset.http_status)}">${escapeHtml(asset.http_status ?? '—')}</td>
        <td class="mono num">${asset.response_time_ms == null ? '—' : `${Math.round(asset.response_time_ms)} ms`}</td>
        ${compact ? '' : `<td class="mono num ${tlsClass}">${tls == null ? '—' : `${escapeHtml(tls)}d`}</td>`}
        <td class="mono when" title="${escapeHtml(dateTime(asset.last_checked_at))}">${escapeHtml(ago(asset.last_checked_at))}</td>
        <td><div class="table-actions">
          <button class="row-action" type="button" data-asset-action="check" data-id="${asset.id}" title="Check now">${icon('refresh')}<span>Check</span></button>
          ${compact ? '' : `<button class="row-action" type="button" data-asset-action="toggle" data-enabled="${asset.enabled ? 'false' : 'true'}" data-id="${asset.id}" title="${asset.enabled ? 'Pause' : 'Resume'} monitoring">${icon(asset.enabled ? 'pause' : 'play')}<span>${asset.enabled ? 'Pause' : 'Resume'}</span></button>
          <button class="row-action danger" type="button" data-asset-action="delete" data-id="${asset.id}" title="Remove asset" aria-label="Remove asset">${icon('trash')}</button>`}
        </div></td>
      </tr>`;
    }).join('');
    return `<div class="ds-table-wrap"><table class="ds-table soc-table${compact ? ' is-compact' : ''}"><thead><tr><th>Asset</th><th>State</th><th>HTTP</th><th>Latency</th>${compact ? '' : '<th>TLS left</th>'}<th>Last check</th><th><span class="ds-sr-only">Actions</span></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function alertRows(alerts, limit = Infinity) {
    if (!alerts.length) {
      return emptyState('Queue is clear', state.assets.length
        ? 'No alerts match this view. New detections from monitored assets appear here.'
        : 'Alerts appear once you monitor an asset and a check needs attention.',
      state.assets.length ? '' : `<button class="ds-btn ds-btn--secondary ds-btn--sm" type="button" data-open="asset-dialog">${icon('plus')}Add an asset</button>`, 'bell');
    }
    return `<div class="list-head"><span>Detection</span><span>${alerts.length} ${alerts.length === 1 ? 'signal' : 'signals'}</span></div>` + alerts.slice(0, limit).map((alert) => {
      const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(alert.severity) ? alert.severity.toLowerCase() : 'low';
      return `
      <article class="alert-row sev-${sev}">
        <div class="alert-main">
          <div class="alert-title-line">${severityMarkup(alert.severity)}<strong>${escapeHtml(alert.title)}</strong></div>
          <span class="alert-detail">${escapeHtml(alert.detail)}</span>
          <div class="alert-meta">
            <span class="alert-asset"><b>${escapeHtml(alert.asset_name)}</b><code>${escapeHtml(alert.asset_domain)}</code></span>
            ${stateMarkup(alert.state, ['open', 'acknowledged', 'investigating', 'resolved'])}
            <span class="alert-time" title="${escapeHtml(dateTime(alert.last_seen_at))}">${escapeHtml(ago(alert.last_seen_at))} · ${escapeHtml(alert.occurrences)}×</span>
            ${alert.incident_id ? `<span class="incident-ref">INC-${escapeHtml(String(alert.incident_id).padStart(4, '0'))}</span>` : ''}
          </div>
        </div>
        <div class="table-actions">
          ${alert.state === 'open' ? `<button class="row-action" type="button" data-alert-state="acknowledged" data-id="${alert.id}">Acknowledge</button>` : ''}
          ${alert.state === 'acknowledged' ? `<button class="row-action" type="button" data-alert-state="investigating" data-id="${alert.id}">Investigate</button>` : ''}
          ${alert.state !== 'resolved' ? `<button class="row-action" type="button" data-alert-state="resolved" data-id="${alert.id}">Resolve</button>` : ''}
          ${!alert.incident_id && alert.state !== 'resolved' ? `<button class="row-action accent" type="button" data-alert-incident="${alert.id}">Open incident</button>` : ''}
        </div>
      </article>`;
    }).join('');
  }

  function incidentRows(incidents, limit = Infinity) {
    if (!incidents.length) return emptyState('No active incidents', 'Escalate an alert from the queue, or open an incident manually to track investigation and response.', `<button class="ds-btn ds-btn--secondary ds-btn--sm" type="button" data-open="incident-dialog">${icon('plus')}Open incident</button>`, 'shield');
    return incidents.slice(0, limit).map((incident) => `
      <article class="incident-row">
        <div class="incident-main"><strong>${escapeHtml(incident.title)}</strong><span><code>INC-${escapeHtml(String(incident.id).padStart(4, '0'))}</code> · ${escapeHtml(incident.asset_domain || 'No linked asset')}</span></div>
        <div class="incident-sev">${severityMarkup(incident.severity)}</div>
        <div class="incident-state">${stateMarkup(incident.status, ['open', 'investigating', 'contained', 'resolved'])}</div>
        <span class="incident-meta"><span class="owner-dot">${escapeHtml((incident.owner || '?').trim().charAt(0).toUpperCase() || '?')}</span>${escapeHtml(incident.owner || 'Unassigned')}</span>
        <button class="ds-btn ds-btn--secondary ds-btn--sm incident-open" type="button" data-incident-open="${incident.id}">Open${icon('arrow')}</button>
      </article>`).join('');
  }

  function timelineMarkup(events) {
    return events.map((item, index) => `<div class="timeline-item${index === events.length - 1 ? ' latest' : ''}"><span class="timeline-dot"></span><div class="timeline-copy"><div class="timeline-meta"><strong>${escapeHtml(item.author)}</strong><time>${escapeHtml(dateTime(item.created_at))}</time></div><p>${escapeHtml(item.message)}</p></div></div>`).join('');
  }

  function activeAlerts() {
    return state.alerts.filter((alert) => ['open', 'acknowledged', 'investigating'].includes(alert.state));
  }

  function updateMetrics(overview) {
    byId('metric-assets').textContent = overview.monitored_assets;
    byId('metric-online').textContent = `${overview.online_assets} online`;
    byId('metric-alerts').textContent = overview.open_alerts;
    byId('metric-critical').textContent = `Critical: ${overview.critical_alerts}`;
    byId('metric-incidents').textContent = overview.active_incidents;
    byId('metric-last-check').textContent = ago(overview.last_check_at);
    byId('nav-asset-count').textContent = overview.monitored_assets;
    byId('nav-alert-count').textContent = overview.open_alerts;
    byId('nav-incident-count').textContent = overview.active_incidents;
  }

  function renderAll(overview) {
    updateMetrics(overview);
    const recentAlerts = activeAlerts();
    const activeIncidents = state.incidents.filter((incident) => incident.status !== 'resolved');
    byId('overview-assets').innerHTML = assetRows(state.assets, 5);
    byId('overview-alerts').innerHTML = alertRows(recentAlerts, 5);
    byId('overview-incidents').innerHTML = incidentRows(activeIncidents, 5);
    byId('all-assets').innerHTML = assetRows(state.assets);
    renderAlertFilter();
    renderIncidentFilter();
    updateIncidentAssetOptions();
    byId('updated-label').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  }

  function renderAlertFilter() {
    const filter = byId('alert-filter').value;
    const alerts = filter === 'active' ? activeAlerts() : filter === 'all' ? state.alerts : state.alerts.filter((alert) => alert.state === filter);
    byId('all-alerts').innerHTML = alertRows(alerts);
  }

  function renderIncidentFilter() {
    const filter = byId('incident-filter').value;
    const incidents = filter === 'active' ? state.incidents.filter((incident) => incident.status !== 'resolved') : state.incidents;
    byId('all-incidents').innerHTML = incidentRows(incidents);
  }

  function updateIncidentAssetOptions() {
    const select = byId('incident-asset');
    const current = select.value;
    select.innerHTML = '<option value="">No linked asset</option>' + state.assets.map((asset) => `<option value="${asset.id}">${escapeHtml(asset.name)} · ${escapeHtml(asset.domain)}</option>`).join('');
    if (state.assets.some((asset) => String(asset.id) === current)) select.value = current;
  }

  async function loadData() {
    try {
      const [overview, assets, alerts, incidents] = await Promise.all([
        api('/overview'), api('/assets'), api('/alerts'), api('/incidents'),
      ]);
      state.assets = assets;
      state.alerts = alerts;
      state.incidents = incidents;
      renderAll(overview);
      setApiState('connected', 'Service online');
    } catch (error) {
      setApiState('failed', 'Service unavailable');
      byId('connection-message').textContent = error.message;
    }
  }

  function setView(view) {
    if (!['overview', 'assets', 'alerts', 'incidents'].includes(view)) return;
    state.view = view;
    document.querySelectorAll('.workspace-view').forEach((section) => {
      section.hidden = section.id !== `view-${view}`;
    });
    document.querySelectorAll('.view-tab').forEach((button) => {
      const selected = button.dataset.view === view;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-selected', String(selected));
    });
    document.querySelectorAll('.soc-nav-item').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
  }

  function openDialog(id) {
    const dialog = byId(id);
    if (dialog && !dialog.open) dialog.showModal();
  }

  function closeDialog(dialog) {
    if (dialog?.open) dialog.close();
  }

  async function createAsset(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('[type="submit"]');
    const error = byId('asset-form-error');
    error.textContent = '';
    submit.disabled = true;
    const data = new FormData(form);
    try {
      const asset = await api('/assets', {
        method: 'POST',
        body: JSON.stringify({
          domain: data.get('domain'),
          name: data.get('name'),
          check_interval_seconds: Number(data.get('check_interval_seconds')),
          authorized: data.get('authorized') === 'on',
        }),
      });
      closeDialog(byId('asset-dialog'));
      form.reset();
      await loadData();
      toast(`${asset.domain} added. Its first automatic check is queued.`);
    } catch (requestError) {
      error.textContent = requestError.message;
    } finally {
      submit.disabled = false;
    }
  }

  async function createIncident(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('[type="submit"]');
    const error = byId('incident-form-error');
    error.textContent = '';
    submit.disabled = true;
    const data = new FormData(form);
    try {
      await api('/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title: data.get('title'), severity: data.get('severity'),
          asset_id: data.get('asset_id') ? Number(data.get('asset_id')) : null,
          owner: data.get('owner'), description: data.get('description'),
          author: currentAnalyst(),
        }),
      });
      closeDialog(byId('incident-dialog'));
      form.reset();
      await loadData();
      setView('incidents');
      toast('Incident opened and added to the response timeline.');
    } catch (requestError) {
      error.textContent = requestError.message;
    } finally {
      submit.disabled = false;
    }
  }

  function currentAnalyst() {
    return window.bsGetSession?.()?.name || 'Analyst';
  }

  async function handleAssetAction(button) {
    const id = Number(button.dataset.id);
    const action = button.dataset.assetAction;
    button.disabled = true;
    try {
      if (action === 'check') {
        const asset = await api(`/assets/${id}/check`, { method: 'POST' });
        await loadData();
        toast(`${asset.domain}: ${asset.status}${asset.last_error ? ` · ${asset.last_error}` : ''}`, asset.status === 'offline' || asset.status === 'blocked');
      } else if (action === 'toggle') {
        await api(`/assets/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled: button.dataset.enabled === 'true' }) });
        await loadData();
        toast(button.dataset.enabled === 'true' ? 'Monitoring resumed.' : 'Monitoring paused.');
      } else if (action === 'delete') {
        const asset = state.assets.find((item) => item.id === id);
        if (!window.confirm(`Remove ${asset?.domain || 'this asset'} and its alert history?`)) return;
        await api(`/assets/${id}`, { method: 'DELETE' });
        await loadData();
        toast('Asset and linked monitoring history removed.');
      }
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function updateAlert(button) {
    button.disabled = true;
    try {
      await api(`/alerts/${button.dataset.id}`, {
        method: 'PATCH', body: JSON.stringify({ state: button.dataset.alertState }),
      });
      await loadData();
      toast(`Alert ${button.dataset.alertState}.`);
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function openIncidentFromAlert(button) {
    const alert = state.alerts.find((item) => item.id === Number(button.dataset.alertIncident));
    if (!alert) return;
    button.disabled = true;
    try {
      await api(`/alerts/${alert.id}/incident`, {
        method: 'POST',
        body: JSON.stringify({
          title: alert.title,
          severity: alert.severity,
          description: alert.detail,
          owner: '',
          author: currentAnalyst(),
        }),
      });
      await loadData();
      setView('incidents');
      toast('Incident opened from alert.');
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function showIncident(id) {
    try {
      const incident = await api(`/incidents/${id}`);
      state.incidentId = id;
      byId('incident-detail-id').textContent = `INC-${String(id).padStart(4, '0')}`;
      byId('incident-detail-title').textContent = incident.title;
      byId('detail-status').value = incident.status;
      byId('detail-owner').value = incident.owner || '';
      byId('incident-timeline').innerHTML = incident.events.length
        ? timelineMarkup(incident.events)
        : emptyState('No timeline updates', 'Add a note to record your response actions.', '', 'note');
      openDialog('incident-detail-dialog');
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function changeIncidentStatus() {
    if (!state.incidentId) return;
    try {
      await api(`/incidents/${state.incidentId}`, {
        method: 'PATCH', body: JSON.stringify({ status: byId('detail-status').value, author: currentAnalyst() }),
      });
      await refreshIncidentDetail();
      await loadData();
      toast('Incident status updated.');
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function saveIncidentOwner() {
    if (!state.incidentId) return;
    try {
      await api(`/incidents/${state.incidentId}`, {
        method: 'PATCH', body: JSON.stringify({ owner: byId('detail-owner').value, author: currentAnalyst() }),
      });
      await refreshIncidentDetail();
      await loadData();
      toast('Incident assignment updated.');
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function refreshIncidentDetail() {
    if (!state.incidentId) return;
    const incident = await api(`/incidents/${state.incidentId}`);
    byId('detail-status').value = incident.status;
    byId('detail-owner').value = incident.owner || '';
    byId('incident-timeline').innerHTML = timelineMarkup(incident.events);
  }

  async function addIncidentNote(event) {
    event.preventDefault();
    if (!state.incidentId) return;
    const submit = event.currentTarget.querySelector('[type="submit"]');
    submit.disabled = true;
    try {
      await api(`/incidents/${state.incidentId}/events`, {
        method: 'POST',
        body: JSON.stringify({ message: byId('incident-note').value, author: currentAnalyst() }),
      });
      byId('incident-note').value = '';
      await refreshIncidentDetail();
      await loadData();
      toast('Timeline note added.');
    } catch (error) {
      toast(error.message, true);
    } finally {
      submit.disabled = false;
    }
  }

  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  document.querySelectorAll('[data-open]').forEach((button) => button.addEventListener('click', () => openDialog(button.dataset.open)));
  document.querySelectorAll('[data-close]').forEach((button) => button.addEventListener('click', () => closeDialog(button.closest('dialog'))));
  document.querySelectorAll('dialog').forEach((dialog) => dialog.addEventListener('click', (event) => {
    if (event.target === dialog) closeDialog(dialog);
  }));
  document.addEventListener('click', (event) => {
    const assetButton = event.target.closest('[data-asset-action]');
    if (assetButton) return handleAssetAction(assetButton);
    const alertButton = event.target.closest('[data-alert-state]');
    if (alertButton) return updateAlert(alertButton);
    const incidentButton = event.target.closest('[data-alert-incident]');
    if (incidentButton) return openIncidentFromAlert(incidentButton);
    const openButton = event.target.closest('[data-incident-open]');
    if (openButton) return showIncident(Number(openButton.dataset.incidentOpen));
    // Empty-state call-to-action buttons are rendered after the static listeners above are bound.
    const dynamicOpen = event.target.closest('.empty-state [data-open]');
    if (dynamicOpen) return openDialog(dynamicOpen.dataset.open);
  });
  byId('asset-form').addEventListener('submit', createAsset);
  byId('incident-form').addEventListener('submit', createIncident);
  byId('incident-note-form').addEventListener('submit', addIncidentNote);
  byId('alert-filter').addEventListener('change', renderAlertFilter);
  byId('incident-filter').addEventListener('change', renderIncidentFilter);
  byId('detail-status').addEventListener('change', changeIncidentStatus);
  byId('save-owner').addEventListener('click', saveIncidentOwner);
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

  await bsAuthReady;
  if (window.bsIsLoggedIn && !window.bsIsLoggedIn()) {
    window.location.href = `/login.html?return=${encodeURIComponent(window.location.href)}`;
    return;
  }
  const session = window.bsGetSession?.();
  if (session?.name) document.querySelectorAll('.user-display-name').forEach((element) => { element.textContent = session.name; });

  setApiState('', 'Connecting');
  loadData();
  // Background refresh must not re-render under someone who is reading a dialog or editing a field.
  const userIsBusy = () => document.hidden || document.querySelector('dialog[open]')
    || document.activeElement?.matches?.('input, select, textarea');
  window.setInterval(() => { if (!userIsBusy()) loadData(); }, 15000);
})();