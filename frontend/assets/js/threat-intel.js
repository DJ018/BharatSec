(async () => {
  const API = '/api/threat-intel';
  const IOC_PAGE_SIZE = 50;
  const state = {
    view: 'overview', overview: {}, feeds: [], indicators: [], correlations: [],
    techniques: [], breach: { configured: false, watches: [] }, exposures: [], toastTimer: null, searchTimer: null,
    iocPage: 0, iocQuery: '', iocStatus: '', iocHasMore: false,
  };
  const byId = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }

  async function api(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
      ...options,
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    });
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try { detail = ((d) => (Array.isArray(d) ? d.map((item) => item.msg).join(' ') : d))((await response.json()).detail) || detail; } catch { /* Keep the HTTP fallback. */ }
      throw new Error(detail);
    }
    return response.status === 204 ? null : response.json();
  }

  function toast(message, error = false) {
    const element = byId('intel-toast');
    element.textContent = message;
    element.className = `intel-toast show${error ? ' error' : ''}`;
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => element.classList.remove('show'), 3200);
  }

  function timeAgo(value) {
    if (!value) return 'Never';
    const milliseconds = Date.now() - new Date(value).getTime();
    if (!Number.isFinite(milliseconds)) return 'Unknown';
    if (milliseconds < 60000) return 'Just now';
    if (milliseconds < 3600000) return `${Math.floor(milliseconds / 60000)}m ago`;
    if (milliseconds < 86400000) return `${Math.floor(milliseconds / 3600000)}h ago`;
    return `${Math.floor(milliseconds / 86400000)}d ago`;
  }

  // Inline line icons (24x24, stroke=currentColor) for template strings.
  const ICON_PATHS = {
    radar: '<path d="M19.1 4.9A10 10 0 1 0 22 12"/><path d="M16.2 7.8A6 6 0 1 0 18 12"/><circle cx="12" cy="12" r="2"/><path d="m13.4 10.6 5.7-5.7"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/><path d="M12 15v2"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    refresh: '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 21v-5h5"/><path d="M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5"/>',
    sparkle: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6.3 6.3l2.5 2.5M15.2 15.2l2.5 2.5M6.3 17.7l2.5-2.5M15.2 8.8l2.5-2.5"/>',
  };
  const icon = (name, size = 14, extra = '') => `<svg class="ico ${extra}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;
  const STATUS_VALUES = ['new', 'investigating', 'confirmed', 'ignored'];

  function empty(title, detail, action = '', glyph = 'radar') {
    return `<div class="ds-empty empty-intel"><span class="empty-glyph">${icon(glyph, 20)}</span><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span>${action}</div>`;
  }

  function sourceClass(feed) {
    return feed.status === 'ok' ? 'ok' : feed.status === 'error' ? 'error' : 'not_synced';
  }

  function renderFeeds() {
    let errors = 0;
    let ready = 0;
    for (const feed of state.feeds) {
      const status = byId(`feed-${feed.key}-status`);
      if (!status) continue;
      status.className = `feed-status ${sourceClass(feed)}`;
      status.textContent = feed.status === 'not_synced' ? 'Not synced' : feed.status === 'ok' ? 'Operational' : 'Feed error';
      status.title = feed.detail;
      const count = byId(`feed-${feed.key}-count`);
      if (count) count.textContent = feed.status === 'not_synced' ? '—' : Number(feed.fetched_count || 0).toLocaleString();
      const meta = byId(`feed-${feed.key}-meta`);
      if (meta) {
        meta.textContent = feed.checked_at ? `Checked ${timeAgo(feed.checked_at)}` : 'Never synced';
        meta.title = feed.detail || '';
      }
      if (feed.status === 'ok') ready++;
      if (feed.status === 'error') errors++;
    }
    const health = byId('service-state');
    const rail = document.querySelector('.feed-health');
    const label = errors ? `${errors} feed issue${errors === 1 ? '' : 's'}` : ready ? 'Feeds operational' : 'Awaiting sync';
    health.className = `connection-pill ${errors ? 'error' : ready ? 'online' : ''}`;
    health.lastChild.textContent = label;
    rail.className = `feed-health ${errors ? 'error' : ready ? 'online' : ''}`;
    byId('rail-feed-state').textContent = label;
    byId('feed-mitre-count').textContent = state.techniques.length ? state.techniques.length.toLocaleString() : '—';
    if (state.overview.last_feed_sync) byId('sync-time').textContent = `Synced ${timeAgo(state.overview.last_feed_sync)}`;
    else byId('sync-time').textContent = 'Waiting for first feed sync';
  }

  function indicatorRow(indicator) {
    const confidence = Math.max(0, Math.min(100, Number(indicator.confidence) || 0));
    const confidenceBand = confidence >= 80 ? 'high' : confidence >= 50 ? 'mid' : 'low';
    const status = STATUS_VALUES.includes(indicator.status) ? indicator.status : 'new';
    return `<tr>
      <td><div class="ioc-cell"><code title="${escapeHtml(indicator.ioc)}">${escapeHtml(indicator.ioc)}</code><small>${escapeHtml(indicator.title || indicator.threat_type || 'Threat indicator')}</small></div></td>
      <td><span class="ioc-type">${escapeHtml(indicator.ioc_type)}</span></td>
      <td><span class="source-label" title="${escapeHtml(indicator.source)}">${escapeHtml(indicator.source)}</span></td>
      <td><div class="confidence ${confidenceBand}"><span class="confidence-track"><i style="width:${confidence}%"></i></span><span>${confidence}</span></div></td>
      <td><select class="state-select ${status}" data-ioc-status="${indicator.id}" aria-label="Review state for ${escapeHtml(indicator.ioc)}"><option value="new" ${indicator.status === 'new' ? 'selected' : ''}>New</option><option value="investigating" ${indicator.status === 'investigating' ? 'selected' : ''}>Investigating</option><option value="confirmed" ${indicator.status === 'confirmed' ? 'selected' : ''}>Confirmed</option><option value="ignored" ${indicator.status === 'ignored' ? 'selected' : ''}>Ignored</option></select></td>
      <td class="mono when">${escapeHtml(timeAgo(indicator.last_seen_at))}</td>
      <td><button class="mini-action" type="button" data-enrich="${indicator.id}">${indicator.enriched_at ? 'Details' : 'Enrich'}</button></td>
    </tr>`;
  }

  function renderIndicators(host, indicators, limit = Infinity) {
    if (!indicators.length) {
      const filtered = host.id === 'all-indicators' && (state.iocQuery || state.iocStatus);
      host.innerHTML = filtered
        ? empty('No indicators match these filters', 'Try a broader search term or switch the review state to "All states".', '', 'radar')
        : empty('No indicators here yet', 'Sync threat feeds to pull CISA KEV and URLhaus, or add a known IOC for analyst tracking.', '<button class="ds-btn ds-btn--secondary ds-btn--sm" type="button" data-open="ioc-dialog">Add indicator</button>', 'radar');
      if (host.id === 'all-indicators') byId('indicator-pagination').hidden = true;
      return;
    }
    const rows = indicators.slice(0, limit).map(indicatorRow).join('');
    host.innerHTML = `<div class="ds-table-wrap"><table class="ds-table indicator-table"><thead><tr><th>Indicator</th><th>Type</th><th>Source</th><th>Confidence</th><th>Review</th><th>Last seen</th><th><span class="ds-sr-only">Actions</span></th></tr></thead><tbody>${rows}</tbody></table></div>`;
    if (host.id === 'all-indicators') {
      byId('indicator-pagination').hidden = false;
      byId('indicator-page-label').textContent = `Page ${state.iocPage + 1} · ${indicators.length} indicators`;
      byId('indicator-prev').disabled = state.iocPage === 0;
      byId('indicator-next').disabled = !state.iocHasMore;
    }
  }

  function correlationRow(indicator, match) {
    return `<article class="correlation-row">
      <div class="correlation-indicator"><code title="${escapeHtml(indicator.ioc)}">${escapeHtml(indicator.ioc)}</code><small>${escapeHtml(indicator.ioc_type)} · ${escapeHtml(indicator.source)}</small></div>
      <span class="match-link" aria-hidden="true">${icon('target', 16)}</span>
      <div class="match-asset"><strong>${escapeHtml(match.asset_name)}</strong><span>${escapeHtml(match.asset_domain)}</span></div>
      <span class="ds-badge ds-badge--high match-tag">${escapeHtml(match.match_type)}</span>
      <span class="correlation-basis">${escapeHtml(Number(indicator.confidence))}% confidence</span>
    </article>`;
  }

  function renderCorrelations(host, limit = Infinity) {
    const rows = state.correlations.flatMap((indicator) => (indicator.matches || []).map((match) => ({ indicator, match })));
    byId('correlation-count').textContent = `${rows.length} ${rows.length === 1 ? 'match' : 'matches'}`;
    if (!rows.length) {
      host.innerHTML = empty('No environment matches', 'Matches appear when a domain or URL indicator overlaps an asset in your Security Operations inventory.', '<a class="ds-btn ds-btn--secondary ds-btn--sm" href="soc.html">Review SOC assets</a>', 'target');
      return;
    }
    host.innerHTML = rows.slice(0, limit).map(({ indicator, match }) => correlationRow(indicator, match)).join('');
  }

  function renderTechniques() {
    const used = new Set(state.indicators.flatMap((indicator) => indicator.enrichment?.techniques || []));
    const techniques = state.techniques.filter((technique) => used.has(technique.id));
    const visible = techniques.length ? techniques : state.techniques.slice(0, 4);
    // Display-only: the catalog may omit `id`, so fall back to the T-number in the MITRE URL.
    const displayId = (technique) => technique.id || (String(technique.url || '').match(/\/(T\d{4})(?:\/(\d{3}))?\/?$/) || []).slice(1).filter(Boolean).join('.') || 'ATT&CK';
    byId('technique-list').innerHTML = visible.length
      ? visible.map((technique) => `<a class="technique-row" href="${/^https:\/\//i.test(technique.url || '') ? escapeHtml(technique.url) : '#'}" target="_blank" rel="noopener noreferrer"><span class="technique-id">${escapeHtml(displayId(technique))}</span><span class="technique-name">${escapeHtml(technique.name)}<small>${escapeHtml(technique.tactic)} · ${techniques.length ? 'Referenced by feed enrichment' : 'Reference catalog'}</small></span><span class="technique-open">${icon('external', 14)}</span></a>`).join('')
      : empty('No technique references', 'Enrich an indicator to map it to ATT&CK techniques.', '', 'target');
  }

  function renderExposure() {
    const configured = state.breach.configured;
    const badge = byId('hibp-state');
    badge.textContent = configured ? 'HIBP configured' : 'Provider not configured';
    badge.className = `provider-label${configured ? '' : ' provider-off'}`;
    byId('hibp-config-notice').hidden = configured;
    byId('watch-submit').disabled = !configured;
    byId('watch-domain').disabled = !configured;
    byId('watch-authorized').disabled = !configured;
    const watches = state.breach.watches || [];
    const exposureContent = state.exposures.length
      ? state.exposures.map((exposure) => `<article class="exposure-row"><div class="exposure-name"><strong>${escapeHtml(exposure.breach_name)}</strong><span>${escapeHtml(exposure.domain)}</span></div><span class="exposure-count">${escapeHtml(Number(exposure.affected_accounts).toLocaleString())} <small>accounts</small></span><code>${escapeHtml(timeAgo(exposure.last_seen_at))}</code></article>`).join('')
      : empty('No breach exposure records', configured ? 'Add a provider-verified domain and run a check to review disclosed breach counts.' : 'Configure the provider key and verify a domain before searching historical disclosures.', '', 'lock');
    const watchContent = watches.length
      ? `<div class="watch-list-head"><span>Domain watches</span><span>${watches.length}</span></div>${watches.map((watch) => `<article class="watch-row"><span class="watch-icon">${icon('globe', 16)}</span><div><strong>${escapeHtml(watch.domain)}</strong><small>Last checked ${escapeHtml(timeAgo(watch.last_checked_at))}</small></div><button class="mini-action" data-breach-check="${watch.id}" type="button" ${configured ? '' : 'disabled'}>Check</button><button class="remove-watch" data-breach-remove="${watch.id}" type="button" aria-label="Remove ${escapeHtml(watch.domain)}">${icon('x', 15)}</button></article>`).join('')}`
      : `<div class="watch-list-head"><span>Domain watches</span><span>0</span></div>${empty('No watched domains', configured ? 'Add a domain verified with the configured breach provider.' : 'Provider setup is required before adding watches.', '', 'globe')}`;
    byId('exposure-list').innerHTML = watchContent + `<div class="exposure-records-head">Breach sources · counts only</div>` + exposureContent;
  }

  function updateStats() {
    byId('stat-iocs').textContent = Number(state.overview.active_indicators || 0).toLocaleString();
    byId('stat-kev').textContent = Number(state.overview.kev_count || 0).toLocaleString();
    byId('stat-matches').textContent = Number(state.overview.environment_matches || 0).toLocaleString();
    byId('stat-breaches').textContent = Number(state.overview.breach_exposures || 0).toLocaleString();
    byId('nav-ioc-count').textContent = Number(state.overview.active_indicators || 0).toLocaleString();
    const matchCount = state.correlations.reduce((total, indicator) => total + (indicator.matches?.length || 0), 0);
    byId('nav-match-count').textContent = matchCount.toLocaleString();
  }

  function renderAll() {
    updateStats();
    renderFeeds();
    renderCurrentView();
  }

  function renderCurrentView() {
    if (state.view === 'overview') {
      renderIndicators(byId('desk-indicators'), state.indicators.filter((indicator) => indicator.status !== 'ignored'), 7);
      renderCorrelations(byId('desk-correlations'), 5);
      renderTechniques();
    } else if (state.view === 'indicators') {
      renderIndicators(byId('all-indicators'), state.indicators);
    } else if (state.view === 'correlations') {
      renderCorrelations(byId('all-correlations'));
    } else if (state.view === 'exposure') {
      renderExposure();
    }
  }

  async function fetchIndicatorPage() {
    const params = new URLSearchParams({
      limit: String(IOC_PAGE_SIZE + 1),
      offset: String(state.iocPage * IOC_PAGE_SIZE),
    });
    if (state.iocQuery) params.set('query', state.iocQuery);
    if (state.iocStatus) params.set('status', state.iocStatus);
    const results = await api(`/indicators?${params}`);
    state.iocHasMore = results.length > IOC_PAGE_SIZE;
    state.indicators = results.slice(0, IOC_PAGE_SIZE);
    return state.indicators;
  }

  async function loadData() {
    try {
      const [overview, feeds, indicators, correlations, techniques, breach, exposures] = await Promise.all([
        api('/overview'), api('/feeds'), fetchIndicatorPage(), api('/correlations'),
        api('/techniques'), api('/breach-watches'), api('/breach-exposures'),
      ]);
      state.overview = overview;
      state.feeds = feeds;
      state.indicators = indicators;
      state.correlations = correlations;
      state.techniques = techniques;
      state.breach = breach;
      state.exposures = exposures;
      renderAll();
      const hasFeedErrors = feeds.some((feed) => feed.status === 'error');
      const pill = byId('service-state');
      pill.className = `connection-pill ${hasFeedErrors ? 'error' : 'online'}`;
      pill.lastChild.textContent = hasFeedErrors ? 'Feed attention' : 'Intel service online';
      byId('intel-error').hidden = true;
    } catch (error) {
      byId('service-state').className = 'connection-pill error';
      byId('service-state').lastChild.textContent = 'Service unavailable';
      byId('intel-error-text').textContent = error.message;
      byId('intel-error').hidden = false;
    }
  }

  function setView(view) {
    if (!['overview', 'indicators', 'correlations', 'exposure'].includes(view)) return;
    state.view = view;
    document.querySelectorAll('.intel-view').forEach((section) => { section.hidden = section.id !== `view-${view}`; });
    document.querySelectorAll('.intel-tab').forEach((button) => {
      const selected = button.dataset.view === view;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-selected', String(selected));
    });
    document.querySelectorAll('.intel-nav-item').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
    renderCurrentView();
  }

  function showDialog(id) {
    const dialog = byId(id);
    if (dialog && !dialog.open) dialog.showModal();
  }

  function closeDialog(dialog) {
    if (dialog?.open) dialog.close();
  }

  function analystName() {
    return window.bsGetSession?.()?.name || 'Analyst';
  }

  async function syncFeeds() {
    const button = byId('sync-button');
    button.disabled = true;
    button.classList.add('is-loading');
    button.setAttribute('aria-busy', 'true');
    button.innerHTML = `${icon('refresh', 16, 'sync-icon')}<span class="btn-label">Syncing…</span>`;
    try {
      const results = await api('/feeds/sync', { method: 'POST' });
      await loadData();
      const failed = results.filter((result) => result.status === 'error');
      toast(failed.length ? `${failed.length} feed${failed.length > 1 ? 's' : ''} could not sync. Check feed status.` : 'Threat feeds synchronized.');
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
      button.classList.remove('is-loading');
      button.removeAttribute('aria-busy');
      button.innerHTML = `${icon('refresh', 16, 'sync-icon')}<span class="btn-label">Sync feeds</span>`;
    }
  }

  async function createIndicator(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('[type="submit"]');
    const error = byId('ioc-error');
    error.textContent = '';
    submit.disabled = true;
    const data = new FormData(form);
    try {
      await api('/indicators', {
        method: 'POST',
        body: JSON.stringify({
          ioc: data.get('ioc'), ioc_type: data.get('ioc_type'), title: data.get('title'),
          confidence: Number(data.get('confidence')),
          tags: String(data.get('tags') || '').split(',').map((tag) => tag.trim()).filter(Boolean),
        }),
      });
      closeDialog(byId('ioc-dialog'));
      form.reset();
      await loadData();
      toast('Indicator added to analyst review.');
    } catch (requestError) {
      error.textContent = requestError.message;
    } finally {
      submit.disabled = false;
    }
  }

  async function changeIndicatorStatus(select) {
    const previous = state.indicators.find((indicator) => indicator.id === Number(select.dataset.iocStatus))?.status;
    select.disabled = true;
    try {
      const updated = await api(`/indicators/${select.dataset.iocStatus}`, {
        method: 'PATCH', body: JSON.stringify({ status: select.value }),
      });
      const index = state.indicators.findIndex((indicator) => indicator.id === updated.id);
      if (index >= 0) state.indicators[index] = updated;
      state.filteredIndicators = state.indicators;
      renderAll();
      toast(`Indicator marked ${updated.status}.`);
    } catch (error) {
      if (previous) select.value = previous;
      toast(error.message, true);
    } finally {
      select.disabled = false;
    }
  }

  async function enrichIndicator(button) {
    button.disabled = true;
    button.textContent = '…';
    try {
      const indicator = await api(`/indicators/${button.dataset.enrich}/enrich`, { method: 'POST' });
      const techniques = indicator.enrichment?.techniques || [];
      const mapped = techniques.map((id) => state.techniques.find((technique) => technique.id === id)?.name || id);
      byId('enrich-title').textContent = indicator.ioc_type.toUpperCase() + ' enrichment';
      byId('enrichment-content').innerHTML = `
        <div class="enrich-summary"><code>${escapeHtml(indicator.ioc)}</code><div class="enrich-facts"><span class="ioc-type">${escapeHtml(indicator.ioc_type)}</span><span>${escapeHtml(indicator.source)}</span><span>${escapeHtml(Number(indicator.confidence))}% feed confidence</span><span class="state-chip ${STATUS_VALUES.includes(indicator.status) ? indicator.status : 'new'}">${escapeHtml(indicator.status)}</span></div></div>
        ${mapped.length ? `<div class="enrich-section"><h3>ATT&amp;CK context</h3><ul class="enrich-techniques">${mapped.map((name) => `<li>${escapeHtml(name)}</li>`).join('')}</ul></div>` : ''}
        <div class="enrich-section"><h3>Raw enrichment</h3><pre>${escapeHtml(JSON.stringify(indicator.enrichment || {}, null, 2))}</pre></div>`;
      await loadData();
      showDialog('enrich-dialog');
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = 'Enrich';
    }
  }

  async function filterIndicators() {
    state.iocQuery = byId('ioc-search').value.trim();
    state.iocStatus = byId('ioc-status-filter').value;
    state.iocPage = 0;
    try {
      await fetchIndicatorPage();
      renderIndicators(byId('all-indicators'), state.indicators);
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function changeIndicatorPage(direction) {
    const nextPage = state.iocPage + direction;
    if (nextPage < 0 || (direction > 0 && !state.iocHasMore)) return;
    state.iocPage = nextPage;
    try {
      await fetchIndicatorPage();
      renderIndicators(byId('all-indicators'), state.indicators);
      byId('view-indicators').scrollIntoView({ block: 'start', behavior: 'smooth' });
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function createBreachWatch(event) {
    event.preventDefault();
    const error = byId('watch-error');
    error.textContent = '';
    const submit = byId('watch-submit');
    submit.disabled = true;
    try {
      await api('/breach-watches', {
        method: 'POST', body: JSON.stringify({ domain: byId('watch-domain').value, authorized: byId('watch-authorized').checked }),
      });
      byId('watch-form').reset();
      await loadData();
      toast('Verified-domain watch added. Use Check to request a provider lookup.');
    } catch (requestError) {
      error.textContent = requestError.message;
    } finally {
      submit.disabled = !state.breach.configured;
    }
  }

  async function handleBreachAction(button) {
    button.disabled = true;
    try {
      if (button.dataset.breachCheck) {
        const result = await api(`/breach-watches/${button.dataset.breachCheck}/check`, { method: 'POST' });
        await loadData();
        toast(`Provider check complete: ${result.breach_count} breach sources.`);
      } else if (button.dataset.breachRemove) {
        await api(`/breach-watches/${button.dataset.breachRemove}`, { method: 'DELETE' });
        await loadData();
        toast('Domain watch removed.');
      }
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  document.querySelectorAll('[data-open]').forEach((button) => button.addEventListener('click', () => showDialog(button.dataset.open)));
  document.querySelectorAll('[data-close]').forEach((button) => button.addEventListener('click', () => closeDialog(button.closest('dialog'))));
  document.querySelectorAll('dialog').forEach((dialog) => dialog.addEventListener('click', (event) => { if (event.target === dialog) closeDialog(dialog); }));
  document.addEventListener('click', (event) => {
    const enrichButton = event.target.closest('[data-enrich]');
    if (enrichButton) return enrichIndicator(enrichButton);
    const breachButton = event.target.closest('[data-breach-check], [data-breach-remove]');
    if (breachButton) return handleBreachAction(breachButton);
    // Empty-state call-to-action buttons are rendered after the static listeners above are bound.
    const dynamicOpen = event.target.closest('.empty-intel [data-open]');
    if (dynamicOpen) return showDialog(dynamicOpen.dataset.open);
  });
  document.addEventListener('change', (event) => {
    if (event.target.matches('[data-ioc-status]')) changeIndicatorStatus(event.target);
  });
  byId('ioc-form').addEventListener('submit', createIndicator);
  byId('watch-form').addEventListener('submit', createBreachWatch);
  byId('indicator-prev').addEventListener('click', () => changeIndicatorPage(-1));
  byId('indicator-next').addEventListener('click', () => changeIndicatorPage(1));
  byId('sync-button').addEventListener('click', syncFeeds);
  byId('refresh-button').addEventListener('click', loadData);
  byId('retry-button').addEventListener('click', loadData);
  byId('ioc-search').addEventListener('input', () => {
    window.clearTimeout(state.searchTimer);
    state.searchTimer = window.setTimeout(filterIndicators, 180);
  });
  byId('ioc-status-filter').addEventListener('change', filterIndicators);
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
  loadData();
  // Background refresh must not re-render under someone who is reading a dialog or editing a field.
  const userIsBusy = () => document.hidden || document.querySelector('dialog[open]')
    || document.activeElement?.matches?.('input, select, textarea');
  window.setInterval(() => { if (!userIsBusy()) loadData(); }, 30000);
})();