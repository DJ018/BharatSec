/* BharatSec public status page: live component checks and the daily self-scan of bharatsec.vercel.app. */
(function () {
  'use strict';
  const byId = (id) => document.getElementById(id);

  const HEADLINES = {
    operational: 'All systems operational',
    degraded: 'Some systems are running slowly or partly',
    down: 'Part of BharatSec is down',
  };
  const PILLS = { operational: 'Operational', degraded: 'Degraded', down: 'Down', off: 'Not switched on' };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const when = (iso) => {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  };
  const day = (iso) => {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  };

  function renderBanner(state, checkedAt) {
    const banner = byId('st-banner');
    if (!banner) return;
    banner.dataset.state = state;
    byId('st-headline').textContent = HEADLINES[state] || 'Status unavailable';
    byId('st-checked').textContent = checkedAt ? `Checked live at ${when(checkedAt)}.` : 'Live checks could not run. Please try again shortly.';
  }

  function renderComponents(components) {
    const list = byId('st-components');
    if (!list) return;
    list.replaceChildren(...components.map((item) => {
      const row = el('li', 'st-item');
      const text = el('div');
      text.append(el('strong', null, item.name), el('span', null, item.detail));
      const pill = el('span', 'st-pill', PILLS[item.status] || item.status);
      pill.dataset.state = item.status;
      row.append(text, pill);
      return row;
    }));
  }

  function fact(label, value) {
    const row = el('div');
    row.append(el('dt', null, label), el('dd', null, value));
    return row;
  }

  function renderSelfScan(selfScan) {
    const box = byId('st-self');
    if (!box) return;
    const latest = selfScan && selfScan.latest;
    if (!latest) {
      box.replaceChildren(el('p', 'st-empty', 'The first daily self-scan has not finished yet. It runs every morning; check back tomorrow.'));
      return;
    }
    const score = el('div', 'st-score');
    const inner = el('div');
    inner.append(el('b', null, String(latest.score)), el('small', null, 'out of 100'));
    score.append(inner);

    const facts = el('dl', 'st-facts');
    facts.append(
      fact('Website', selfScan.domain),
      fact('SSL/TLS grade', latest.ssl_grade),
      fact('Security headers', `${latest.headers_present} of ${latest.headers_checked} present`),
      fact('Scanned', when(latest.completed_at)),
    );
    const details = el('div');
    const link = el('a', 'ds-btn ds-btn--secondary ds-btn--sm', 'Open the full report');
    link.href = `/report?scan=${encodeURIComponent(latest.scan_id)}`;
    details.append(facts, link);
    box.replaceChildren(score, details);

    const history = byId('st-history');
    if (history && selfScan.history.length > 1) {
      history.hidden = false;
      history.replaceChildren(...selfScan.history.slice().reverse().map((scan) => {
        const row = el('li');
        const bar = el('span', 'st-bar');
        const fill = el('i');
        fill.style.width = `${Math.max(0, Math.min(100, scan.score))}%`;
        bar.append(fill);
        row.append(el('span', null, day(scan.completed_at)), bar, el('b', null, String(scan.score)));
        row.setAttribute('aria-label', `${day(scan.completed_at)}: ${scan.score} out of 100`);
        return row;
      }));
    }
  }

  async function load() {
    try {
      const response = await fetch('/api/public/status', { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(String(response.status));
      const data = await response.json();
      renderBanner(data.status, data.checked_at);
      renderComponents(data.components || []);
      renderSelfScan(data.self_scan);
    } catch {
      renderBanner('error', null);
      const box = byId('st-self');
      if (box) box.replaceChildren(el('p', 'st-empty', 'The self-scan result could not be loaded right now.'));
    }
  }

  load();
})();
