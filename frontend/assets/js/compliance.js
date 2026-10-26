/* BharatSec Compliance: render the team checklist and save ticks and notes. */
(async function () {
  'use strict';

  const byId = (id) => document.getElementById(id);
  const saveState = byId('save-state');
  let data = null;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function setState(text, tone) {
    if (!saveState) return;
    saveState.textContent = text;
    saveState.className = `ds-status ds-hide-sm${tone ? ` ds-status--${tone}` : ''}`;
  }

  function renderProgress() {
    const pct = data.total ? Math.round((data.done / data.total) * 100) : 0;
    byId('overall-ring').style.setProperty('--v', String(pct));
    byId('overall-pct').textContent = `${pct}%`;
    byId('overall-count').textContent = `${data.done} of ${data.total} done`;
    byId('overall-label').textContent = pct === 100 ? 'All done' : pct >= 60 ? 'Good progress' : pct > 0 ? 'Getting started' : 'Not started';

    const bars = byId('framework-bars');
    bars.replaceChildren();
    data.frameworks.forEach((fw) => {
      const row = el('div', 'cp-fw');
      const bar = el('div', 'cp-bar');
      const fill = el('i');
      fill.style.width = `${fw.total ? Math.round((fw.done / fw.total) * 100) : 0}%`;
      bar.appendChild(fill);
      row.append(el('strong', null, fw.name), el('span', null, `${fw.done} / ${fw.total}`), bar);
      bars.appendChild(row);
    });
  }

  function recount() {
    data.done = data.items.filter((item) => item.done).length;
    data.frameworks.forEach((fw) => { fw.done = data.items.filter((item) => item.framework === fw.id && item.done).length; });
    renderProgress();
  }

  async function save(item, changes) {
    setState('Saving…', 'warn');
    try {
      const response = await fetch(`/api/compliance/${encodeURIComponent(item.id)}`, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ done: item.done, ...changes }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      Object.assign(item, await response.json());
      setState('Saved', 'live');
      return true;
    } catch (error) {
      setState('Not saved', 'error');
      return false;
    }
  }

  function itemCard(item) {
    const card = el('article', `cp-item${item.done ? ' is-done' : ''}`);
    const box = el('input', 'cp-check');
    box.type = 'checkbox';
    box.checked = item.done;
    box.setAttribute('aria-label', `Mark done: ${item.title}`);
    box.addEventListener('change', async () => {
      const previous = item.done;
      item.done = box.checked;
      card.classList.toggle('is-done', item.done);
      recount();
      if (!(await save(item, {}))) {
        item.done = previous;
        box.checked = previous;
        card.classList.toggle('is-done', previous);
        recount();
      } else {
        meta.lastChild.textContent = updatedText(item);
      }
    });

    const body = el('div');
    body.appendChild(el('h3', null, item.title));
    body.appendChild(el('p', null, item.why));
    const how = el('p', 'cp-how');
    how.append(el('b', null, 'How: '), document.createTextNode(item.how));
    body.appendChild(how);

    const meta = el('div', 'cp-meta');
    if (item.source) {
      const link = el('a', null, item.source.startsWith('/') ? 'Open in BharatSec' : 'Source');
      link.href = item.source;
      if (!item.source.startsWith('/')) { link.target = '_blank'; link.rel = 'noopener noreferrer'; }
      meta.appendChild(link);
    }
    meta.appendChild(el('span', null, updatedText(item)));
    body.appendChild(meta);

    const note = el('input', 'ds-input cp-note');
    note.type = 'text';
    note.maxLength = 500;
    note.placeholder = 'Add a note (owner, evidence, due date)';
    note.value = item.note || '';
    note.setAttribute('aria-label', `Note for: ${item.title}`);
    note.addEventListener('change', () => save(item, { note: note.value }).then(() => { meta.lastChild.textContent = updatedText(item); }));
    body.appendChild(note);

    card.append(box, body);
    return card;
  }

  function updatedText(item) {
    if (!item.updated_at) return '';
    const when = new Date(item.updated_at);
    const date = isNaN(when) ? '' : when.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    return `Updated ${date}${item.updated_by ? ` by ${item.updated_by}` : ''}`;
  }

  function render() {
    renderProgress();
    const sections = byId('sections');
    sections.replaceChildren();
    data.frameworks.forEach((fw) => {
      const section = el('section', 'cp-section');
      section.id = fw.id;
      const head = el('div', 'cp-section-head');
      head.append(el('h2', null, fw.name), el('p', null, fw.summary));
      section.appendChild(head);
      data.items.filter((item) => item.framework === fw.id).forEach((item) => section.appendChild(itemCard(item)));
      sections.appendChild(section);
    });
  }

  byId('sign-out')?.addEventListener('click', async () => {
    try { await window.bsLogout?.(); } finally { window.location.href = '/login.html'; }
  });

  await window.bsAuthReady;
  if (window.bsIsLoggedIn && !window.bsIsLoggedIn()) {
    window.location.href = `/login.html?return=${encodeURIComponent(window.location.href)}`;
    return;
  }
  const session = window.bsGetSession?.();
  if (session?.name) document.querySelectorAll('.user-display-name').forEach((node) => { node.textContent = session.name; });

  try {
    const response = await fetch('/api/compliance', { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    data = await response.json();
    render();
    setState('Synced', 'live');
  } catch (error) {
    setState('Unavailable', 'error');
    byId('sections').replaceChildren(el('p', 'cp-disclaimer', 'Could not load the checklist. Please refresh the page.'));
  }
})();
