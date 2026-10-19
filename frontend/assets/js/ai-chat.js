/* BharatSec AI — shared chat helpers (landing assistant + dashboard Copilot).
   - BharatSecAI.renderMarkdown(text): safe Markdown → DocumentFragment. Model output is NEVER assigned to
     innerHTML; every node is created with DOM APIs, and links are limited to http(s)/mailto.
   - BharatSecAI.stream(url, body, handlers): POST and read server-sent events (meta / delta / error / done).
   - BharatSecAI.status(): { mode: 'online' | 'offline', providers: [...] }. */
(function () {
  'use strict';

  const SAFE_URL = /^(https?:|mailto:)/i;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // Inline syntax: `code`, **bold**, *italic* / _italic_, [text](url), bare https:// links.
  const INLINE = /(`[^`\n]+`)|(\*\*(?:[^*\n]|\*(?!\*))+\*\*)|(\*[^*\s][^*\n]*\*|\b_[^_\n]+_\b)|(\[[^\]\n]+\]\([^)\s]+\))|(https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g;

  function appendInline(parent, text) {
    let last = 0;
    // matchAll iterates a private copy of the regex, so the recursive calls below
    // (bold/italic contents) cannot reset this loop's position.
    for (const match of text.matchAll(INLINE)) {
      if (match.index > last) parent.appendChild(document.createTextNode(text.slice(last, match.index)));
      const token = match[0];
      if (match[1]) {
        parent.appendChild(el('code', null, token.slice(1, -1)));
      } else if (match[2]) {
        const strong = el('strong');
        appendInline(strong, token.slice(2, -2));
        parent.appendChild(strong);
      } else if (match[3]) {
        const em = el('em');
        appendInline(em, token.slice(1, -1));
        parent.appendChild(em);
      } else if (match[4]) {
        const split = token.indexOf('](');
        appendLink(parent, token.slice(1, split), token.slice(split + 2, -1));
      } else {
        appendLink(parent, token, token);
      }
      last = match.index + token.length;
    }
    if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
  }

  function appendLink(parent, label, href) {
    if (!SAFE_URL.test(href)) {
      parent.appendChild(document.createTextNode(label));
      return;
    }
    const a = el('a', null, label);
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer nofollow';
    parent.appendChild(a);
  }

  function codeBlock(code, lang) {
    const wrap = el('div', 'ds-md-code');
    const bar = el('div', 'ds-md-code-bar');
    bar.appendChild(el('span', null, lang || 'code'));
    const copy = el('button', 'ds-md-copy', 'Copy');
    copy.type = 'button';
    copy.addEventListener('click', () => {
      navigator.clipboard?.writeText(code).then(() => {
        copy.textContent = 'Copied';
        setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
      }).catch(() => { copy.textContent = 'Press Ctrl+C'; });
    });
    bar.appendChild(copy);
    const pre = el('pre');
    pre.appendChild(el('code', null, code));
    wrap.append(bar, pre);
    return wrap;
  }

  function tableBlock(rows) {
    const cells = (row) => row.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
    const wrap = el('div', 'ds-md-table');
    const table = el('table');
    const thead = el('thead');
    const headRow = el('tr');
    cells(rows[0]).forEach((c) => { const th = el('th'); appendInline(th, c); headRow.appendChild(th); });
    thead.appendChild(headRow);
    const tbody = el('tbody');
    rows.slice(2).forEach((row) => {
      const tr = el('tr');
      cells(row).forEach((c) => { const td = el('td'); appendInline(td, c); tr.appendChild(td); });
      tbody.appendChild(tr);
    });
    table.append(thead, tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function renderMarkdown(source) {
    const fragment = document.createDocumentFragment();
    const lines = String(source || '').replace(/\r\n?/g, '\n').split('\n');
    let i = 0;
    let paragraph = [];

    const flushParagraph = () => {
      if (!paragraph.length) return;
      const p = el('p');
      paragraph.forEach((line, index) => {
        if (index) p.appendChild(el('br'));
        appendInline(p, line);
      });
      fragment.appendChild(p);
      paragraph = [];
    };

    while (i < lines.length) {
      const line = lines[i];
      const fence = line.match(/^\s*```\s*([\w+#.-]*)\s*$/);
      if (fence) {
        flushParagraph();
        const body = [];
        i += 1;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) { body.push(lines[i]); i += 1; }
        i += 1; // closing fence (absent while still streaming)
        fragment.appendChild(codeBlock(body.join('\n'), fence[1]));
        continue;
      }
      const heading = line.match(/^\s*(#{1,4})\s+(.*)$/);
      if (heading) {
        flushParagraph();
        const h = el(`h${Math.min(heading[1].length + 2, 6)}`);
        appendInline(h, heading[2].replace(/\s*#+\s*$/, ''));
        fragment.appendChild(h);
        i += 1;
        continue;
      }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
        flushParagraph();
        fragment.appendChild(el('hr'));
        i += 1;
        continue;
      }
      if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+-[\s:|-]*\|?\s*$/.test(lines[i + 1])) {
        flushParagraph();
        const rows = [];
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(lines[i]); i += 1; }
        fragment.appendChild(tableBlock(rows));
        continue;
      }
      if (/^\s*>\s?/.test(line)) {
        flushParagraph();
        const quote = el('blockquote');
        while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
          const p = el('p');
          appendInline(p, lines[i].replace(/^\s*>\s?/, ''));
          quote.appendChild(p);
          i += 1;
        }
        fragment.appendChild(quote);
        continue;
      }
      const listItem = line.match(/^\s*([-*+•]|\d+[.)])\s+(.*)$/);
      if (listItem) {
        flushParagraph();
        const ordered = /\d/.test(listItem[1]);
        const list = el(ordered ? 'ol' : 'ul');
        while (i < lines.length) {
          const item = lines[i].match(/^\s*([-*+•]|\d+[.)])\s+(.*)$/);
          if (!item || /\d/.test(item[1]) !== ordered) break;
          const li = el('li');
          appendInline(li, item[2]);
          list.appendChild(li);
          i += 1;
        }
        fragment.appendChild(list);
        continue;
      }
      if (!line.trim()) {
        flushParagraph();
        i += 1;
        continue;
      }
      paragraph.push(line.trim());
      i += 1;
    }
    flushParagraph();
    return fragment;
  }

  async function stream(url, body, handlers = {}) {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
      signal: handlers.signal,
    });
    if (!response.ok || !response.body) {
      const data = await response.json().catch(() => ({}));
      const detail = Array.isArray(data.detail) ? data.detail.map((item) => item.msg).join(' ') : data.detail;
      const error = new Error(detail || `BharatSec AI request failed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let text = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const raw = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const data = raw.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('');
        if (!data) continue;
        let event;
        try { event = JSON.parse(data); } catch { continue; }
        if (event.type === 'meta') handlers.onMeta?.(event);
        else if (event.type === 'delta') { text += event.text || ''; handlers.onDelta?.(text, event.text || ''); }
        else if (event.type === 'error') handlers.onError?.(event.message || 'The answer was interrupted.');
        else if (event.type === 'done') handlers.onDone?.(text);
      }
    }
    return text;
  }

  let statusPromise = null;
  function status() {
    statusPromise = statusPromise || fetch('/api/ai/status', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : { mode: 'unknown', providers: [] }))
      .catch(() => ({ mode: 'unknown', providers: [] }));
    return statusPromise;
  }

  function sourceLabel(source, model) {
    if (source === 'gemini') return `Gemini${model ? ` · ${model}` : ''}`;
    if (source === 'openai') return `OpenAI${model ? ` · ${model}` : ''}`;
    if (source === 'rules') return 'Offline knowledge';
    if (source === 'local') return 'Offline (no connection)';
    if (source === 'signin') return 'Account required';
    return 'BharatSec AI';
  }

  window.BharatSecAI = { renderMarkdown, stream, status, sourceLabel };
})();
