/* BharatSec free tools. The form's data-tool ("ssl" | "email" | "headers") picks the check.
   Results are built with DOM APIs only. */
(function () {
  'use strict';

  const form = document.getElementById('tool-form');
  const result = document.getElementById('tool-result');
  if (!form || !result) return;
  const tool = form.dataset.tool;
  const input = form.querySelector('input');
  const button = form.querySelector('button');

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function row(tone, title, detail, code) {
    const r = el('div', 'tl-row');
    r.appendChild(el('span', `tl-icon is-${tone}`, tone === 'ok' ? '✓' : tone === 'bad' ? '✕' : '!'));
    const body = el('div');
    body.appendChild(el('b', null, title));
    if (detail) body.appendChild(el('p', null, detail));
    if (code) { const p = el('p'); p.appendChild(el('code', null, code)); body.appendChild(p); }
    r.appendChild(body);
    return r;
  }

  function card(title, rows, advice, domain) {
    const c = el('section', 'tl-card');
    c.appendChild(el('h2', null, title));
    const list = el('div', 'tl-rows');
    rows.forEach((r) => list.appendChild(r));
    c.appendChild(list);
    if (advice && advice.length) {
      const box = el('div', 'tl-advice');
      box.appendChild(el('h3', null, 'What to do'));
      const ul = el('ul');
      advice.forEach((line) => ul.appendChild(el('li', null, line)));
      box.appendChild(ul);
      c.appendChild(box);
    }
    const more = el('div', 'tl-more');
    more.appendChild(el('span', null, 'Want the full picture? A full scan also checks DNS, subdomains, TLS and attack paths.'));
    const a = el('a', 'ds-btn ds-btn--brand', `Full free scan of ${domain}`);
    a.href = `/?domain=${encodeURIComponent(domain)}#scan`;
    more.appendChild(a);
    c.appendChild(more);
    return c;
  }

  const renderers = {
    ssl(data) {
      const s = data.ssl || {};
      const rows = [
        row(s.valid ? 'ok' : 'bad', s.valid ? 'Valid certificate' : 'No valid certificate', s.issuer ? `Issued by ${s.issuer}` : null),
        row(!s.valid ? 'bad' : s.days_remaining < 30 ? 'warn' : 'ok', s.expires ? `Expires in ${s.days_remaining} days` : 'Expiry unknown', s.expires ? `Valid until ${new Date(s.expires).toLocaleDateString('en-IN', { dateStyle: 'medium' })}` : null),
        row(/^A/.test(s.grade || '') ? 'ok' : 'warn', `TLS grade ${s.grade || 'N/A'}`, s.protocol ? `Negotiated ${s.protocol}` : null),
      ];
      return card(`SSL / TLS for ${data.domain}`, rows, data.advice, data.domain);
    },
    email(data) {
      const rows = [
        row(data.spf.present ? 'ok' : 'bad', data.spf.present ? 'SPF record found' : 'No SPF record', data.spf.present ? null : 'Anyone can claim to send mail from this domain.', data.spf.record),
        row(data.dkim.present ? 'ok' : 'warn', data.dkim.present ? 'DKIM key found' : 'No DKIM key found on common selectors', data.dkim.present ? null : 'Your provider may use a custom selector; check its DKIM settings.'),
        row(!data.dmarc.present ? 'bad' : data.dmarc.policy === 'none' ? 'warn' : 'ok',
          data.dmarc.present ? `DMARC policy: ${data.dmarc.policy || 'unknown'}` : 'No DMARC record',
          data.dmarc.present ? null : 'Receivers have no instruction for spoofed mail.', data.dmarc.record),
        row(data.mx.length ? 'ok' : 'warn', data.mx.length ? `${data.mx.length} mail server(s)` : 'No MX records', data.mx.slice(0, 3).join(', ') || null),
      ];
      return card(`Email security for ${data.domain}`, rows, data.advice, data.domain);
    },
    headers(data) {
      const rows = [row(data.https_redirect ? 'ok' : 'warn', data.https_redirect ? 'HTTP redirects to HTTPS' : 'HTTP does not redirect to HTTPS', data.status_code ? `Responded with HTTP ${data.status_code}` : null)];
      data.headers.forEach((h) => rows.push(row(h.present ? 'ok' : 'bad', `${h.name}: ${h.present ? 'present' : 'missing'}`, h.why)));
      const advice = data.missing.length ? [`Add the ${data.missing.length} missing header(s) in your web server, CDN or hosting settings.`] : [];
      return card(`Security headers for ${data.domain}`, rows, advice, data.domain);
    },
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const domain = (input.value || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#]/)[0];
    if (!/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)) {
      result.replaceChildren(el('div', 'tl-error', 'Please enter a valid domain, like example.com.'));
      return;
    }
    button.disabled = true;
    const label = button.textContent;
    button.textContent = 'Checking…';
    result.replaceChildren(el('div', 'tl-card', `Checking ${domain}…`));
    try {
      const response = await fetch(`/api/public/tools/${tool}?domain=${encodeURIComponent(domain)}`, { headers: { Accept: 'application/json' } });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'The check could not be completed.');
      result.replaceChildren(renderers[tool](data));
    } catch (error) {
      result.replaceChildren(el('div', 'tl-error', error.message));
    } finally {
      button.disabled = false;
      button.textContent = label;
    }
  });

  const preset = new URLSearchParams(window.location.search).get('domain');
  if (preset) { input.value = preset; form.requestSubmit(); }
})();
