/* BharatSec Account page: change password, and (admins) manage team members.
   Member data is rendered with textContent / DOM APIs only, never innerHTML. */
(async () => {
  'use strict';

  const byId = (id) => document.getElementById(id);
  let me = null;

  async function api(path, options = {}) {
    const response = await fetch(`/api/auth${path}`, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...options,
    });
    if (response.status === 204) return null;
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = Array.isArray(data.detail) ? data.detail.map((item) => item.msg).join(' ') : data.detail;
      const error = new Error(detail || `Request failed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function showMessage(element, text, kind) {
    element.textContent = text || '';
    element.classList.toggle('is-error', kind === 'error');
    element.classList.toggle('is-success', kind === 'success');
  }

  // Initials from letters/digits only, so "Devesh (owner)" becomes "DO" rather than "D(".
  const initials = (name) => (String(name || '').match(/[\p{L}\p{N}]+/gu) || ['?']).map((word) => word[0]).join('').slice(0, 2).toUpperCase();

  function formatWhen(iso) {
    if (!iso) return 'Never';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return 'N/A';
    const minutes = Math.round((Date.now() - date.getTime()) / 60000);
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} min ago`;
    if (minutes < 1440) return `${Math.round(minutes / 60)} h ago`;
    return date.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // ── Profile ──────────────────────────────────────────────────
  function renderProfile(user) {
    byId('profile-name').textContent = user.name;
    byId('profile-username').textContent = `@${user.username}`;
    byId('profile-avatar').textContent = initials(user.name);
    byId('sidebar-avatar').textContent = initials(user.name);
    byId('sidebar-role').textContent = user.role === 'admin' ? 'Administrator' : 'Analyst';
    const badge = byId('profile-role');
    badge.textContent = user.role === 'admin' ? 'Administrator' : 'Analyst';
    badge.className = `ds-badge ${user.role === 'admin' ? 'ds-badge--accent' : 'ds-badge--primary'}`;
    document.querySelectorAll('.user-display-name').forEach((node) => { node.textContent = user.name; });
    byId('force-banner').hidden = !user.must_change_password;
    // Accounts created with Google/GitHub/etc. have no password yet: offer to set one instead of changing it.
    const hasPassword = user.has_password !== false;
    byId('current-password-field').hidden = !hasPassword;
    byId('security-title').textContent = hasPassword ? 'Change password' : 'Set a password';
    byId('security-subtitle').textContent = hasPassword
      ? 'Use at least 12 characters. Changing it signs you out on your other devices.'
      : `Optional. Lets you also sign in with your username (@${user.username}) and a password.`;
    byId('password-submit').textContent = hasPassword ? 'Update password' : 'Set password';
  }

  // ── Sign-in methods (Google, GitHub, Facebook, Microsoft) ────
  async function loadConnections() {
    const message = byId('connections-message');
    let data;
    try {
      data = await api('/identities');
    } catch (error) {
      return showMessage(message, error.message, 'error');
    }
    const providers = data.providers || [];
    const connected = new Map((data.identities || []).map((identity) => [identity.provider, identity]));
    // Providers that can be connected now, plus any already connected (even if later switched off).
    const keys = [...new Set([...providers.map((provider) => provider.key), ...connected.keys()])];
    byId('connections').hidden = keys.length === 0;
    const items = keys.map((key) => {
      const provider = providers.find((item) => item.key === key) || { key, label: window.bsSocial.LABELS[key] || key };
      const identity = connected.get(key);
      const item = el('li', 'ac-connection');
      const text = el('div', 'ac-connection-text');
      text.append(el('strong', null, provider.label), el('span', null, identity
        ? `Connected${identity.email ? ` · ${identity.email}` : ''}`
        : 'Not connected'));
      item.append(window.bsSocial.icon(key), text);
      if (identity) {
        const disconnect = el('button', 'ds-btn ds-btn--ghost ds-btn--sm', 'Disconnect');
        disconnect.type = 'button';
        disconnect.addEventListener('click', async () => {
          if (!window.confirm(`Stop signing in with ${provider.label}?`)) return;
          try {
            await api(`/identities/${encodeURIComponent(key)}`, { method: 'DELETE' });
            showMessage(message, `${provider.label} disconnected.`, 'success');
          } catch (error) {
            showMessage(message, error.message, 'error');
          }
          loadConnections();
        });
        item.appendChild(disconnect);
      } else if (providers.some((entry) => entry.key === key)) {
        item.appendChild(window.bsSocial.button(provider, { link: true }));
      }
      return item;
    });
    byId('connections-list').replaceChildren(...items);
  }

  // ── Password ─────────────────────────────────────────────────
  function strength(password) {
    let score = 0;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password) || /[^A-Za-z0-9]/.test(password)) score += 1;
    return password.length < 12 ? 1 : Math.min(3, Math.max(1, score - 1));
  }

  byId('new-password').addEventListener('input', (event) => {
    const value = event.target.value;
    const level = value ? strength(value) : 0;
    const bar = byId('strength-bar');
    bar.dataset.level = String(level);
    bar.style.width = `${(level / 3) * 100}%`;
    byId('strength-text').textContent = !value
      ? 'At least 12 characters. A passphrase of a few words works well.'
      : value.length < 12 ? `${12 - value.length} more character${value.length === 11 ? '' : 's'} needed.`
        : ['', 'Acceptable. Longer is stronger.', 'Good password.', 'Strong password.'][level];
  });

  byId('password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const message = byId('password-message');
    const current = byId('current-password').value;
    const next = byId('new-password').value;
    if (!current && me.has_password !== false) return showMessage(message, 'Enter your current password.', 'error');
    if (next.length < 12) return showMessage(message, 'Your new password must be at least 12 characters.', 'error');
    if (next !== byId('confirm-password').value) return showMessage(message, "The new passwords don't match.", 'error');
    const button = byId('password-submit');
    button.disabled = true;
    try {
      const { user } = await api('/password', { method: 'POST', body: JSON.stringify({ current_password: current, new_password: next }) });
      me = user;
      renderProfile(user);
      event.target.reset();
      byId('strength-bar').style.width = '0';
      showMessage(message, 'Password saved. Your other devices have been signed out.', 'success');
    } catch (error) {
      showMessage(message, error.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  // ── Team (admins) ────────────────────────────────────────────
  const teamMessage = byId('team-message');

  function showSecret(intro, secret) {
    byId('secret-intro').textContent = intro;
    byId('secret-value').textContent = secret;
    byId('secret-copy').textContent = 'Copy';
    byId('secret-dialog').showModal();
  }

  byId('secret-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(byId('secret-value').textContent);
      byId('secret-copy').textContent = 'Copied';
    } catch {
      byId('secret-copy').textContent = 'Select and copy';
    }
  });

  document.querySelectorAll('dialog [data-close]').forEach((button) => {
    button.addEventListener('click', () => button.closest('dialog').close());
  });

  function memberRow(member) {
    const row = el('tr');
    const isMe = member.id === me.id;

    const who = el('td');
    const wrap = el('div', 'ac-member');
    wrap.appendChild(el('span', 'ds-avatar', initials(member.name)));
    const text = el('div', 'ac-member-text');
    const name = el('strong', null, member.name);
    if (isMe) name.appendChild(el('span', 'ds-badge ac-you', 'You'));
    const handle = el('span', null, `@${member.username}${member.email ? ` · ${member.email}` : ''}`);
    if ((member.providers || []).length) {
      const providers = el('span', 'ac-member-providers');
      providers.title = `Signs in with ${member.providers.map((key) => window.bsSocial.LABELS[key] || key).join(', ')}`;
      member.providers.forEach((key) => providers.appendChild(window.bsSocial.icon(key)));
      handle.appendChild(providers);
    }
    text.append(name, handle);
    wrap.appendChild(text);
    who.appendChild(wrap);

    const roleCell = el('td');
    const select = el('select', 'ds-select ac-role-select');
    select.setAttribute('aria-label', `Role for ${member.name}`);
    [['analyst', 'Analyst'], ['admin', 'Admin']].forEach(([value, label]) => {
      const option = el('option', null, label);
      option.value = value;
      option.selected = member.role === value;
      select.appendChild(option);
    });
    select.disabled = isMe;
    if (isMe) select.title = "You can't change your own role";
    select.addEventListener('change', async () => {
      try {
        await api(`/users/${member.id}`, { method: 'PATCH', body: JSON.stringify({ role: select.value }) });
        showMessage(teamMessage, `${member.name} is now ${select.value === 'admin' ? 'an admin' : 'an analyst'}.`, 'success');
      } catch (error) {
        showMessage(teamMessage, error.message, 'error');
      }
      loadTeam();
    });
    roleCell.appendChild(select);

    const last = el('td', null, member.must_change_password ? 'Awaiting first sign-in' : formatWhen(member.last_login_at));

    const actions = el('td');
    const actionWrap = el('div', 'ac-row-actions');
    if (!isMe) {
      const reset = el('button', 'ds-btn ds-btn--ghost ds-btn--sm', 'Reset password');
      reset.type = 'button';
      reset.addEventListener('click', async () => {
        if (!window.confirm(`Reset the password for ${member.name}? They will be signed out everywhere.`)) return;
        try {
          const data = await api(`/users/${member.id}/reset-password`, { method: 'POST' });
          showSecret(`New temporary password for ${member.name}. Share it privately; it is shown only once.`, data.temporary_password);
          loadTeam();
        } catch (error) {
          showMessage(teamMessage, error.message, 'error');
        }
      });
      const remove = el('button', 'ds-btn ds-btn--danger ds-btn--sm', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        if (!window.confirm(`Remove ${member.name} from this workspace? They lose access immediately.`)) return;
        try {
          await api(`/users/${member.id}`, { method: 'DELETE' });
          showMessage(teamMessage, `${member.name} was removed.`, 'success');
          loadTeam();
        } catch (error) {
          showMessage(teamMessage, error.message, 'error');
        }
      });
      actionWrap.append(reset, remove);
    }
    actions.appendChild(actionWrap);

    row.append(who, roleCell, last, actions);
    return row;
  }

  async function loadTeam() {
    const body = byId('team-body');
    try {
      const { users } = await api('/users');
      body.replaceChildren(...users.map(memberRow));
    } catch (error) {
      const row = el('tr');
      const cell = el('td');
      cell.colSpan = 4;
      cell.appendChild(el('div', 'ds-empty', error.message));
      row.appendChild(cell);
      body.replaceChildren(row);
    }
  }

  byId('add-member-button').addEventListener('click', () => {
    byId('member-form').reset();
    showMessage(byId('member-message'), '');
    byId('member-dialog').showModal();
    byId('member-email').focus();
  });

  byId('member-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const message = byId('member-message');
    const username = byId('member-username').value.trim();
    const email = byId('member-email').value.trim();
    if (!email && !username) return showMessage(message, 'Enter their email, a username, or both.', 'error');
    if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return showMessage(message, 'Enter a valid email address.', 'error');
    if (username && !/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
      return showMessage(message, 'Username must be 3–32 letters, numbers, dots, dashes or underscores.', 'error');
    }
    const button = byId('member-submit');
    button.disabled = true;
    try {
      const data = await api('/users', {
        method: 'POST',
        body: JSON.stringify({ username, email, display_name: byId('member-name').value.trim(), role: byId('member-role').value }),
      });
      byId('member-dialog').close();
      showSecret(
        data.user.email
          ? `Account created for ${data.user.name} (@${data.user.username}). They can sign in with Google, GitHub or Facebook using ${data.user.email}, or with this temporary password, shown only once.`
          : `Account created for ${data.user.name} (@${data.user.username}). Share this temporary password privately; it is shown only once.`,
        data.temporary_password,
      );
      loadTeam();
    } catch (error) {
      showMessage(message, error.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  byId('sign-out').addEventListener('click', async () => {
    try {
      await window.bsLogout();
      window.location.href = '/login.html';
    } catch (error) {
      window.alert(error.message);
    }
  });

  // ── Two-factor sign-in ───────────────────────────────────────
  function showTwoFactor(state) {
    ['tf-off', 'tf-setup', 'tf-recovery', 'tf-on'].forEach((id) => { byId(id).hidden = id !== `tf-${state}`; });
    const on = state === 'on' || state === 'recovery';
    const badge = byId('two-factor-badge');
    badge.textContent = on ? 'On' : 'Off';
    badge.className = `ds-badge ${on ? 'ds-badge--success' : ''}`;
  }

  byId('tf-start').addEventListener('click', async () => {
    const message = byId('tf-message');
    showMessage(message, '');
    try {
      const data = await api('/2fa/setup', { method: 'POST' });
      byId('tf-secret').textContent = data.secret.replace(/(.{4})/g, '$1 ').trim();
      const qr = window.qrcode ? window.qrcode(0, 'M') : null;
      if (qr) {
        qr.addData(data.otpauth_uri);
        qr.make();
        byId('tf-qr').src = qr.createDataURL(5, 2);
        byId('tf-qr').parentElement.hidden = false;
      } else {
        byId('tf-qr').parentElement.hidden = true;  // the setup key still works
      }
      byId('tf-code').value = '';
      showTwoFactor('setup');
      byId('tf-code').focus();
    } catch (error) {
      showMessage(message, error.message, 'error');
    }
  });

  byId('tf-secret-copy').addEventListener('click', () => {
    navigator.clipboard?.writeText(byId('tf-secret').textContent.replace(/\s/g, '')).then(
      () => showMessage(byId('tf-message'), 'Setup key copied.', 'success'),
      () => showMessage(byId('tf-message'), 'Copy the key by selecting it.', 'error'),
    );
  });

  byId('tf-cancel').addEventListener('click', () => { showTwoFactor('off'); showMessage(byId('tf-message'), ''); });

  byId('tf-confirm').addEventListener('click', async () => {
    const message = byId('tf-message');
    const button = byId('tf-confirm');
    button.disabled = true;
    try {
      const data = await api('/2fa/enable', { method: 'POST', body: JSON.stringify({ code: byId('tf-code').value.trim() }) });
      const list = byId('tf-codes');
      list.replaceChildren(...data.recovery_codes.map((code) => el('li', null, code)));
      showTwoFactor('recovery');
      showMessage(message, 'Two-factor sign-in is on.', 'success');
      me.two_factor = true;
    } catch (error) {
      showMessage(message, error.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  byId('tf-codes-copy').addEventListener('click', () => {
    const text = [...byId('tf-codes').children].map((li) => li.textContent).join('\n');
    navigator.clipboard?.writeText(text).then(
      () => showMessage(byId('tf-message'), 'Recovery codes copied. Store them in a password manager.', 'success'),
      () => showMessage(byId('tf-message'), 'Copy the codes by selecting them.', 'error'),
    );
  });

  byId('tf-done').addEventListener('click', () => {
    byId('tf-codes').replaceChildren();  // don't leave them on screen
    showTwoFactor('on');
    showMessage(byId('tf-message'), '');
  });

  byId('tf-disable').addEventListener('click', async () => {
    const message = byId('tf-message');
    try {
      await api('/2fa/disable', { method: 'POST', body: JSON.stringify({ code: byId('tf-off-code').value.trim() }) });
      byId('tf-off-code').value = '';
      showTwoFactor('off');
      showMessage(message, 'Two-factor sign-in is off.', 'success');
      me.two_factor = false;
    } catch (error) {
      showMessage(message, error.message, 'error');
    }
  });

  // ── Boot ─────────────────────────────────────────────────────
  await bsAuthReady;
  if (!window.bsIsLoggedIn()) {
    window.location.href = `/login.html?return=${encodeURIComponent('/account.html')}`;
    return;
  }
  me = window.bsGetSession();
  renderProfile(me);
  showTwoFactor(me.two_factor ? 'on' : 'off');
  loadConnections();
  // A failed connect comes back as ?oauth_error=…; show it, then tidy the address bar.
  const params = new URLSearchParams(window.location.search);
  if (params.get('oauth_error')) {
    showMessage(byId('connections-message'), params.get('oauth_error').slice(0, 300), 'error');
    params.delete('oauth_error');
    const query = params.toString();
    window.history.replaceState(null, '', `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`);
  }
  if (me.must_change_password) byId('current-password').focus();
  if (me.role === 'admin') {
    byId('team').hidden = false;
    byId('nav-team').hidden = false;
    loadTeam();
  }
})();
