/* BharatSec authentication uses server-managed HttpOnly session cookies. */
let bsSession = null;

localStorage.removeItem('bs_users');
localStorage.removeItem('bs_session');
sessionStorage.removeItem('bs_session');

const bsAuthReady = fetch('/api/auth/me', {
  headers: { Accept: 'application/json' },
  credentials: 'same-origin',
})
  .then(async (response) => {
    if (!response.ok) return null;
    const result = await response.json();
    bsSession = result.user || null;
    // Someone signed in with a temporary password must set their own before using the app.
    const exempt = ['/login', '/login.html', '/account', '/account.html'];
    if (bsSession?.must_change_password && !exempt.includes(window.location.pathname)) {
      window.location.replace('/account.html?force=1#security');
    }
    if (bsSession) bsNudgeScheduledJobs();
    return bsSession;
  })
  .catch(() => null);

async function bsAuthRequest(path, payload) {
  let response;
  try {
    response = await fetch(`/api/auth/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
  } catch {
    return { success: false, error: 'BharatSec could not reach the server. Check your connection and try again.' };
  }

  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = result.detail;
    return {
      success: false,
      error: Array.isArray(detail) ? detail.map((item) => item.msg).join(' ') : detail || 'Authentication failed.',
    };
  }

  bsSession = result.user || null;
  return { success: true, session: bsSession };
}

async function bsRegister(username, password, displayName) {
  return bsAuthRequest('register', {
    username: username.trim(),
    password,
    display_name: displayName.trim(),
  });
}

async function bsLogin(username, password, remember = false, code = '') {
  const payload = { username: username.trim(), password, remember };
  if (code) payload.code = code;  // only once the server has asked for a second factor
  return bsAuthRequest('login', payload);
}

function bsGetSession() {
  return bsSession;
}

function bsIsLoggedIn() {
  return bsSession !== null;
}

async function bsLogout() {
  let response;
  try {
    response = await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
    });
  } catch {
    throw new Error('Could not reach the server to sign out. Check your connection and try again.');
  }
  if (!response.ok) {
    throw new Error('The server could not end this session. Please try again.');
  }
  bsSession = null;
}

async function bsRequireAuth(returnUrl) {
  await bsAuthReady;
  if (bsIsLoggedIn()) return true;
  const destination = returnUrl || window.location.href;
  window.location.href = `/login.html?return=${encodeURIComponent(destination)}`;
  return false;
}

/* The server has no always-on process, so SOC checks and threat-feed syncs run when /api/cron/tick is called.
   A schedule calls it too; this backup asks while someone is using the app, at most every 5 minutes per browser.
   The server paces the work itself, so extra calls are cheap no-ops. */
function bsNudgeScheduledJobs() {
  const key = 'bs_jobs_nudged_at';
  try {
    const last = Number(localStorage.getItem(key) || 0);
    if (Date.now() - last < 5 * 60 * 1000) return;
    localStorage.setItem(key, String(Date.now()));
  } catch { /* storage blocked: still nudge */ }
  fetch('/api/cron/tick', { method: 'POST', credentials: 'same-origin', keepalive: true }).catch(() => {});
}
