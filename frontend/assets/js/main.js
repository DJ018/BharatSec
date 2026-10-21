/* ============================================================
   BharatSec — Landing Page JavaScript
   ============================================================ */

// ── Navbar: glass on scroll + mobile menu ─────────────────────

(function () {
  const navbar = document.getElementById('navbar');
  if (!navbar) return;

  function syncScrolled() {
    navbar.classList.toggle('scrolled', window.scrollY > 12);
  }
  window.addEventListener('scroll', syncScrolled, { passive: true });
  syncScrolled();

  const menuBtn = document.getElementById('lp-menu-btn');
  const links = document.getElementById('lp-nav-links');
  if (!menuBtn || !links) return;

  function setMenu(open) {
    navbar.classList.toggle('is-menu-open', open);
    menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    menuBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  }
  menuBtn.addEventListener('click', function () {
    setMenu(!navbar.classList.contains('is-menu-open'));
  });
  links.addEventListener('click', function (event) {
    if (event.target.closest('a')) setMenu(false);
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && navbar.classList.contains('is-menu-open')) {
      setMenu(false);
      menuBtn.focus();
    }
  });
})();

// ── Domain Validation ─────────────────────────────────────────

/**
 * Normalize a raw domain string: trim, lowercase, strip protocol,
 * strip www. prefix, and remove trailing paths/query strings.
 */
function normalizeDomain(raw) {
  let d = raw.trim().toLowerCase();
  // Strip protocol
  d = d.replace(/^https?:\/\//, '');
  // Strip www. prefix
  d = d.replace(/^www\./, '');
  // Strip path, query, hash
  d = d.split('/')[0];
  d = d.split('?')[0];
  d = d.split('#')[0];
  return d;
}

/**
 * Validate a normalized domain string.
 * Checks hostname regex and that the TLD looks plausible.
 */
function isValidDomain(domain) {
  if (!domain) return false;
  // Hostname regex: alphanumeric + hyphens, at least one dot, valid TLD
  const hostnameRe = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!hostnameRe.test(domain)) return false;
  // Reject domains that are only TLD (e.g. "com", "co.in" without a label)
  const parts = domain.split('.');
  if (parts.length < 2) return false;
  // Reject IP addresses
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) return false;
  return true;
}

// In local development the landing page may be opened via file:// or Live
// Server. Route those users to FastAPI so dashboard assets and API requests
// are served from the same backend origin.
function getBharatSecBackendBase() {
  if (window.BHARATSEC_API_BASE) {
    return window.BHARATSEC_API_BASE.replace(/\/$/, '');
  }
  const isLocalFrontend = window.location.protocol === 'file:' ||
    (['localhost', '127.0.0.1'].includes(window.location.hostname) && window.location.port !== '8000');
  return isLocalFrontend ? 'http://127.0.0.1:8000' : '';
}

// ── Scan UI Helpers ───────────────────────────────────────────

const SCAN_ARROW_ICON = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>';

function setScanLoading(isLoading) {
  const btn = document.getElementById('scan-btn');
  const input = document.getElementById('domain-input');
  if (!btn || !input) return;
  if (isLoading) {
    btn.innerHTML = '<span class="scan-spinner" aria-hidden="true"></span> Scanning…';
    btn.disabled = true;
    input.disabled = true;
  } else {
    btn.innerHTML = 'Run assessment ' + SCAN_ARROW_ICON;
    btn.disabled = false;
    input.disabled = false;
  }
}

function showScanError(message) {
  // Remove any existing error
  const old = document.getElementById('scan-error');
  if (old) old.remove();

  const input = document.getElementById('domain-input');
  if (input) {
    input.classList.remove('is-invalid');
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
  }

  if (!message) return;
  if (!input) return;

  const err = document.createElement('div');
  err.id = 'scan-error';
  err.className = 'scan-error';
  err.setAttribute('role', 'alert');
  err.textContent = message;

  // Insert after the scan-input-row
  const row = input.closest('.scan-input-row');
  if (row && row.parentNode) {
    row.parentNode.insertBefore(err, row.nextSibling);
  }

  // Highlight the input
  input.classList.add('is-invalid');
  input.setAttribute('aria-invalid', 'true');
  input.setAttribute('aria-describedby', 'scan-error');
  setTimeout(function () {
    input.classList.remove('is-invalid');
  }, 3000);
}

// ── Start Scan ────────────────────────────────────────────────

async function handleScanSubmit() {
  const input = document.getElementById('domain-input');
  const authCheck = document.getElementById('auth-check');

  if (!input) return;

  // Clear previous error
  showScanError('');

  var raw = input.value;
  var domain = normalizeDomain(raw);

  if (!raw.trim()) {
    showScanError('Please enter a domain to scan.');
    input.focus();
    return;
  }

  if (!isValidDomain(domain)) {
    showScanError('Please enter a valid domain (e.g., example.com).');
    input.focus();
    return;
  }

  if (authCheck && !authCheck.checked) {
    showScanError('Please confirm you are authorized to scan this domain.');
    return;
  }

  setScanLoading(true);

  // Small delay so the user sees the loading state
  await new Promise(function (r) { return setTimeout(r, 200); });

  // Redirect to the backend-hosted dashboard in local development. Otherwise
  // keep the normal same-origin dashboard route.
  const backendBase = getBharatSecBackendBase();
  const dashboardPath = backendBase ? `${backendBase}/dashboard.html` : 'dashboard.html';
  window.location.href = dashboardPath + '?domain=' + encodeURIComponent(domain);
}

// startScan() is defined in index.html with auth-gating logic


// ── Domain input reference ────────────────────────────────────

var domainInput = document.getElementById('domain-input');

// ── "Scan" shortcuts elsewhere on the page focus the hero input ──

document.addEventListener('click', function (event) {
  const trigger = event.target.closest && event.target.closest('[data-scan-focus]');
  if (!trigger || !domainInput) return;
  event.preventDefault();
  const scanBox = document.getElementById('scan');
  if (scanBox) scanBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
  domainInput.focus({ preventScroll: true });
});

// ── Placeholder typing animation ──────────────────────────────

var typing = false;

async function typeDemoText() {
  if (typing) return;
  // Leave the placeholder alone while the user is typing in the field.
  if (document.activeElement === domainInput || domainInput.value) return;
  typing = true;

  var texts = ['example.com', 'yourcompany.com', 'startup.in', 'gov.in'];
  var text = texts[Math.floor(Math.random() * texts.length)];

  // Type
  for (var i = 0; i <= text.length; i++) {
    domainInput.placeholder = text.slice(0, i) + (i < text.length ? '|' : '');
    await sleep(80 + Math.random() * 40);
  }

  await sleep(1500);

  // Erase
  for (var i = text.length; i >= 0; i--) {
    domainInput.placeholder = text.slice(0, i);
    await sleep(40);
  }

  domainInput.placeholder = 'yourcompany.com';
  typing = false;
}

function sleep(ms) { return new Promise(function (r) { return setTimeout(r, ms); }); }

var prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

if (domainInput && !prefersReducedMotion) {
  setInterval(function () { typeDemoText(); }, 4000);
}

// Allow Enter key in input
if (domainInput) {
  domainInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') (typeof startScan === 'function' ? startScan : handleScanSubmit)();
  });
}

// ── Scroll reveal animations ──────────────────────────────────

(function () {
  const items = document.querySelectorAll('[data-reveal]');
  if (!items.length || prefersReducedMotion || !('IntersectionObserver' in window)) return;

  document.documentElement.classList.add('lp-reveal-ready');

  const observer = new IntersectionObserver((entries) => {
    observerAlive = true; // the observer reports every target once on start
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        // Stagger siblings slightly for a calmer cascade.
        const siblings = Array.prototype.indexOf.call(entry.target.parentNode.children, entry.target);
        const target = entry.target;
        target.style.transitionDelay = Math.min(siblings, 5) * 60 + 'ms';
        target.classList.add('is-visible');
        // Clear the stagger so later hover transitions are not delayed.
        setTimeout(function () { target.style.transitionDelay = ''; }, 900);
        observer.unobserve(target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

  let observerAlive = false;
  items.forEach(el => observer.observe(el));

  // Fallback: if the observer never fires (old/embedded browsers), show everything.
  setTimeout(function () {
    if (!observerAlive) items.forEach(function (el) { el.classList.add('is-visible'); });
  }, 2500);
})();

// Arriving at index.html#scan (e.g. from the "Domain scanner" link) puts the cursor in the domain box.
(function focusScanBox() {
  if (window.location.hash !== '#scan') return;
  const input = document.getElementById('domain-input');
  if (input) input.focus({ preventScroll: false });
})();
