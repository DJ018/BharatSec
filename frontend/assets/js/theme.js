/* BharatSec theme + app-shell behaviour.
   Load synchronously in <head> (before stylesheets) so the saved theme applies before first paint.
   - Theme: dark by default; [data-theme-toggle] buttons switch it; the choice is remembered per browser.
   - Drawer: on narrow screens [data-drawer-toggle] opens the sidebar; the scrim or Escape closes it.
   Pages can react to theme changes via: window.addEventListener('bharatsec:themechange', e => e.detail.theme) */
(function () {
  var KEY = 'bharatsec-theme';
  var root = document.documentElement;

  function read() {
    try {
      var saved = localStorage.getItem(KEY);
      return saved === 'light' || saved === 'dark' ? saved : 'dark';
    } catch (e) {
      return 'dark';
    }
  }

  function syncToggles(theme) {
    var buttons = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < buttons.length; i++) {
      var next = theme === 'dark' ? 'light' : 'dark';
      buttons[i].setAttribute('aria-label', 'Switch to ' + next + ' theme');
      buttons[i].setAttribute('title', 'Switch to ' + next + ' theme');
      buttons[i].setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
    }
  }

  function apply(theme, persist) {
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;
    if (persist) {
      try { localStorage.setItem(KEY, theme); } catch (e) { /* storage unavailable: theme lasts for this page */ }
    }
    syncToggles(theme);
    try {
      window.dispatchEvent(new CustomEvent('bharatsec:themechange', { detail: { theme: theme } }));
    } catch (e) { /* very old browsers */ }
  }

  apply(read(), false);

  window.bsTheme = {
    get: function () { return root.getAttribute('data-theme') || 'dark'; },
    set: function (theme) { apply(theme === 'light' ? 'light' : 'dark', true); },
    toggle: function () { this.set(this.get() === 'dark' ? 'light' : 'dark'); },
    /* Read a design token, e.g. bsTheme.token('--ds-accent'); useful for canvas/Chart.js colours. */
    token: function (name) { return getComputedStyle(root).getPropertyValue(name).trim(); }
  };

  function setDrawer(open) {
    document.body.classList.toggle('ds-drawer-open', open);
    var toggles = document.querySelectorAll('[data-drawer-toggle]');
    for (var i = 0; i < toggles.length; i++) toggles[i].setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  document.addEventListener('click', function (event) {
    var target = event.target;
    if (!target || !target.closest) return;
    if (target.closest('[data-theme-toggle]')) {
      window.bsTheme.toggle();
      return;
    }
    if (target.closest('[data-drawer-toggle]')) {
      setDrawer(!document.body.classList.contains('ds-drawer-open'));
      return;
    }
    if (target.closest('.ds-scrim') || (target.closest('.ds-sidebar a[href]') && document.body.classList.contains('ds-drawer-open'))) {
      setDrawer(false);
    }
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && document.body && document.body.classList.contains('ds-drawer-open')) setDrawer(false);
  });

  document.addEventListener('DOMContentLoaded', function () {
    syncToggles(window.bsTheme.get());
    var years = document.querySelectorAll('[data-current-year]');
    for (var i = 0; i < years.length; i++) years[i].textContent = String(new Date().getFullYear());
  });
})();
