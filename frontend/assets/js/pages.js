/* BharatSec company and trust pages: navigation glass on scroll, mobile menu, footer year. */
(function () {
  'use strict';
  const navbar = document.getElementById('navbar');
  if (navbar) {
    const sync = () => navbar.classList.toggle('scrolled', window.scrollY > 12);
    window.addEventListener('scroll', sync, { passive: true });
    sync();
    const menuBtn = document.getElementById('lp-menu-btn');
    const links = document.getElementById('lp-nav-links');
    if (menuBtn && links) {
      const setMenu = (open) => {
        navbar.classList.toggle('is-menu-open', open);
        menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        menuBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
      };
      menuBtn.addEventListener('click', () => setMenu(!navbar.classList.contains('is-menu-open')));
      links.addEventListener('click', (event) => { if (event.target.closest('a')) setMenu(false); });
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && navbar.classList.contains('is-menu-open')) { setMenu(false); menuBtn.focus(); }
      });
    }
  }
  document.querySelectorAll('[data-current-year]').forEach((el) => { el.textContent = String(new Date().getFullYear()); });
})();
