/* BharatSec motion and micro-interactions, shared by every page.
   Uses Motion (Framer Motion's framework-free library, loaded before this file) when available:
   - entrance: page headers, stat tiles, cards and the hero rise in with a soft blur, staggered;
   - spotlight: cards, tiles and features light up under the pointer;
   - magnetic: primary buttons lean a few pixels toward the pointer;
   - count-up: numbers in stat tiles and scores count to their value when they first appear.
   Content is never left hidden: theme.js only hides entrance targets (html.fx-js) when motion is
   allowed, and removes that class itself if this file or Motion fails to load. */
(() => {
  'use strict';

  const root = document.documentElement;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  const Motion = window.Motion;
  const EASE = [0.22, 1, 0.36, 1];

  /* Static layout blocks only: page scripts fill these in but never replace them. */
  const ENTRANCE_GROUPS = [
    '.lp-hero-copy > *',
    '.lp-hero-visual',
    '.ds-page-header',
    '.ds-stats',
    '.ds-content > .ds-card',
    '.ds-content > .ds-section',
    '.ds-content > section',
    '.auth-card',
    '.lg-brand-body > *',
    '.lg-suite',
  ];
  const SPOTLIGHT = '.ds-card, .ds-stat, .lp-feature, .lp-product, .lp-step, .lp-stat, .auth-card, .ac-connection';
  const MAGNETIC = '.ds-btn--brand, .ds-btn--primary.ds-btn--lg, .lp-scan-btn';
  const COUNTERS = '.ds-stat-value, .gauge-score, .exec-score-num, .feed-count, .lp-stat-value, .sev-chip .count';

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn, { once: true });
    else fn();
  }

  /* ── Entrance ─────────────────────────────────────────────── */
  function entrance() {
    const done = new WeakSet();
    ENTRANCE_GROUPS.forEach((selector) => {
      const items = [...document.querySelectorAll(selector)].filter((el) => !done.has(el));
      items.forEach((el, index) => {
        done.add(el);
        Motion.inView(el, () => {
          Motion.animate(
            el,
            { opacity: [0, 1], transform: ['translateY(16px)', 'translateY(0px)'], filter: ['blur(6px)', 'blur(0px)'] },
            { duration: 0.7, delay: Math.min(index, 6) * 0.07, ease: EASE },
          ).then(() => {
            el.style.removeProperty('transform');
            el.style.removeProperty('filter');
            el.classList.add('fx-in');
          });
        }, { margin: '0px 0px -6% 0px' });
      });
    });
    root.classList.add('fx-live');
  }

  /* ── Spotlight ────────────────────────────────────────────── */
  function spotlight() {
    let active = null;
    document.addEventListener('pointermove', (event) => {
      const el = event.target instanceof Element ? event.target.closest(SPOTLIGHT) : null;
      if (active && active !== el) active.classList.remove('fx-lit');
      active = el;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      el.style.setProperty('--fx-x', `${event.clientX - rect.left}px`);
      el.style.setProperty('--fx-y', `${event.clientY - rect.top}px`);
      el.classList.add('fx-spot', 'fx-lit');
    }, { passive: true });
    document.addEventListener('pointerleave', () => active?.classList.remove('fx-lit'));
  }

  /* ── Magnetic buttons ─────────────────────────────────────── */
  function magnetic() {
    document.addEventListener('pointermove', (event) => {
      const button = event.target instanceof Element ? event.target.closest(MAGNETIC) : null;
      document.querySelectorAll('.fx-magnet').forEach((el) => {
        if (el !== button) { el.classList.remove('fx-magnet'); el.style.removeProperty('--fx-mx'); el.style.removeProperty('--fx-my'); }
      });
      if (!button || button.disabled) return;
      const rect = button.getBoundingClientRect();
      const dx = (event.clientX - (rect.left + rect.width / 2)) / rect.width;
      const dy = (event.clientY - (rect.top + rect.height / 2)) / rect.height;
      button.classList.add('fx-magnet');
      button.style.setProperty('--fx-mx', `${(dx * 6).toFixed(2)}px`);
      button.style.setProperty('--fx-my', `${(dy * 4).toFixed(2)}px`);
    }, { passive: true });
  }

  /* ── Count-up numbers ─────────────────────────────────────── */
  const NUMBER = /^(\D*?)(-?\d[\d,]*(?:\.\d+)?)(.*)$/s;
  const written = new WeakMap();   // the last text this script wrote into each element
  const runs = new WeakMap();      // the running count-up per element, so a newer value replaces it

  function countUp(el) {
    const text = el.textContent.trim();
    if (written.get(el) === text) return; // our own write echoing back through the observer
    runs.get(el)?.stop();
    const match = text.match(NUMBER);
    if (!match || text.length > 24) return;
    const [, prefix, raw, suffix] = match;
    const target = Number(raw.replace(/,/g, ''));
    if (!Number.isFinite(target) || target === 0) return;
    const decimals = (raw.split('.')[1] || '').length;
    const grouped = raw.includes(',');
    const format = (value) => {
      const body = grouped
        ? value.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })
        : value.toFixed(decimals);
      return `${prefix}${body}${suffix}`;
    };
    const write = (value) => { written.set(el, value); el.textContent = value; };
    const run = Motion.animate(0, target, {
      duration: Math.min(1.2, 0.6 + Math.log10(Math.abs(target) + 1) * 0.15),
      ease: EASE,
      onUpdate: (value) => write(format(value)),
    });
    runs.set(el, run);
    run.then(() => { if (runs.get(el) === run) write(text); });
  }

  function counters() {
    const seen = new WeakSet();
    const watch = (el) => {
      if (seen.has(el)) return;
      seen.add(el);
      countUp(el);
      new MutationObserver(() => countUp(el)).observe(el, { childList: true, characterData: true, subtree: true });
    };
    document.querySelectorAll(COUNTERS).forEach(watch);
    // Tiles rendered later by page scripts.
    new MutationObserver((records) => {
      records.forEach((record) => record.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node.matches(COUNTERS)) watch(node);
        node.querySelectorAll?.(COUNTERS).forEach(watch);
      }));
    }).observe(document.body, { childList: true, subtree: true });
  }

  ready(() => {
    if (finePointer) spotlight();
    if (reduced || !Motion) { root.classList.remove('fx-js'); return; }
    try {
      entrance();
      if (finePointer) magnetic();
      counters();
    } catch (error) {
      console.warn('[BharatSec] Motion effects disabled:', error);
      root.classList.remove('fx-js');
    }
  });
})();
