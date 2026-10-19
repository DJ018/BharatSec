/* BharatSec ambient network background.
   Draws a slow-moving node graph on #particle-canvas when the page has one
   (landing, login and dashboard). Colours come from design tokens via
   bsTheme.token(...) and refresh on the bharatsec:themechange event, so the
   canvas looks intentional in both the dark and light themes. */
(() => {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;

  const context = canvas.getContext('2d');
  if (!context) return;

  const isLandingPage = document.body.classList.contains('landing-page');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let width = 0;
  let height = 0;
  let nodes = [];
  let animationFrame = 0;
  let palette = readPalette();

  /* Convert a token value (#rgb, #rrggbb or rgb()/rgba()) into an "r,g,b" string. */
  function toRgb(value, fallback) {
    const v = (value || '').trim();
    let match = v.match(/^#([0-9a-f]{3})$/i);
    if (match) return match[1].split('').map(ch => parseInt(ch + ch, 16)).join(',');
    match = v.match(/^#([0-9a-f]{6})/i);
    if (match) return [0, 2, 4].map(i => parseInt(match[1].slice(i, i + 2), 16)).join(',');
    match = v.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/i);
    if (match) return `${match[1]},${match[2]},${match[3]}`;
    return fallback;
  }

  function token(name) {
    if (window.bsTheme && typeof window.bsTheme.token === 'function') return window.bsTheme.token(name);
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function readPalette() {
    const isLight = window.bsTheme && typeof window.bsTheme.get === 'function'
      ? window.bsTheme.get() === 'light'
      : document.documentElement.getAttribute('data-theme') === 'light';
    const nodeColors = [
      toRgb(token('--ds-saffron'), '244,162,97'),
      toRgb(token('--ds-green'), '126,224,161'),
      toRgb(token('--ds-info'), '108,180,255')
    ];
    return {
      nodeColors,
      line: toRgb(token('--ds-green'), '126,224,161'),
      // Light backgrounds need slightly stronger ink to read; dark needs restraint.
      lineAlpha: (isLandingPage ? 0.17 : 0.13) * (isLight ? 0.9 : 1),
      nodeAlpha: isLight ? 0.4 : 0.3,
      pulseAlpha: isLight ? 0.55 : 0.5
    };
  }

  function resize() {
    stop(); // the previous loop is replaced by the one draw() starts below
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);

    const count = Math.max(24, Math.min(78, Math.round((width * height) / 22000)));
    nodes = Array.from({ length: count }, (_, index) => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.24,
      vy: (Math.random() - 0.5) * 0.24,
      radius: index % 9 === 0 ? 2 : 1.2,
      colorIndex: index % 3
    }));

    draw(0, !reduceMotion.matches);
  }

  function draw(timestamp, move = true) {
    context.clearRect(0, 0, width, height);
    const linkDistance = width < 640 ? 118 : 156;

    if (move) {
      nodes.forEach(node => {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < -12) node.x = width + 12;
        if (node.x > width + 12) node.x = -12;
        if (node.y < -12) node.y = height + 12;
        if (node.y > height + 12) node.y = -12;
      });
    }

    for (let first = 0; first < nodes.length; first++) {
      const node = nodes[first];
      const color = palette.nodeColors[node.colorIndex];
      for (let second = first + 1; second < nodes.length; second++) {
        const target = nodes[second];
        const dx = target.x - node.x;
        const dy = target.y - node.y;
        const distance = Math.hypot(dx, dy);
        if (distance >= linkDistance) continue;

        const strength = 1 - distance / linkDistance;
        context.strokeStyle = `rgba(${palette.line},${strength * palette.lineAlpha})`;
        context.lineWidth = 0.7;
        context.beginPath();
        context.moveTo(node.x, node.y);
        context.lineTo(target.x, target.y);
        context.stroke();

        if (move && (first * 7 + second * 13) % 11 === 0) {
          const progress = (timestamp * 0.00012 + first * 0.19) % 1;
          context.fillStyle = `rgba(${color},${strength * palette.pulseAlpha})`;
          context.beginPath();
          context.arc(node.x + dx * progress, node.y + dy * progress, 1.5, 0, Math.PI * 2);
          context.fill();
        }
      }

      context.fillStyle = `rgba(${color},${node.radius > 1.5 ? palette.nodeAlpha + 0.1 : palette.nodeAlpha})`;
      context.beginPath();
      context.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      context.fill();
    }

    if (move && !document.hidden && !reduceMotion.matches) {
      animationFrame = window.requestAnimationFrame(draw);
    }
  }

  function stop() {
    window.cancelAnimationFrame(animationFrame);
    animationFrame = 0;
  }

  function start() {
    stop();
    draw(0, !reduceMotion.matches);
  }

  window.addEventListener('resize', resize, { passive: true });
  document.addEventListener('visibilitychange', () => document.hidden ? stop() : start());
  reduceMotion.addEventListener?.('change', start);
  window.addEventListener('bharatsec:themechange', () => {
    palette = readPalette();
    start(); // repaint immediately (also covers the static reduced-motion frame)
  });
  resize();
})();
