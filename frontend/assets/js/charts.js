/* ============================================================
   BharatSec: Chart.js Configurations
   Colours come from design tokens (bsTheme.token) so the gauge
   follows the active theme; it re-renders on bharatsec:themechange.
   ============================================================ */

let gaugeChart = null;
let gaugeScore = null;

function chartToken(name, fallback) {
  const value = window.bsTheme && typeof window.bsTheme.token === 'function' ? window.bsTheme.token(name) : '';
  return value || fallback;
}

// Score (higher = safer) → token for the gauge arc.
function gaugeColor(score) {
  if (score < 35) return chartToken('--ds-critical', '#ff5d6c');
  if (score < 55) return chartToken('--ds-high', '#ff9a4d');
  if (score < 70) return chartToken('--ds-medium', '#f2c94c');
  if (score < 85) return chartToken('--ds-low', '#4ade80');
  return chartToken('--ds-primary', '#7ee0a1');
}

function createGaugeChart(score, options) {
  const canvas = document.getElementById('score-gauge');
  if (!canvas) return;
  if (typeof Chart === 'undefined') {
    console.warn('[charts.js] Chart.js library not loaded');
    return;
  }
  const animate = !(options && options.animate === false);
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  gaugeScore = value;

  if (gaugeChart) {
    gaugeChart.destroy();
  }

  gaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [value, 100 - value],
        backgroundColor: [gaugeColor(value), chartToken('--ds-surface-3', 'rgba(127,127,127,.2)')],
        borderColor: ['transparent', 'transparent'],
        borderWidth: 0,
        borderRadius: [8, 0],
        circumference: 270,
        rotation: -135,
      }]
    },
    options: {
      responsive: false,
      cutout: '82%',
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
      },
      animation: animate ? {
        animateRotate: true,
        duration: 1200,
        easing: 'easeOutCubic',
      } : false
    }
  });

  // Animate score number on first render only
  if (animate) animateScoreNum(score);
}

function animateScoreNum(target) {
  const el = document.getElementById('gauge-score-num');
  if (!el) return;

  const duration = 1200;
  const startTime = performance.now();

  const step = (now) => {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.floor(eased * target);
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = target;
  };

  requestAnimationFrame(step);
}

function updateGaugeColors(score) {
  const levelEl = document.getElementById('gauge-level');
  if (!levelEl) return;

  let level, tone;
  if (score < 35)      { level = 'CRITICAL'; tone = 'critical'; }
  else if (score < 55) { level = 'HIGH';     tone = 'high';     }
  else if (score < 70) { level = 'MEDIUM';   tone = 'medium';   }
  else if (score < 85) { level = 'LOW';      tone = 'low';      }
  else                 { level = 'SECURE';   tone = 'primary';  }

  levelEl.textContent = level === 'SECURE' ? 'Secure' : `${level.charAt(0)}${level.slice(1).toLowerCase()} risk`;
  levelEl.className = `gauge-level ${level} ds-badge ds-badge--dot ds-badge--${tone}`;
}

// Re-colour the gauge when the theme changes (no re-animation).
window.addEventListener('bharatsec:themechange', () => {
  if (gaugeChart && gaugeScore !== null) {
    // Wait a frame so the new token values are applied before reading them.
    requestAnimationFrame(() => createGaugeChart(gaugeScore, { animate: false }));
  }
});

// ── Category bar animation ─────────────────────────────────────

function animateCategoryBars(score) {
  const bars = [
    { fill: 'bar-attack', val: 'val-attack', score: score.attack_surface },
    { fill: 'bar-web',    val: 'val-web',    score: score.web_security },
    { fill: 'bar-identity',val:'val-identity', score: score.identity_exposure },
    { fill: 'bar-config', val: 'val-config', score: score.configuration },
    { fill: 'bar-cred',   val: 'val-cred',   score: score.credential_risk },
  ];

  bars.forEach(({ fill, val, score: s }) => {
    const bar   = document.getElementById(fill);
    const label = document.getElementById(val);
    if (!bar || !label) return;

    label.textContent = s;

    // Color class (higher score = safer)
    let cls;
    if (s >= 75)      cls = 'high-score';
    else if (s >= 55) cls = 'medium-score';
    else if (s >= 35) cls = 'low-score';
    else              cls = 'critical-score';

    bar.className = `cat-bar-fill ${cls}`;

    // Animate width after brief delay
    setTimeout(() => {
      bar.style.width = s + '%';
    }, 200);
  });
}
