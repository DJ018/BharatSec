/* BharatSec ambient shader.
   Paints a slow, domain-warped aurora in the brand colours (saffron to green) on every
   <canvas data-fx-shader>. Colours come from the design tokens, so it follows the light and
   dark themes. It renders at reduced resolution and 30 fps, pauses when off screen or in a
   background tab, draws a single still frame for people who prefer reduced motion, and
   removes itself when WebGL is unavailable (the CSS aurora underneath then shows instead).
   Optional attributes: data-intensity="0..1" (default 1). */
(() => {
  'use strict';

  const VERTEX = `
    attribute vec2 a_pos;
    void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }
  `;

  const FRAGMENT = `
    precision mediump float;
    uniform vec2 u_res;
    uniform float u_time;
    uniform vec2 u_mouse;
    uniform vec3 u_bg;
    uniform vec3 u_warm;
    uniform vec3 u_cool;
    uniform vec3 u_mid;
    uniform float u_intensity;
    uniform float u_light;

    float hash(vec2 p) {
      p = fract(p * vec2(123.34, 456.21));
      p += dot(p, p + 45.32);
      return fract(p.x * p.y);
    }
    float noise(vec2 p) {
      vec2 i = floor(p);
      vec2 f = fract(p);
      vec2 u = f * f * (3.0 - 2.0 * f);
      return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x),
                 mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
    }
    float fbm(vec2 p) {
      float value = 0.0;
      float amplitude = 0.5;
      mat2 rotate = mat2(1.6, 1.2, -1.2, 1.6);
      for (int i = 0; i < 5; i++) {
        value += amplitude * noise(p);
        p = rotate * p;
        amplitude *= 0.5;
      }
      return value;
    }

    void main() {
      vec2 uv = gl_FragCoord.xy / u_res;
      vec2 p = (gl_FragCoord.xy - 0.5 * u_res) / u_res.y;
      float t = u_time * 0.035;

      // Two layers of domain warping give the slow, silky aurora folds.
      vec2 q = vec2(fbm(p * 1.3 + t), fbm(p * 1.3 - t + 3.1));
      vec2 r = vec2(fbm(p * 1.7 + 2.0 * q + vec2(1.7, 9.2) + t * 1.4),
                    fbm(p * 1.7 + 2.0 * q + vec2(8.3, 2.8) - t));
      float field = fbm(p * 1.1 + 2.4 * r);

      vec3 colour = mix(u_warm, u_cool, smoothstep(0.3, 0.75, field * 0.55 + uv.x * 0.75 - 0.1));
      colour = mix(colour, u_mid, clamp(length(q) * 0.45, 0.0, 1.0) * 0.45);

      // Soft light that drifts toward the pointer.
      vec2 pointer = (u_mouse - 0.5) * vec2(u_res.x / u_res.y, 1.0);
      float halo = exp(-2.6 * length(p - pointer));

      // Thin luminous ribbons riding the warp field.
      float ribbon = pow(abs(sin((p.x * 1.2 + p.y * 0.7 + r.x * 1.6 + t * 3.0) * 3.2)), 18.0);

      float amount = smoothstep(0.3, 0.95, field) * 0.85 + halo * 0.22 + ribbon * 0.18;
      amount *= u_intensity;

      // Dark theme: the aurora is emitted light added to the background (luminous, never muddy).
      // Light theme: a gentle tint mixed into the paper colour.
      vec3 glow = u_bg + colour * amount * 0.9;
      vec3 tint = mix(u_bg, colour, clamp(amount, 0.0, 1.0));
      vec3 result = mix(glow, tint, u_light);
      float vignette = smoothstep(1.35, 0.15, length(uv - vec2(0.5, 0.62)));
      result = mix(u_bg, result, vignette);
      result += (hash(gl_FragCoord.xy + fract(u_time)) - 0.5) * 0.012; // film grain against banding

      gl_FragColor = vec4(result, 1.0);
    }
  `;

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  function token(name) {
    if (window.bsTheme && typeof window.bsTheme.token === 'function') return window.bsTheme.token(name);
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  /* "#rgb", "#rrggbb" or "rgb(a)()" → [r, g, b] in 0..1. */
  function toVec3(value, fallback) {
    const v = (value || '').trim();
    let m = v.match(/^#([0-9a-f]{3})$/i);
    if (m) return m[1].split('').map((ch) => parseInt(ch + ch, 16) / 255);
    m = v.match(/^#([0-9a-f]{6})/i);
    if (m) return [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16) / 255);
    m = v.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/i);
    if (m) return [m[1], m[2], m[3]].map((n) => Number(n) / 255);
    return fallback;
  }

  function isLight() {
    return document.documentElement.getAttribute('data-theme') === 'light';
  }

  function compile(gl, type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      const log = gl.getShaderInfoLog(shader);
      gl.deleteShader(shader);
      throw new Error(log || 'shader compile failed');
    }
    return shader;
  }

  function mount(canvas) {
    if (canvas.dataset.fxShaderMounted) return;
    canvas.dataset.fxShaderMounted = '1';

    const gl = canvas.getContext('webgl', {
      alpha: false, antialias: false, depth: false, stencil: false,
      premultipliedAlpha: false, preserveDrawingBuffer: false, powerPreference: 'low-power',
    });
    if (!gl) { canvas.remove(); return; }

    let program;
    try {
      program = gl.createProgram();
      gl.attachShader(program, compile(gl, gl.VERTEX_SHADER, VERTEX));
      gl.attachShader(program, compile(gl, gl.FRAGMENT_SHADER, FRAGMENT));
      gl.linkProgram(program);
      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program));
    } catch (error) {
      console.warn('[BharatSec] Shader background disabled:', error.message);
      canvas.remove();
      return;
    }
    gl.useProgram(program);

    // One oversized triangle covers the whole viewport.
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const position = gl.getAttribLocation(program, 'a_pos');
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);

    const uniform = (name) => gl.getUniformLocation(program, name);
    const u = {
      res: uniform('u_res'), time: uniform('u_time'), mouse: uniform('u_mouse'),
      bg: uniform('u_bg'), warm: uniform('u_warm'), cool: uniform('u_cool'), mid: uniform('u_mid'),
      intensity: uniform('u_intensity'), light: uniform('u_light'),
    };

    const baseIntensity = Math.max(0, Math.min(1, Number(canvas.dataset.intensity || 1)));
    function applyColours() {
      const light = isLight();
      gl.uniform3fv(u.bg, toVec3(token('--ds-bg'), light ? [0.96, 0.97, 0.96] : [0.02, 0.05, 0.035]));
      gl.uniform3fv(u.warm, toVec3(token('--ds-saffron'), [0.96, 0.64, 0.38]));
      gl.uniform3fv(u.cool, toVec3(token('--ds-green'), [0.49, 0.88, 0.63]));
      gl.uniform3fv(u.mid, toVec3(token('--ds-medium'), [0.95, 0.79, 0.3]));
      // Light backgrounds need a gentler wash to keep text contrast.
      gl.uniform1f(u.intensity, baseIntensity * (light ? 0.42 : 0.68));
      gl.uniform1f(u.light, light ? 1 : 0);
    }

    let width = 0;
    let height = 0;
    function resize() {
      const rect = canvas.getBoundingClientRect();
      const scale = Math.min(window.devicePixelRatio || 1, 1.5) * 0.55; // soft field: low resolution is invisible
      const w = Math.max(1, Math.round(rect.width * scale));
      const h = Math.max(1, Math.round(rect.height * scale));
      if (w === width && h === height) return;
      width = w; height = h;
      canvas.width = w; canvas.height = h;
      gl.viewport(0, 0, w, h);
      gl.uniform2f(u.res, w, h);
    }

    const pointer = { x: 0.35, y: 0.6, tx: 0.35, ty: 0.6 };
    window.addEventListener('pointermove', (event) => {
      const rect = canvas.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      pointer.tx = Math.min(1.2, Math.max(-0.2, (event.clientX - rect.left) / rect.width));
      pointer.ty = Math.min(1.2, Math.max(-0.2, 1 - (event.clientY - rect.top) / rect.height));
    }, { passive: true });

    const start = performance.now() - 20000 * Math.random();
    function draw(now) {
      resize();
      pointer.x += (pointer.tx - pointer.x) * 0.04;
      pointer.y += (pointer.ty - pointer.y) * 0.04;
      gl.uniform1f(u.time, (now - start) / 1000);
      gl.uniform2f(u.mouse, pointer.x, pointer.y);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      if (!canvas.classList.contains('is-ready')) canvas.classList.add('is-ready');
    }

    let visible = true;
    let frame = 0;
    let last = 0;
    function loop(now) {
      frame = 0;
      if (!visible || document.hidden || reducedMotion.matches) return;
      if (now - last >= 33) { // ~30 fps is plenty for a slow field
        last = now;
        draw(now);
      }
      frame = requestAnimationFrame(loop);
    }
    function wake() {
      if (reducedMotion.matches) { draw(performance.now()); return; }
      if (!frame) frame = requestAnimationFrame(loop);
    }

    applyColours();
    draw(performance.now());
    new IntersectionObserver((entries) => {
      visible = entries.some((entry) => entry.isIntersecting);
      if (visible) wake();
    }).observe(canvas);
    document.addEventListener('visibilitychange', wake);
    reducedMotion.addEventListener?.('change', wake);
    window.addEventListener('resize', () => { resize(); if (reducedMotion.matches) draw(performance.now()); }, { passive: true });
    window.addEventListener('bharatsec:themechange', () => { applyColours(); draw(performance.now()); });
    canvas.addEventListener('webglcontextlost', (event) => { event.preventDefault(); visible = false; });
    wake();
  }

  function mountAll() {
    document.querySelectorAll('canvas[data-fx-shader]').forEach(mount);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountAll);
  else mountAll();

  window.bsShader = { mount };
})();
