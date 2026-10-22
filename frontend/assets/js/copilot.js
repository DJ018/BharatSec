/* ============================================================
   BharatSec: Security Copilot Chat
   Dashboard AI assistant panel
   ============================================================ */

const BACKEND_URL = (() => {
  if (window.BHARATSEC_API_BASE) return window.BHARATSEC_API_BASE.replace(/\/$/, '');
  const isLocalFrontend = window.location.protocol === 'file:' ||
    (['localhost', '127.0.0.1'].includes(window.location.hostname) && window.location.port !== '8000');
  return isLocalFrontend ? 'http://127.0.0.1:8000' : '';
})();
let copilotOpen = false;
let currentScanId = null;
let conversationHistory = [];
let copilotSending = false;
let copilotGeneration = 0;
let copilotController = null;

function detectLanguage(text) {
  const value = (text || '').trim();
  if (!value) return 'en';
  if (/[\u0900-\u097F]/.test(value)) return 'hi';
  const lower = value.toLowerCase();
  return /\b(namaste|kya|kaise|aap|tum|hai|hoga|nahi|kyun|hindi)\b/.test(lower) ? 'hi' : 'en';
}

// Static icon markup for the voice button (constant strings, never user data).
const COPILOT_ICONS = {
  mic:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 10a7 7 0 0 0 14 0M12 17v4"/></svg>',
  stop: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
};

function setupCopilotVoice() {
  const btn = document.getElementById('copilot-voice-btn');
  if (!btn) return;
  btn.innerHTML = COPILOT_ICONS.mic;

  const isSecureContext = window.isSecureContext || ['localhost', '127.0.0.1'].includes(window.location.hostname);
  const SpeechRecognitionCtor = window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognitionCtor || !isSecureContext) {
    btn.title = 'Voice input needs Chrome/Edge on localhost or HTTPS';
    btn.disabled = true;
    btn.innerHTML = COPILOT_ICONS.mic;
    btn.addEventListener('click', () => {
      appendMessage('ai', 'Voice input is available on Chrome/Edge when the site is running on localhost or HTTPS. Please type your question for now.', 'error');
    }, { once: true });
    return;
  }

  let listening = false;
  const recognition = new SpeechRecognitionCtor();
  recognition.lang = 'hi-IN';
  recognition.continuous = false;
  recognition.interimResults = false;

  recognition.onstart = () => {
    listening = true;
    btn.classList.add('active');
    btn.innerHTML = COPILOT_ICONS.stop;
    btn.title = 'Listening...';
  };

  recognition.onend = () => {
    listening = false;
    btn.classList.remove('active');
    btn.innerHTML = COPILOT_ICONS.mic;
    btn.title = 'Speak to BharatSec AI';
  };

  recognition.onerror = () => {
    appendMessage('ai', 'Voice input is not available right now. Please type your question or try again.', 'error');
  };

  recognition.onresult = (event) => {
    const transcript = Array.from(event.results)
      .map(result => result[0]?.transcript || '')
      .join(' ')
      .trim();

    if (!transcript) return;
    const input = document.getElementById('copilot-input');
    if (input) input.value = transcript;
    sendMessage();
  };

  btn.addEventListener('click', () => {
    if (listening) {
      recognition.stop();
      return;
    }
    const input = document.getElementById('copilot-input');
    const currentText = input ? input.value : '';
    recognition.lang = detectLanguage(currentText) === 'hi' ? 'hi-IN' : 'en-US';
    recognition.start();
  });
}

setupCopilotVoice();

// ── Toggle Copilot Panel ──────────────────────────────────────

function toggleCopilot() {
  copilotOpen = !copilotOpen;
  const panel = document.getElementById('copilot-panel');
  const fab   = document.getElementById('copilot-fab');
  const input = document.getElementById('copilot-input');
  if (!panel || !fab) return;

  if (copilotOpen) {
    panel.classList.add('open');
    fab.classList.add('open');
    fab.setAttribute('aria-expanded', 'true');
    fab.setAttribute('aria-label', 'Close BharatSec AI');
    document.body.classList.add('copilot-open');
    if (input) input.focus();
  } else {
    panel.classList.remove('open');
    fab.classList.remove('open');
    fab.setAttribute('aria-expanded', 'false');
    fab.setAttribute('aria-label', 'Open BharatSec AI');
    document.body.classList.remove('copilot-open');
    fab.focus();   // don't leave keyboard focus inside the hidden panel
  }
}

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && copilotOpen) toggleCopilot();
});

function setCopilotScanId(scanId) {
  if (currentScanId === scanId) return;
  currentScanId = scanId;
  // A new scan starts a new conversation: cancel any answer still streaming for the old one.
  copilotGeneration += 1;
  if (copilotController) copilotController.abort();
  copilotController = null;
  copilotSending = false;
  setComposerDisabled(false);
  conversationHistory = [];
  const container = document.getElementById('copilot-messages');
  if (container) {
    container.replaceChildren();
    appendMessage('ai', 'Scan context is ready. Ask me about findings, your score, attack paths, or what to fix first.');
  }
  const subtitle = document.getElementById('copilot-subtitle');
  if (subtitle) subtitle.textContent = 'Connected to this scan';
}

// ── Send suggestion chip ──────────────────────────────────────

function sendSuggestion(el) {
  const input = document.getElementById('copilot-input');
  if (!input || !el) return;
  input.value = el.textContent;
  sendMessage();
}

// ── Send message ──────────────────────────────────────────────

async function sendMessage() {
  const input   = document.getElementById('copilot-input');
  if (!input || copilotSending) return;
  const message = input.value.trim();
  if (!message) return;
  input.value = '';

  copilotSending = true;
  setComposerDisabled(true);
  appendMessage('user', message);
  const typingId = showTyping();

  let bubble = null;
  let partial = '';            // latest streamed text, kept so an interruption never erases it
  let pending = 0;
  const generation = copilotGeneration;
  const controller = new AbortController();
  copilotController = controller;
  let idle = setTimeout(() => controller.abort(), 60000);
  try {
    // With a scan loaded, answers are grounded in it; otherwise Copilot answers general questions.
    const url = currentScanId ? `${BACKEND_URL}/api/ai/copilot/stream` : `${BACKEND_URL}/api/ai/chat/stream`;
    const body = currentScanId
      ? { scan_id: currentScanId, message, history: conversationHistory }
      : { message, history: conversationHistory };
    const content = await window.BharatSecAI.stream(url, body, {
      signal: controller.signal,
      onMeta(meta) {
        removeTyping(typingId);
        bubble = appendStreamingMessage(meta.source, meta.model);
      },
      onDelta(text) {
        partial = text;
        clearTimeout(idle);
        idle = setTimeout(() => controller.abort(), 60000);
        if (pending) return;
        pending = requestAnimationFrame(() => { pending = 0; renderAnswer(bubble, partial, true); });
      },
      onError(errorMessage) {
        if (bubble) bubble.dataset.error = errorMessage;
      },
    });
    if (pending) { cancelAnimationFrame(pending); pending = 0; }
    if (generation !== copilotGeneration) return;   // a new scan replaced this conversation
    if (!bubble) throw new Error('BharatSec AI returned an empty response. Please try again.');
    renderAnswer(bubble, content, false);
    if (!content.trim()) {
      addRetryButton(message);
    } else {
      conversationHistory.push({ role: 'user', content: message }, { role: 'assistant', content });
      conversationHistory = conversationHistory.slice(-12);
    }
  } catch (error) {
    if (pending) { cancelAnimationFrame(pending); pending = 0; }
    removeTyping(typingId);
    if (generation !== copilotGeneration) return;
    const text = error.name === 'AbortError'
      ? 'The BharatSec AI request timed out. Check your connection and try again.'
      : (error.message || 'BharatSec AI is temporarily unavailable. Please try again.');
    if (bubble) {
      // Keep the server's own error (e.g. quota exceeded) if it sent one.
      if (!bubble.dataset.error) bubble.dataset.error = text;
      renderAnswer(bubble, partial, false);
    } else {
      appendMessage('ai', text, 'error');
    }
    addRetryButton(message);
  } finally {
    clearTimeout(idle);
    if (copilotController === controller) copilotController = null;
    if (generation === copilotGeneration) {
      copilotSending = false;
      setComposerDisabled(false);
      input.focus();
    }
  }

  if (generation === copilotGeneration) updateSuggestions(message);
}

// ── Append message ────────────────────────────────────────────

function appendMessage(role, text, source = '') {
  const container = document.getElementById('copilot-messages');
  if (!container) return;
  const msg = document.createElement('div');
  msg.className = `msg ${role}`;

  const avatar = document.createElement('div');
  avatar.className = 'msg-avatar';
  avatar.textContent = role === 'ai' ? 'AI' : 'You';

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  bubble.textContent = text;

  if (role === 'ai' && source) {
    const badge = document.createElement('span');
    badge.className = `copilot-source${source === 'error' ? ' error' : ''}`;
    badge.textContent = source === 'gemini' ? 'Gemini' : source === 'rules' ? 'BharatSec AI rules' : source === 'error' ? 'Not sent' : 'BharatSec AI';
    bubble.appendChild(badge);
  }

  msg.appendChild(avatar);
  msg.appendChild(bubble);
  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;

}

function appendStreamingMessage(source, model) {
  const container = document.getElementById('copilot-messages');
  const msg = document.createElement('div');
  msg.className = 'msg ai';
  const avatar = document.createElement('div');
  avatar.className = 'msg-avatar';
  avatar.textContent = 'AI';
  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  bubble.dataset.source = source || '';
  bubble.dataset.model = model || '';
  msg.append(avatar, bubble);
  container.appendChild(msg);
  return bubble;
}

// Model output is rendered as Markdown through BharatSecAI.renderMarkdown, which only creates DOM nodes.
function renderAnswer(bubble, text, streaming) {
  if (!bubble) return;
  const container = document.getElementById('copilot-messages');
  const nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
  const body = document.createElement('div');
  body.className = `ds-md${streaming ? ' ds-md-cursor' : ''}`;
  body.appendChild(window.BharatSecAI.renderMarkdown(text));
  const nodes = [body];
  if (!streaming) {
    if (bubble.dataset.error) {
      const warn = document.createElement('div');
      warn.className = 'ds-ai-source is-offline';
      warn.textContent = bubble.dataset.error;
      nodes.push(warn);
    }
    const label = document.createElement('div');
    label.className = `ds-ai-source${bubble.dataset.source === 'rules' ? ' is-offline' : ''}`;
    label.textContent = window.BharatSecAI.sourceLabel(bubble.dataset.source, bubble.dataset.model);
    nodes.push(label);
  }
  bubble.replaceChildren(...nodes);
  if (nearBottom || !streaming) container.scrollTop = container.scrollHeight;
}

function addRetryButton(message) {
  const container = document.getElementById('copilot-messages');
  if (!container) return;
  const button = document.createElement('button');
  button.className = 'copilot-retry';
  button.type = 'button';
  button.textContent = 'Retry';
  button.addEventListener('click', () => {
    const input = document.getElementById('copilot-input');
    if (!input) return;
    input.value = message;
    sendMessage();
  }, { once: true });
  const lastBubble = container.lastElementChild?.querySelector('.msg-bubble');
  if (lastBubble) lastBubble.appendChild(button);
}

function setComposerDisabled(disabled) {
  const input = document.getElementById('copilot-input');
  const button = document.querySelector('.copilot-send');
  if (input) input.disabled = disabled;
  if (button) button.disabled = disabled;
}

// ── Typing indicator ──────────────────────────────────────────

function showTyping() {
  const container = document.getElementById('copilot-messages');
  if (!container) return '';
  const id = 'typing-' + Date.now();
  const msg = document.createElement('div');
  msg.className = 'msg ai';
  msg.id = id;
  msg.innerHTML = `
    <div class="msg-avatar">AI</div>
    <div class="msg-bubble">
      <div class="typing-indicator">
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
      </div>
    </div>`;
  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeTyping(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// ── Dynamic suggestions ───────────────────────────────────────

const SUGGESTION_POOL = [
  "Why is my score low?", "What should I fix first?",
  "Explain email security", "What is HSTS?",
  "Explain CSP simply", "How do attack paths work?",
  "What is credential exposure?", "Explain SSL certificates",
  "What are security headers?", "How do subdomains add risk?",
  "What is DMARC?", "Explain clickjacking",
];
const usedSuggestions = new Set();

function updateSuggestions(lastMsg) {
  if (!lastMsg) return;
  usedSuggestions.add(lastMsg.toLowerCase());
  const container = document.getElementById('copilot-suggestions');
  if (!container) return;
  const picks = SUGGESTION_POOL.filter(s => !usedSuggestions.has(s.toLowerCase())).slice(0, 3);
  container.innerHTML = picks.map(s =>
    `<button type="button" class="suggestion-chip" onclick="sendSuggestion(this)">${s}</button>`
  ).join('');
}

