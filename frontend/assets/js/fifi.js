/* ============================================================
   BharatSec: FIFI AI Bot (Landing Page)
   FIFI = Friendly Intelligent Friend Interface
   ============================================================ */

let fifiOpen = false;
const usedChips = new Set();

// Presentation-only constants (static markup, no dynamic data).
const FIFI_MARK_SRC = 'assets/images/brand/bharatsec-mark.svg';
const FIFI_MIC_ICON = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/></svg>';
const FIFI_STOP_ICON = '<svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>';

function detectLanguage(text) {
  const value = (text || '').trim();
  if (!value) return 'en';
  if (/[\u0900-\u097F]/.test(value)) return 'hi';
  const lower = value.toLowerCase();
  return /\b(namaste|kya|kaise|aap|tum|hai|hoga|nahi|kyun|hindi)\b/.test(lower) ? 'hi' : 'en';
}

function setupFifiVoice() {
  const btn = document.getElementById('fifi-voice-btn');
  if (!btn) return;

  const isSecureContext = window.isSecureContext || ['localhost', '127.0.0.1'].includes(window.location.hostname);
  const SpeechRecognitionCtor = window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognitionCtor || !isSecureContext) {
    btn.title = 'Voice input needs Chrome/Edge on localhost or HTTPS';
    btn.disabled = true;
    btn.innerHTML = FIFI_MIC_ICON;
    btn.addEventListener('click', () => {
      appendFifiMsg('ai', 'Voice input is available on Chrome/Edge when the site is running on localhost or HTTPS. Please type your question for now.');
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
    btn.innerHTML = FIFI_STOP_ICON;
    btn.title = 'Listening...';
    btn.setAttribute('aria-label', 'Stop voice input');
  };

  recognition.onend = () => {
    listening = false;
    btn.classList.remove('active');
    btn.innerHTML = FIFI_MIC_ICON;
    btn.title = 'Speak to BharatSec AI';
    btn.setAttribute('aria-label', 'Voice input');
  };

  recognition.onerror = () => {
    appendFifiMsg('ai', 'Voice input is not available right now. Please type your question or try again.');
  };

  recognition.onresult = (event) => {
    const transcript = Array.from(event.results)
      .map(result => result[0]?.transcript || '')
      .join(' ')
      .trim();

    if (!transcript) return;
    const input = document.getElementById('fifi-input');
    if (input) input.value = transcript;
    fifSendMsg();
  };

  btn.addEventListener('click', () => {
    if (listening) {
      recognition.stop();
      return;
    }
    const input = document.getElementById('fifi-input');
    const currentText = input ? input.value : '';
    recognition.lang = detectLanguage(currentText) === 'hi' ? 'hi-IN' : 'en-US';
    recognition.start();
  });
}

setupFifiVoice();

// ── Toggle panel ──────────────────────────────────────────────

function toggleFIFI() {
  fifiOpen = !fifiOpen;
  const panel = document.getElementById('fifi-panel');
  const fab   = document.getElementById('fifi-fab');
  if (!panel || !fab) return;

  fab.setAttribute('aria-expanded', fifiOpen ? 'true' : 'false');
  if (fifiOpen) {
    panel.classList.add('open');
    fab.classList.add('open');
    const input = document.getElementById('fifi-input');
    if (input) input.focus();
    const pulse = fab.querySelector('.fifi-pulse');
    if (pulse) pulse.style.display = 'none';
  } else {
    panel.classList.remove('open');
    fab.classList.remove('open');
    fab.focus();
  }
}

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && fifiOpen) toggleFIFI();
});

// ── Send from chip ────────────────────────────────────────────

function fifSend(el) {
  if (!el) return;
  const text = el.textContent.trim();
  const input = document.getElementById('fifi-input');
  if (!input) return;
  input.value = text;
  fifSendMsg();
}

// ── Send message ──────────────────────────────────────────────

// Conversation memory sent with each question (last 12 turns), so follow-ups have context.
let fifiHistory = [];
let fifiBusy = false;
let fifiGeneration = 0;        // bumped by "New chat" so a late answer cannot leak into the new conversation
let fifiController = null;     // aborts the in-flight request
const FIFI_IDLE_TIMEOUT_MS = 60000;

async function fifSendMsg() {
  const input   = document.getElementById('fifi-input');
  if (!input || fifiBusy) return;
  const message = input.value.trim();
  if (!message) return;
  input.value = '';
  fifiBusy = true;
  const generation = fifiGeneration;
  const controller = new AbortController();
  fifiController = controller;

  appendFifiMsg('user', message);
  const typingId = showFifiTyping();
  let bubble = null;
  let partial = '';           // latest streamed text, kept so an interruption never erases it
  let pending = 0;
  let idle = setTimeout(() => controller.abort(), FIFI_IDLE_TIMEOUT_MS);

  try {
    const backendBase = typeof getBharatSecBackendBase === 'function' ? getBharatSecBackendBase() : '';
    const answer = await window.BharatSecAI.stream(`${backendBase}/api/ai/chat/stream`, { message, history: fifiHistory }, {
      signal: controller.signal,
      onMeta(meta) {
        removeFifiTyping(typingId);
        bubble = appendFifiStreamingBubble();
        bubble.dataset.source = meta.source || '';
        bubble.dataset.model = meta.model || '';
      },
      onDelta(text) {
        partial = text;
        clearTimeout(idle);
        idle = setTimeout(() => controller.abort(), FIFI_IDLE_TIMEOUT_MS);
        // Re-render at most once per frame while tokens stream in.
        if (pending) return;
        pending = requestAnimationFrame(() => { pending = 0; renderFifiAnswer(bubble, partial, true); });
      },
      onError(errorMessage) {
        if (bubble) bubble.dataset.error = errorMessage;
      },
    });
    if (pending) { cancelAnimationFrame(pending); pending = 0; }
    if (generation !== fifiGeneration) return;
    if (!bubble) throw new Error('BharatSec AI returned an empty response.');
    renderFifiAnswer(bubble, answer, false);
    fifiHistory.push({ role: 'user', content: message }, { role: 'assistant', content: answer });
    fifiHistory = fifiHistory.slice(-12);
  } catch (error) {
    if (pending) { cancelAnimationFrame(pending); pending = 0; }
    removeFifiTyping(typingId);
    if (generation !== fifiGeneration) return;   // the user started a new chat; drop this answer
    if (bubble) {
      if (!bubble.dataset.error) {
        bubble.dataset.error = error.name === 'AbortError'
          ? 'The answer stopped responding. Please try again.'
          : 'The answer was interrupted. Please try again.';
      }
      renderFifiAnswer(bubble, partial, false);
    } else if (error.name === 'AbortError') {
      appendFifiMsg('ai', 'BharatSec AI took too long to respond. Please try again.');
    } else if (error.status === 401) {
      // The AI API needs an account; invite sign-in rather than guess from the small offline table.
      const signIn = `${window.location.origin}/login.html?return=${encodeURIComponent('/#top')}`;
      const reply = appendFifiStreamingBubble();
      reply.dataset.source = 'signin';
      renderFifiAnswer(reply, `**Sign in to chat with BharatSec AI.**\n\nOnce you're signed in I can answer questions on cybersecurity, Indian cyber law, AI, business, coding and general knowledge, and remember the conversation.\n\n[Sign in or create an account](${signIn})`, false);
    } else if (error.status === 429) {
      appendFifiMsg('ai', 'You are sending messages quickly. Please wait a few seconds and try again.');
    } else {
      appendFifiMsg('ai', getFIFIResponse(message));
    }
  } finally {
    clearTimeout(idle);
    if (generation === fifiGeneration) fifiBusy = false;
    if (fifiController === controller) fifiController = null;
  }
  if (generation === fifiGeneration) updateFifiChips(message);
}

function appendFifiStreamingBubble() {
  const container = document.getElementById('fifi-messages');
  const wrap = document.createElement('div');
  wrap.className = 'fifi-msg ai';
  const avatar = document.createElement('div');
  avatar.className = 'fifi-msg-avatar';
  const mark = document.createElement('img');
  mark.src = FIFI_MARK_SRC;
  mark.alt = '';
  avatar.appendChild(mark);
  const bubble = document.createElement('div');
  bubble.className = 'fifi-bubble';
  wrap.append(avatar, bubble);
  container.appendChild(wrap);
  return bubble;
}

function renderFifiAnswer(bubble, text, streaming) {
  if (!bubble) return;
  const container = document.getElementById('fifi-messages');
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
    const source = document.createElement('div');
    source.className = `ds-ai-source${bubble.dataset.source === 'rules' ? ' is-offline' : ''}`;
    source.textContent = window.BharatSecAI.sourceLabel(bubble.dataset.source, bubble.dataset.model);
    nodes.push(source);
  }
  bubble.replaceChildren(...nodes);
  if (nearBottom || !streaming) container.scrollTop = container.scrollHeight;
}

function fifiNewChat() {
  fifiGeneration += 1;
  if (fifiController) fifiController.abort();
  fifiController = null;
  fifiBusy = false;
  fifiHistory = [];
  const container = document.getElementById('fifi-messages');
  if (!container) return;
  const first = container.firstElementChild;
  container.replaceChildren(...(first ? [first] : []));
  document.getElementById('fifi-input')?.focus();
}

// Show whether answers come from a language model or offline knowledge.
if (window.BharatSecAI) {
  window.BharatSecAI.status().then((status) => {
    const tagline = document.getElementById('fifi-tagline');
    if (!tagline || status.mode === 'unknown') return;
    tagline.textContent = status.mode === 'online'
      ? 'Online · answers anything'
      : 'Offline knowledge mode';
  });
}

// ── Append message ────────────────────────────────────────────

function appendFifiMsg(role, text) {
  const container = document.getElementById('fifi-messages');
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = `fifi-msg ${role}`;

  const avatar = document.createElement('div');
  avatar.className = 'fifi-msg-avatar';
  if (role === 'ai') {
    const mark = document.createElement('img');
    mark.src = FIFI_MARK_SRC;
    mark.alt = '';
    avatar.appendChild(mark);
  } else {
    avatar.textContent = 'You';
  }

  const bubble = document.createElement('div');
  bubble.className = 'fifi-bubble';
  setFifiBubbleContent(bubble, text);

  wrap.appendChild(avatar);
  wrap.appendChild(bubble);
  container.appendChild(wrap);
  container.scrollTop = container.scrollHeight;

}

function setFifiBubbleContent(bubble, text) {
  const template = document.createElement('template');
  template.innerHTML = String(text).replace(/\n/g, '<br/>');
  const allowedTags = new Set(['br', 'strong', 'em', 'code', 'ul', 'ol', 'li']);

  function appendSafeNode(parent, node) {
    if (node.nodeType === Node.TEXT_NODE) {
      parent.appendChild(document.createTextNode(node.textContent || ''));
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return;

    const tagName = node.tagName.toLowerCase();
    if (!allowedTags.has(tagName)) {
      node.childNodes.forEach(child => appendSafeNode(parent, child));
      return;
    }

    const safeNode = document.createElement(tagName);
    node.childNodes.forEach(child => appendSafeNode(safeNode, child));
    parent.appendChild(safeNode);
  }

  const safeContent = document.createDocumentFragment();
  template.content.childNodes.forEach(node => appendSafeNode(safeContent, node));
  bubble.replaceChildren(safeContent);
}

// ── Typing indicator ──────────────────────────────────────────

function showFifiTyping() {
  const id = 'fifi-typing-' + Date.now();
  const container = document.getElementById('fifi-messages');
  if (!container) return id;
  const wrap = document.createElement('div');
  wrap.id = id;
  wrap.className = 'fifi-msg ai';
  wrap.innerHTML = `
    <div class="fifi-msg-avatar"><img src="${FIFI_MARK_SRC}" alt="" /></div>
    <div class="fifi-bubble">
      <div class="fifi-typing">
        <div class="fifi-dot"></div>
        <div class="fifi-dot"></div>
        <div class="fifi-dot"></div>
      </div>
    </div>`;
  container.appendChild(wrap);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeFifiTyping(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// ── FIFI Responses ────────────────────────────────────────────

const FIFI_KB = [
  // ── Platform ──────────────────────────────────────────────
  {
    keys: ['what is bharatsec', 'what is this', 'explain', 'about this', 'tell me about', 'what is cybershield'],
 reply: `<strong>BharatSec</strong> is India's AI-powered cyber risk intelligence platform that analyzes any domain and tells you:\n\n• How exposed your digital identity is\n• What vulnerabilities exist RIGHT NOW\n• What an attacker could do with that info\n• What to fix first, ranked by impact\n\nThink of it as a complete security health check for your domain, powered by AI. Built for India. Trusted worldwide.`
  },
  {
    keys: ['products', 'bharatsec ai', 'copilot', 'soc', 'threat intelligence', 'bharatsec risk', 'bharatsec cloud'],
 reply: `<strong>BharatSec Product Suite</strong>, all available today:\n\n• <strong>Domain Scanner</strong>: attack surface discovery and a 0–100 risk score\n• <strong>Copilot</strong>: AI assistant grounded in your scan results\n• <strong>SOC</strong>: monitor your domains, triage alerts, run incidents\n• <strong>Threat Intel</strong>: CISA KEV and URLhaus feeds, IOC triage, environment matches\n• <strong>Cloud</strong>: read-only AWS, Azure and GCP posture checks\n• <strong>Risk</strong>: translate findings into financial loss scenarios\n\nStart with a domain scan from the box above.`
  },
  {
    keys: ['scan', 'how to scan', 'scan domain', 'analyze', 'start', 'begin'],
 reply: `<strong>Scanning is super easy!</strong>\n\n1. Type your domain (e.g. <code>mybusiness.com</code>) in the box above\n2. Check the authorization checkbox\n3. Click <strong>Run assessment</strong>\n\nThe scan runs DNS checks, SSL inspection, HTTP headers audit, subdomain enumeration, and AI risk analysis, all automatically. Results appear in about 30–60 seconds!`
  },
  {
    keys: ['good score', 'what score', 'score mean', 'score is', 'risk score', 'bharatsec score', 'cybershield score'],
 reply: `<strong>BharatSec Score Guide:</strong>\n\n<strong>85–100</strong> → SECURE: Well protected\n<strong>70–84</strong> → LOW RISK: Minor improvements needed\n<strong>55–69</strong> → MEDIUM RISK: Several gaps to address\n<strong>35–54</strong> → HIGH RISK: Significant vulnerabilities\n<strong>0–34</strong> → CRITICAL: Immediate action required\n\nMost businesses score between 40–70. A score above 75 is excellent!`
  },
  {
    keys: ['dmarc', 'spf', 'dkim', 'email security', 'email auth', 'spoofing'],
 reply: `<strong>Email Security (SPF, DMARC, DKIM):</strong>\n\n• <strong>SPF</strong>: Lists which servers can send emails for your domain\n• <strong>DMARC</strong>: Tells email receivers what to do with spoofed emails\n• <strong>DKIM</strong>: Cryptographically signs emails so they can't be forged\n\nWithout all three, <em>anyone</em> can send phishing emails pretending to be you. This is how 90%+ of business email fraud starts. FIFI recommends fixing this first!`
  },
  {
    keys: ['ssl', 'https', 'certificate', 'tls', 'encrypt'],
 reply: `<strong>SSL/TLS Certificates</strong> encrypt all data between your site and visitors.\n\nWithout a valid certificate:\n• Browsers show scary red warnings\n• Passwords travel in plaintext\n• Search engines rank you lower\n• Users don't trust your site\n\nBharatSec checks your certificate grade (A–F), protocol version, expiry date, and any known vulnerabilities.`
  },
  {
    keys: ['header', 'hsts', 'csp', 'x-frame', 'security header', 'http header'],
 reply: `<strong>HTTP Security Headers</strong> are free instructions you send to browsers:\n\n• <strong>HSTS</strong>: Forces HTTPS (prevents SSL stripping)\n• <strong>CSP</strong>: Prevents XSS attacks\n• <strong>X-Frame-Options</strong>: Blocks clickjacking\n• <strong>X-Content-Type-Options</strong>: Stops MIME sniffing\n• <strong>Referrer-Policy</strong>: Stops URL leakage\n\nMost take under 5 minutes to add. BharatSec scans for all of them!`
  },
  {
    keys: ['subdomain', 'subdomains', 'dev', 'staging', 'admin', 'attack surface'],
 reply: `<strong>Subdomains</strong> are additional entry points to your infrastructure.\n\nEvery active subdomain (dev, test, staging, admin, old) needs the same security attention as your main domain.\n\nDevelopment subdomains are especially risky because they often have:\n• Weaker authentication\n• Older software\n• Debug modes enabled\n• Shared credentials with production\n\nBharatSec discovers and risk-rates all your subdomains automatically!`
  },
  {
    keys: ['attack path', 'how attack', 'hacker', 'exploit', 'chain'],
 reply: `<strong>Attack Paths</strong> show how multiple weaknesses combine into real attacks.\n\n<strong>Example chain:</strong>\nMissing DMARC → Attacker sends spoofed email → Employee clicks → Malware installed → Account takeover → Data breach\n\nNo single weakness caused the breach, it's the <em>combination</em>. BharatSec AI maps these chains so you can break them at the weakest link.`
  },
  {
    keys: ['free', 'cost', 'price', 'paid', 'subscription'],
 reply: `<strong>BharatSec AI is completely free</strong> to use!\n\nJust enter your domain and hit scan. No credit card, no hidden fees.\n\nThis is a cybersecurity intelligence tool built to help individuals and organizations in India and beyond understand and reduce their digital risk.`
  },
  {
    keys: ['safe', 'legal', 'authorized', 'permission', 'ethical'],
 reply: `<strong>BharatSec is safe and ethical!</strong>\n\nWe perform <strong>passive reconnaissance only</strong>. We read publicly available information:\n• Public DNS records\n• Public WHOIS data\n• Public HTTP headers\n• Public SSL certificate info\n\nNo hacking, no exploitation, no unauthorized access. We do ask you to confirm you're authorized to scan the domain before starting.`
  },
  {
    keys: ['hello', 'hi', 'hey', 'hiya', 'sup', 'greetings'],
 reply: `Hey there! I'm <strong>FIFI</strong>, BharatSec's AI assistant!\n\nI can help you:\n• Understand how the platform works\n• Explain cybersecurity concepts in plain English\n• Tell you what to scan and why\n• Answer any security questions\n\nWhat would you like to know? `
  },
  {
    keys: ['who are you', 'what are you', 'your name', 'fifi'],
 reply: `I'm <strong>FIFI</strong>, the Friendly Intelligent Friend Interface!\n\nI'm BharatSec's built-in AI assistant. I know everything about this platform, cybersecurity best practices, and how to interpret your scan results.\n\nAsk me anything, I'm always here! `
  },
  {
    keys: ['fix', 'remediate', 'how to fix', 'what to do', 'improve score'],
 reply: `<strong>How to improve your BharatSec score:</strong>\n\nAfter scanning, go to the <strong>Remediation</strong> tab on the dashboard. FIFI (that's me, but on the dashboard) will rank all fixes by impact × effort.\n\n<strong>Quick wins (under 10 minutes each):</strong>\n1. Add DMARC DNS record\n2. Add HSTS + X-Frame-Options headers\n3. Enable HTTPS redirect\n4. Fix SPF record\n\nThese 4 steps alone can improve most scores by 15–25 points!`
  },
  {
    keys: ['india', 'bharat', 'indian', 'desi'],
 reply: `<strong>BharatSec is built for India!</strong>\n\nWe're building the first comprehensive AI-powered cybersecurity platform designed specifically with Indian businesses, startups, and organizations in mind.\n\nOur mission: Make enterprise-grade cybersecurity accessible to every Indian business, from a chai stall with a website to a Fortune 500 company. Jai Hind! `
  },

  // ── Cybersecurity Awareness ───────────────────────────────
  {
    keys: ['cyber crime', 'cybercrime', 'online fraud', 'scam', 'fraud', 'cyber fraud'],
 reply: `<strong>Cyber Crime Awareness:</strong>\n\nCyber crime is any illegal activity that uses a computer, network, or digital device. Common types in India:\n\n• <strong>Phishing</strong>: Fake emails/SMS pretending to be banks, govt, or companies to steal passwords & OTPs\n• <strong>UPI/Payment Fraud</strong>: Fake payment links, QR code scams, "send money to receive money" tricks\n• <strong>Identity Theft</strong>: Stealing personal data (Aadhaar, PAN) to open accounts or take loans in your name\n• <strong>Ransomware</strong>: Malware that locks your files until you pay a ransom\n• <strong>Job Fraud</strong>: Fake job offers asking for "registration fees" or personal documents\n• <strong>Social Media Hacking</strong>: Account takeover for blackmail, impersonation, or spreading scams\n\n<strong>If you are a victim:</strong> Report immediately at <code>cybercrime.gov.in</code> or call <strong>1930</strong> (National Cyber Crime Helpline).`
  },
  {
    keys: ['report cyber', 'cybercrime.gov', '1930', 'helpline', 'complaint', 'file complaint', 'police'],
 reply: `<strong>How to Report Cyber Crime in India:</strong>\n\n1. <strong>Call 1930</strong>: National Cyber Crime Helpline (24x7, toll-free)\n2. <strong>Visit cybercrime.gov.in</strong>: File a complaint online through the National Cyber Crime Reporting Portal\n3. <strong>Local Police Station</strong>: Every district now has a Cyber Cell. File an FIR.\n4. <strong>Bank</strong>: If financial fraud, call your bank immediately to freeze the transaction\n\n<strong>Information to keep ready:</strong>\n• Screenshots of messages/emails\n• Transaction IDs and amounts\n• Sender phone numbers/email addresses\n• Date and time of incident\n\n<strong>Remember:</strong> Report within the "Golden Hour" (first 24 hours) for the best chance of recovering lost money.`
  },
  {
    keys: ['cert-in', 'certin', 'cert', 'indian cert', 'computer emergency'],
 reply: `<strong>CERT-In (Indian Computer Emergency Response Team):</strong>\n\nCERT-In is India's national agency for cybersecurity incident response, operating under the Ministry of Electronics & IT (MeitY).\n\n<strong>What CERT-In does:</strong>\n• Responds to major cyber security incidents and breaches\n• Issues alerts and advisories about new threats and vulnerabilities\n• Coordinates incident response across government and private sector\n• Publishes security guidelines and best practices for organizations\n• Conducts cybersecurity drills and training programs\n\n<strong>Website:</strong> <code>cert-in.org.in</code>\n\nIf your organization faces a significant breach, you are legally required to report it to CERT-In within 6 hours under the IT Act guidelines.`
  },
  {
    keys: ['it act', 'information technology act', 'cyber law', 'law', 'legal', 'section', 'ipc'],
 reply: `<strong>Indian Cyber Laws (IT Act 2000):</strong>\n\nThe Information Technology Act, 2000 is India's primary law governing cybercrime and electronic commerce.\n\n<strong>Key sections:</strong>\n• <strong>Section 43</strong>: Penalty for damage to computer systems (unauthorized access, data theft)\n• <strong>Section 65</strong>: Tampering with computer source documents\n• <strong>Section 66</strong>: Computer-related offences (hacking)\n• <strong>Section 66C</strong>: Identity theft (using someone's digital signature, password, etc.)\n• <strong>Section 66D</strong>: Cheating by personation using computer resource\n• <strong>Section 66E</strong>: Violation of privacy (publishing private images without consent)\n• <strong>Section 67</strong>: Publishing obscene material electronically\n• <strong>Section 67A</strong>: Publishing sexually explicit material\n• <strong>Section 67B</strong>: Child pornography\n\nPunishments range from fines up to several lakh rupees to imprisonment of 3 years to life, depending on the offence.`
  },
  {
    keys: ['dpdp act', 'data protection', 'privacy law', 'personal data', 'dpdp'],
 reply: `<strong>Digital Personal Data Protection (DPDP) Act, 2023:</strong>\n\nIndia's comprehensive data privacy law that governs how organizations collect, process, and store personal data.\n\n<strong>Key provisions:</strong>\n• Organizations must get <strong>consent</strong> before collecting personal data\n• Individuals have the <strong>right to access, correct, and erase</strong> their data\n• Data breaches must be reported to the Data Protection Board and affected individuals\n• Significant data fiduciaries have additional obligations (DPO appointment, audits)\n• Cross-border data transfers are generally permitted (unlike GDPR)\n• Penalties up to <strong>₹250 crore</strong> per instance of non-compliance\n\n<strong>What this means for businesses:</strong> If you collect any personal data (names, emails, phone numbers, payment info), you need to comply with DPDP Act requirements. BharatSec can help you assess your exposure.`
  },
  {
    keys: ['ransomware', 'ransom', 'malware', 'virus', 'trojan', 'worm'],
 reply: `<strong>Ransomware & Malware Awareness:</strong>\n\n<strong>Ransomware</strong> is malicious software that encrypts your files and demands payment (ransom) to unlock them.\n\n<strong>How it spreads:</strong>\n• Phishing emails with infected attachments\n• Malicious links in messages\n• Compromised websites (drive-by downloads)\n• Infected USB drives\n• Exploiting unpatched software vulnerabilities\n\n<strong>Protection tips:</strong>\n• Keep all software and OS updated\n• Never open suspicious email attachments\n• Maintain offline backups of critical data\n• Use reputable antivirus/anti-malware\n• Enable file extensions in Windows to spot fake .pdf.exe files\n• Segment your network so an infection can't spread everywhere\n\n<strong>If infected:</strong> Disconnect from network immediately, do NOT pay the ransom (it funds more crime and there's no guarantee you'll get data back), and report to CERT-In.`
  },
  {
    keys: ['phishing', 'fake email', 'fake sms', 'smishing', 'vishing', 'fake call'],
 reply: `<strong>Phishing, Smishing & Vishing:</strong>\n\n• <strong>Phishing</strong>: Fraudulent emails that look like they're from legitimate sources (banks, IT dept, Amazon, etc.)\n• <strong>Smishing</strong>: Same thing via SMS/text messages\n• <strong>Vishing</strong>: Voice phishing via phone calls\n\n<strong>Red flags to spot them:</strong>\n Urgent language ("Your account will be blocked!")\n Requests for OTP, password, CVV, PIN\n Suspicious links (hover to see the real URL)\n Poor grammar or spelling\n Generic greetings ("Dear Customer" instead of your name)\n Too-good-to-be-true offers\n\n<strong>Golden rule:</strong> Banks, govt agencies, and legitimate companies will NEVER ask for your password, OTP, or PIN via email, SMS, or phone call.`
  },
  {
    keys: ['password', 'strong password', 'password security', '2fa', 'mfa', 'two factor', 'multi factor'],
 reply: `<strong>Password & Authentication Security:</strong>\n\n<strong>Creating strong passwords:</strong>\n• At least 12 characters long\n• Mix of uppercase, lowercase, numbers, and symbols\n• NOT based on personal info (name, birthdate, pet name)\n• Unique for every account, never reuse passwords\n• Use a <strong>password manager</strong> (Bitwarden, 1Password, etc.)\n\n<strong>Enable MFA/2FA everywhere:</strong>\n• Multi-Factor Authentication adds a second layer beyond your password\n• Even if your password is stolen, attackers can't log in without the second factor\n• Use authenticator apps (Google Authenticator, Authy) rather than SMS when possible\n\n<strong>Check if you've been breached:</strong> Visit <code>haveibeenpwned.com</code> to see if your email/password has appeared in known data breaches.`
  },
  {
    keys: ['social engineering', 'social media safety', 'impersonation', 'fake profile'],
 reply: `<strong>Social Engineering Attacks:</strong>\n\nSocial engineering is psychological manipulation to trick people into revealing confidential information or performing actions.\n\n<strong>Common tactics:</strong>\n• <strong>Pretexting</strong>: Attacker pretends to be someone in authority (IT support, bank officer, police)\n• <strong>Baiting</strong>: Offering something enticing (free download, USB drive left in parking lot)\n• <strong>Quid Pro Quo</strong>: "I'll help you with X if you give me Y"\n• <strong>Tailgating</strong>: Following someone into a secure area without authorization\n\n<strong>Protection:</strong>\n• Verify identity through a separate channel (call back on official number)\n• Be skeptical of unsolicited requests for information\n• Don't share too much personal info on social media\n• Train employees regularly, humans are the weakest link in security\n• Implement a "verify before acting" culture for sensitive requests`
  },
  {
    keys: ['public wifi', 'wifi security', 'hotspot', 'network security'],
 reply: `<strong>Public Wi-Fi Security:</strong>\n\nPublic Wi-Fi (cafes, airports, hotels, railway stations) is notoriously insecure.\n\n<strong>Risks:</strong>\n• <strong>Man-in-the-Middle attacks</strong>: Attacker intercepts your traffic\n• <strong>Evil Twin networks</strong>: Fake Wi-Fi named "Free Airport WiFi" that steals your data\n• <strong>Packet sniffing</strong>: Anyone on the same network can capture unencrypted traffic\n• <strong>Session hijacking</strong>: Stealing your login cookies to access your accounts\n\n<strong>Protection:</strong>\n• Always use a VPN on public Wi-Fi\n• Only visit HTTPS websites (look for the padlock)\n• Disable auto-connect to open networks\n• Don't access banking, email, or sensitive accounts on public Wi-Fi\n• Use your phone's hotspot instead when possible\n• Forget the network after using it`
  },
  {
    keys: ['data breach', 'breach', 'leaked', 'data leak', 'exposed'],
 reply: `<strong>What Data Breaches Mean:</strong>\n\nA data breach is when sensitive, confidential, or protected data is accessed, stolen, or exposed without authorization.\n\n<strong>Common causes:</strong>\n• Weak or stolen passwords\n• Unpatched software vulnerabilities\n• Insider threats (employees, contractors)\n• Misconfigured cloud storage (open S3 buckets, etc.)\n• Phishing attacks that steal credentials\n• Physical theft of devices\n\n<strong>Impact on organizations:</strong>\n• Financial losses (fines, lawsuits, remediation costs)\n• Reputation damage and loss of customer trust\n• Legal liability under DPDP Act / GDPR\n• Operational disruption\n\n<strong>If your data was breached:</strong>\n1. Change passwords immediately on affected accounts\n2. Enable MFA everywhere\n3. Monitor bank/credit card statements\n4. Check haveibeenpwned.com regularly\n5. Freeze credit if identity theft is suspected`
  },
  {
    keys: ['safe browsing', 'browser security', 'safe online', 'internet safety'],
 reply: `<strong>Safe Browsing Habits:</strong>\n\n<strong>Check the URL before you click:</strong>\n• Look for <code>https://</code> and the padlock icon\n• Watch for misspelled domains (amaz0n.com, flipkart-offers.in)\n• Don't click shortened URLs (bit.ly, tinyurl) unless you trust the source\n\n<strong>Browser security settings:</strong>\n• Keep your browser updated\n• Disable third-party cookies\n• Use privacy-focused browsers (Firefox, Brave)\n• Install ad-blockers (uBlock Origin)\n• Don't save passwords in the browser, use a password manager\n• Clear browsing data regularly\n\n<strong>Downloads:</strong>\n• Only download from official websites or app stores\n• Scan downloaded files with antivirus before opening\n• Be suspicious of .exe, .scr, .bat, .vbs files from unknown sources`
  },
  {
    keys: ['mobile security', 'phone security', 'android security', 'app security'],
 reply: `<strong>Mobile Security Tips:</strong>\n\nYour phone holds more personal data than your computer, so protect it accordingly.\n\n<strong>Essential steps:</strong>\n• Use a strong screen lock (6+ digit PIN or biometric)\n• Keep your OS and apps updated (security patches!)\n• Only install apps from Google Play Store / Apple App Store\n• Review app permissions, does a flashlight app really need your contacts?\n• Don't jailbreak/root your phone\n• Enable "Find My Device" / "Find My iPhone"\n• Use mobile security apps (look for CERT-In empanelled vendors)\n• Don't click links in SMS from unknown senders\n• Backup your data regularly\n\n<strong>App permissions to watch:</strong> Camera, Microphone, Location, Contacts, SMS: only grant when absolutely necessary.`
  },
  {
    keys: ['child safety', 'kids online', 'parental control', 'child protection'],
 reply: `<strong>Child Online Safety:</strong>\n\nChildren are increasingly targeted by cyber criminals through gaming platforms, social media, and messaging apps.\n\n<strong>Risks for children:</strong>\n• Cyberbullying and online harassment\n• Online predators and grooming\n• Exposure to inappropriate content\n• Identity theft (children's identities are valuable, clean credit history)\n• In-app purchase scams and gaming fraud\n• Oversharing personal information\n\n<strong>What parents can do:</strong>\n• Use parental controls on devices and apps\n• Keep computers in common areas, not bedrooms\n• Talk openly about online safety, build trust, not fear\n• Teach them: never share personal info, photos, or location with strangers\n• Monitor screen time and app usage\n• Know their friends, both real and online\n• Report cyber crimes against children at <code>cybercrime.gov.in</code>`
  },
  {
    keys: ['business security', 'small business', 'startup security', 'company security', 'msme'],
 reply: `<strong>Cybersecurity for Indian Businesses & Startups:</strong>\n\nSmall businesses and startups are prime targets: 43% of cyber attacks target small businesses, and 60% of those go out of business within 6 months.\n\n<strong>Minimum security baseline:</strong>\n1. Use strong, unique passwords + MFA on all accounts\n2. Keep all software, CMS, and plugins updated\n3. Regular offline backups (3-2-1 rule: 3 copies, 2 media types, 1 offsite)\n4. HTTPS everywhere with valid SSL certificates\n5. Email security: SPF, DKIM, DMARC configured\n6. Employee security awareness training\n7. Access control: least privilege principle\n8. Incident response plan (who to call, what to do)\n\n<strong>Start with BharatSec:</strong> Scan your domain to see your current exposure, it's free and takes 60 seconds. Then work through the prioritized remediation plan.`
  },
  {
    keys: ['cloud security', 'aws security', 'azure', 'gcp', 'cloud misconfig'],
 reply: `<strong>Cloud Security Basics:</strong>\n\nCloud misconfiguration is one of the leading causes of data breaches worldwide.\n\n<strong>Common mistakes:</strong>\n• Publicly accessible S3 buckets / blob storage\n• Overly permissive IAM roles and security groups\n• Unencrypted data at rest or in transit\n• Disabled logging and monitoring\n• Default credentials on cloud services\n• Exposed API keys in code repositories\n\n<strong>Best practices:</strong>\n• Follow the principle of least privilege for all IAM roles\n• Enable MFA for all cloud accounts, especially root\n• Encrypt all sensitive data\n• Enable logging (CloudTrail, etc.) and set up alerts\n• Regularly audit security groups and firewall rules\n• Use infrastructure-as-code (Terraform, etc.) to avoid manual misconfigurations\n• Scan your cloud footprint regularly, BharatSec Cloud (coming soon) will help with this!`
  },
  {
    keys: ['zero trust', 'zero trust architecture', 'zta'],
 reply: `<strong>Zero Trust Architecture (ZTA):</strong>\n\n"Never trust, always verify" is the core principle of Zero Trust security.\n\n<strong>Key principles:</strong>\n• No user or device is trusted by default, even if inside the network\n• Every access request must be authenticated, authorized, and encrypted\n• Least privilege access, users get only what they need\n• Micro-segmentation, break the network into small zones\n• Continuous monitoring and validation\n\n<strong>Why it matters:</strong> Traditional "castle-and-moat" security (strong perimeter, trusted inside) fails when attackers get past the firewall. Zero Trust assumes breach and limits the blast radius.\n\n<strong>For Indian organizations:</strong> CERT-In recommends Zero Trust principles in its security guidelines. Start with MFA, network segmentation, and access reviews.`
  },
];

const GENERAL_KB = [
  {
    keys: ['prime minister of india', 'pm of india', 'who is pm', 'prime minister'],
 reply: `As of October 2026, <strong>Narendra Modi</strong> is the Prime Minister of India. He began his third consecutive term on 9 June 2024.`
  },
  {
    keys: ['president of india', 'who is the president'],
 reply: `As of October 2026, <strong>Droupadi Murmu</strong> is the President of India and its constitutional head of state.`
  },
  {
    keys: ['capital of india', 'indian capital'],
 reply: `<strong>New Delhi</strong> is the capital of India.`
  },
  {
    keys: ['currency of india', 'indian currency', 'rupee'],
 reply: `India's currency is the <strong>Indian rupee (INR)</strong>, represented by the symbol ₹.`
  },
  {
    keys: ['national language', 'language of india'],
 reply: `India has <strong>no national language</strong>. Hindi and English are used for official Union government purposes; states may designate their own official languages.`
  },
  {
    keys: ['independence day', 'when did india become independent'],
 reply: `India became independent from British rule on <strong>15 August 1947</strong>. Independence Day is observed on 15 August each year.`
  },
  {
    keys: ['national animal', 'national bird', 'national flower'],
 reply: `India's national animal is the <strong>Bengal tiger</strong>, its national bird is the <strong>Indian peafowl</strong>, and its national flower is the <strong>lotus</strong>.`
  },
  {
    keys: ['national anthem'],
 reply: `India's national anthem is <strong>Jana Gana Mana</strong>.`
  },
  {
    keys: ['national sport', 'official sport of india'],
 reply: `India has <strong>no officially designated national sport</strong>.`
  },
  {
    keys: ['how many states', 'number of states', 'states and union territories'],
 reply: `India has <strong>28 states and 8 union territories</strong>.`
  },
  {
    keys: ['artificial intelligence', 'ai', 'machine learning', 'llm', 'large language model'],
 reply: `<strong>Artificial Intelligence (AI)</strong> is the field of building systems that can learn patterns, reason, and make decisions from data.\n\n• <strong>Machine Learning</strong> teaches a model from examples\n• <strong>Generative AI</strong> can create text, images, code, and dialogue\n• <strong>LLMs</strong> are large models trained on massive amounts of text\n\nAI is useful for search, automation, writing, coding, analysis, and cyber defense.`
  },
  {
    keys: ['python', 'javascript', 'java', 'programming', 'coding', 'developer', 'software'],
 reply: `<strong>Programming</strong> is the process of giving instructions to a computer to perform tasks.\n\n• <strong>Python</strong> is great for AI, automation, and scripting\n• <strong>JavaScript</strong> powers interactive websites and frontend apps\n• <strong>HTML/CSS</strong> structure and style web pages\n\nThe best language depends on your goal: web, automation, data science, cybersecurity, or app development.`
  },
  {
    keys: ['dns', 'domain name system', 'ip address', 'http', 'https', 'website', 'internet'],
 reply: `<strong>How the internet works:</strong>\n\n• <strong>DNS</strong> translates names like example.com into IP addresses\n• <strong>IP address</strong> is the device address on the network\n• <strong>HTTP/HTTPS</strong> are protocols used for web traffic\n• <strong>HTTPS</strong> encrypts the connection using TLS\n\nWithout DNS, the internet would be hard to use because humans remember names, not numbers.`
  },
  {
    keys: ['cloud', 'aws', 'azure', 'gcp', 'docker', 'kubernetes'],
 reply: `<strong>Cloud computing</strong> means using remote servers over the internet instead of owning all hardware yourself.\n\nPopular services include AWS, Azure, and Google Cloud. They help teams deploy apps, store data, and scale faster.\n\nFor security, you still need proper access control, patching, monitoring, and encrypted data storage.`
  },
  {
    keys: ['blockchain', 'bitcoin', 'cryptocurrency', 'crypto'],
 reply: `<strong>Blockchain</strong> is a distributed digital ledger that records transactions across many computers. It is designed to be hard to alter after the fact.\n\nCryptocurrency like Bitcoin uses blockchain technology, but blockchain itself can also be used for supply chains, identity, and secure records.\n\nImportant caveat: crypto is risky, volatile, and often targeted by scams and fraud.`
  },
  {
    keys: ['mobile phone', 'android', 'ios', 'smartphone', 'phone', 'laptop', 'computer'],
 reply: `<strong>Modern devices</strong> are digital tools used for communication, work, shopping, and entertainment.\n\nTo stay safe: keep software updated, use strong locks, avoid untrusted apps, and enable MFA where available. This protects your data from loss, theft, and malware.`
  },
  {
    keys: ['learn', 'study', 'career', 'cybersecurity career', 'jobs', 'cyber security job'],
 reply: `<strong>Cybersecurity careers</strong> include security analyst, ethical hacker, SOC engineer, cloud security specialist, incident responder, and GRC specialist.\n\nA strong path is: learn networking, Linux, Python, security basics, then specialize in web, cloud, or threat intelligence. Practice with labs, CTFs, and real-world projects.`
  },
  {
    keys: ['math', 'statistics', 'algebra', 'calculus', 'probability'],
 reply: `<strong>Math</strong> is the language of logic, models, and systems.\n\n• <strong>Algebra</strong> helps with equations and patterns\n• <strong>Statistics</strong> helps analyze uncertainty and risk\n• <strong>Probability</strong> helps estimate likelihood\n\nThese are especially important in data science, AI, and cyber risk analysis.`
  },
  {
    keys: ['india', 'bharat', 'history', 'geography', 'country'],
 reply: `<strong>India</strong> is a large South Asian country with a rich history, diverse culture, and a fast-growing digital economy. It is also a rapidly evolving cybersecurity and technology market with major focus on digital public infrastructure, compliance, and infrastructure security.`
  }
];

function matchesKnowledgeKeyword(message, keyword) {
  const text = message.toLowerCase();
  const term = keyword.toLowerCase();
  if (term.length > 3) return text.includes(term);
  const escapedTerm = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`\\b${escapedTerm}\\b`, 'i').test(text);
}

function getGeneralKnowledgeResponse(message) {
  const msg = message.toLowerCase();

  for (const { keys, reply } of GENERAL_KB) {
    if (keys.some(key => matchesKnowledgeKeyword(msg, key))) return reply;
  }

  if (/(what|who|why|how|when|where|which)/.test(msg)) {
 return `Here is a practical way to think about that question:\n\n1. Define the topic clearly\n2. Break it into simple parts\n3. Ask what it does, why it matters, and how it works\n4. For technology, check if it is about security, software, networking, or AI\n\nI can help with general knowledge, cybersecurity, BharatSec, software, coding, internet basics, and business/tech questions. Ask me a more specific question and I’ll answer it clearly.`;
  }

 return `I can answer a wide range of questions about tech, cybersecurity, BharatSec, internet basics, coding, AI, business, and general knowledge.\n\nTry asking me something like:\n• What is AI?\n• What is cloud computing?\n• What is phishing?\n• What is Python?\n• How do I protect my website?\n\nI’ll explain it in simple, practical language.`;
}

function getFIFIResponse(message) {
  const msg = message.toLowerCase();
  for (const { keys, reply } of FIFI_KB) {
    if (keys.some(key => matchesKnowledgeKeyword(msg, key))) return reply;
  }

  for (const { keys, reply } of GENERAL_KB) {
    if (keys.some(key => matchesKnowledgeKeyword(msg, key))) return reply;
  }

  return getGeneralKnowledgeResponse(message);
}

// ── Rotating suggestion chips ─────────────────────────────────

const ALL_CHIPS = [
  "What is BharatSec?",
  "How do I scan my domain?",
  "What is a good security score?",
  "What is DMARC?",
  "Explain SSL certificates",
  "What are security headers?",
  "How do I fix my score?",
  "Is BharatSec free?",
  "Is scanning safe and legal?",
  "What is FIFI?",
  "Tell me about BharatSec products",
  "What is cyber crime?",
  "How do I report cyber fraud?",
  "What is CERT-In?",
  "What is phishing?",
  "How to create strong passwords?",
  "What is ransomware?",
  "Is public WiFi safe?",
  "What is the IT Act 2000?",
  "What is DPDP Act 2023?",
  "Tips for mobile security",
  "Cybersecurity for small business",
  "What is social engineering?",
  "How to protect kids online?",
  "What is Zero Trust?",
];

function updateFifiChips(lastMsg) {
  if (!lastMsg) return;
  usedChips.add(lastMsg.toLowerCase());
  const container = document.getElementById('fifi-suggestions');
  if (!container) return;
  const available = ALL_CHIPS.filter(c => !usedChips.has(c.toLowerCase())).slice(0, 3);
  container.innerHTML = available.map(c =>
    `<button type="button" class="fifi-chip" onclick="fifSend(this)">${c}</button>`
  ).join('');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
