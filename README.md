# 🛡️ BharatSec
### Personal & Organizational Digital Risk Guardian

> **"Know Your Exposure. Understand Your Risk. Protect Your Digital World."**

BharatSec is a full-stack cybersecurity intelligence platform that continuously evaluates a domain's security posture — discovering attack surfaces, analyzing vulnerabilities, calculating an AI-powered risk score, and delivering prioritized remediation guidance.

---

## 🚀 Quick Start

### 1. Preview the Frontend
```
Open frontend/index.html in any browser
```
The static landing page can be previewed directly. Sign-in, protected workspaces, assistant API access, and live scans require the backend; serve the app from the backend for a complete local run.

### 2. Start the Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
```
Backend runs at: http://localhost:8000  
API Docs at: http://localhost:8000/api/docs

Create an account at http://127.0.0.1:8000/login before using protected features. Keep the backend terminal open during the scan. For local runs, BharatSec serves the dashboard and API from the same origin. Verify the server at http://127.0.0.1:8000/api/health.

### BharatSec SOC

Open http://127.0.0.1:8000/soc after signing in. Add only public domains you own or are explicitly authorized to monitor. The local SOC stores assets, deduplicated availability/TLS/HTTPS alerts, incidents, assignments, and timeline notes in `backend/data/soc.db`. Enabled assets are checked automatically on their configured interval; a manual **Check** action is also available.

SOC checks use bounded DNS, HTTPS, and HTTP requests and refuse domains that resolve to private or reserved IP addresses. The service uses server-side accounts and sessions; account recovery, organization roles, and email/SMS/webhook notifications are not included.

### BharatSec Threat Intel

Open http://127.0.0.1:8000/threat-intel after signing in. The workspace syncs CISA KEV and abuse.ch URLhaus indicators, supports analyst-submitted IOCs and triage states, enriches indicators with local DNS/CVE context, and correlates domain/URL indicators with SOC assets. Feed polling defaults to every 15 minutes; use **Sync feeds** for an on-demand refresh. Set `VIRUSTOTAL_API_KEY` in the backend environment to enable optional reputation lookups.

Breach exposure checks are optional: set `HIBP_API_KEY` server-side and add a domain verified with Have I Been Pwned. Results contain breach names and account counts only. This checks a historic breach corpus; it is not live or private dark-web monitoring. ATT&CK associations describe feed context, not observed attacker activity. Threat Intel data is stored in `backend/data/threat_intel.db`.

### BharatSec Risk

Open http://127.0.0.1:8000/risk after signing in. Risk quantification translates completed BharatSec scans into adjustable financial loss scenarios using organization-supplied assumptions, saved in the browser. Estimates are planning inputs, not actuarial forecasts, legal advice, or regulatory assessments. The workspace includes a clearly labeled illustrative scenario; completed scans are held in memory for the lifetime of the backend process.

### BharatSec Cloud

Open http://127.0.0.1:8000/cloud after signing in. Cloud scans are **read-only** and use the backend's configured AWS credential chain, Azure `DefaultAzureCredential`, or Google Application Default Credentials. Do not paste cloud secrets into the browser. Install backend requirements, configure the appropriate local profile/role, managed identity, service principal environment, or ADC, and grant the read permissions shown in the provider workspace. Select a provider, confirm authorization, and start a scan. Results and scan history are stored in `backend/data/cloud.db`; provider credentials are never stored by BharatSec.

Checks include AWS S3 public-access controls, policies, ACLs, encryption and logging, IAM administrator access and old active access keys, internet-open security groups, and public EC2 IPs; Azure storage account and blob-container public access, broad subscription role assignments, and internet-open network security group rules; and GCP Cloud Storage IAM/public-access prevention, encryption/logging settings, broad project IAM roles, and Compute Engine external IPs. Missing permissions are reported as coverage warnings. These inventory checks are point-in-time signals, not a full compliance certification or guarantee that an environment is secure.

The backend binds to `127.0.0.1` by default. All application APIs, API documentation, and workspace pages require a server-side account session; `/api/health`, the landing page, sign-in, and registration status remain public. Passwords are PBKDF2-hashed and sessions use revocable, HttpOnly, SameSite=Strict cookies. Registration is enabled for local development and disabled by default on public binds. Authenticated accounts share the platform's SOC, threat-intelligence, and cloud workspace; this release does not provide per-organization data isolation or role-based access.

**Before deployment:** serve the frontend and API from one HTTPS origin behind a TLS-terminating reverse proxy. Set `BHARATSEC_HOST=0.0.0.0`, `BHARATSEC_SESSION_SECRET` to a unique random secret of at least 32 characters, `BHARATSEC_COOKIE_SECURE=true`, and `BHARATSEC_CORS_ORIGINS` to the exact allowed HTTPS origins (comma-separated, never `*`). On first startup, set `BHARATSEC_BOOTSTRAP_USERNAME` and a strong `BHARATSEC_BOOTSTRAP_PASSWORD` (12+ characters) to create the initial account. Registration remains disabled unless deliberately enabled with `BHARATSEC_ALLOW_REGISTRATION=true`; only do so for a trusted team because accounts share one workspace. Keep the backend and its SQLite data directory on persistent storage, protect the server and backups, and configure network/firewall controls. Authentication has basic per-IP/account request throttles. Behind a reverse proxy, set `BHARATSEC_TRUSTED_PROXY_HOPS` to the number of proxies that append to `X-Forwarded-For` (usually `1`) so throttles see real client addresses; leave it at `0` when the app is reachable without that proxy, because the header is otherwise caller-controlled. The application does not yet provide password-reset email, MFA, organization isolation, or administrative account management; assess those requirements before opening registration to the public.

For example, create a session secret in PowerShell with:
```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
```

### Render demo deployment

The repository includes [`render.yaml`](./render.yaml) for a free Render demo service named `bharatsec-web`. Create the service from the Render Blueprint and provide `BHARATSEC_BOOTSTRAP_USERNAME` plus a strong `BHARATSEC_BOOTSTRAP_PASSWORD` when prompted. The blueprint generates the session secret, enables secure cookies, disables public registration, and allows only `https://bharatsec-web.onrender.com`. If Render assigns a different service URL, update `BHARATSEC_CORS_ORIGINS` to that exact HTTPS origin.

Render's free service has ephemeral storage and may spin down; accounts and SQLite data can reset when the service restarts or redeploys. Use a paid service with a persistent disk before storing real customer, SOC, threat-intelligence, or cloud-scan data.

---

## 🔑 Optional: Connect a Copilot AI Provider

BharatSec AI answers questions on cybersecurity (at any depth), Indian cyber law (CERT-In, IT Act, DPDP Act), AI and LLMs, business and startups, programming, and general knowledge. The landing-page assistant uses `POST /api/ai/chat/stream` and the dashboard Copilot uses `POST /api/ai/copilot/stream` (scan-grounded); both stream answers token by token, render formatted Markdown safely, and remember the last 12 conversation turns. Non-streaming `POST /api/ai/chat` and `POST /api/ai/copilot` remain available. Answers come from **Gemini** when `GEMINI_API_KEY` is set and **OpenAI** when `OPENAI_API_KEY` is set; with both, Gemini is tried first and OpenAI takes over automatically if Gemini is rate-limited or down (each provider gets one retry). Without any key, BharatSec AI runs in **offline knowledge mode**: it answers from a built-in knowledge base (security, Indian cyber law, AI, business basics, this platform) and says clearly when a question needs a provider key. `GET /api/ai/status` reports which mode is active. Provider keys are **not required for domain scans and do not make network/DNS scanning faster**.

The microphone buttons provide speech-to-text input in supported secure browser contexts. Assistant replies are displayed as text and are not spoken aloud.

Optional AI settings: `GEMINI_MODEL` (default `gemini-2.5-flash`), `OPENAI_MODEL` (default `gpt-4.1-mini`), `COPILOT_TIMEOUT` (default 45 seconds), `AI_MAX_OUTPUT_TOKENS` (default 2048, the longest answer), and `AI_RATE_LIMIT_PER_MINUTE` (default 20 AI requests per user per minute, to protect your provider quota and bill).

**Windows (PowerShell, Gemini):**

```powershell
$env:GEMINI_API_KEY = "your-api-key-here"
cd backend
python main.py
```

**Windows (PowerShell, OpenAI alternative):**
```powershell
$env:OPENAI_API_KEY = "your-api-key-here"
cd backend
python main.py
```

The dashboard sends the active scan ID and the latest 12 conversation turns to the Copilot. Each answer shows whether it came from Gemini, OpenAI, or offline knowledge. If a provider fails before answering, BharatSec AI falls back to the next provider and then to offline knowledge; if an answer is cut off mid-stream, the chat says so and offers a retry. All AI endpoints require a signed-in account; signed-out visitors are invited to sign in.

**Linux/Mac:**
```bash
cd backend
GEMINI_API_KEY=your-api-key-here python main.py
```

Get a free Gemini API key at: https://makersuite.google.com/app/apikey

---

## 📁 Project Structure

```
BharatSec/
├── README.md
├── render.yaml                     ← Render demo deployment blueprint
├── backend/
│   ├── main.py                     ← FastAPI entry point, auth middleware, page routes
│   ├── config.py                   ← Settings loaded from environment / .env
│   ├── auth.py                     ← Accounts, sessions, login rate limits
│   ├── requirements.txt
│   ├── .env.example                ← Copy to .env and fill in optional keys
│   ├── engines/
│   │   ├── net_guard.py            ← Blocks scans of private/internal addresses
│   │   ├── osint_engine.py         ← DNS, WHOIS, subdomains, web fingerprinting
│   │   ├── security_engine.py      ← TLS certificate and protocol checks
│   │   ├── risk_engine.py          ← Findings, score, attack paths, priorities
│   │   ├── ai_engine.py            ← Assistant / Copilot (Gemini, OpenAI, rules)
│   │   ├── soc_engine.py           ← SOC asset monitoring, alerts, incidents
│   │   ├── threat_intel_engine.py  ← Feeds, IOCs, correlation, breach watches
│   │   └── cloud_engine.py         ← AWS / Azure / GCP posture checks
│   ├── routers/                    ← /api/* endpoints: auth, scan, ai, soc, threat_intel, cloud
│   ├── models/
│   │   └── scan_models.py          ← Pydantic data models
│   ├── tests/                      ← unittest suite (python -m unittest discover -s tests -t .)
│   └── data/                       ← SQLite databases (created at runtime, not committed)
└── frontend/
    ├── index.html                  ← Landing page
    ├── login.html                  ← Sign in / register
    ├── dashboard.html              ← Domain scan dashboard
    ├── soc.html                    ← SOC workspace
    ├── threat-intel.html           ← Threat Intel workspace
    ├── cloud.html                  ← Cloud posture workspace
    ├── risk.html                   ← Risk quantification workspace
    └── assets/
        ├── css/                    ← One stylesheet per page, plus shared product-brand.css
        ├── js/                     ← One script per page, plus shared auth.js
        └── images/
            ├── brand/
            │   └── bharatsec-logo.png  ← Logo used across the app
            ├── products/           ← SOC, Threat Intel, Cloud, Risk logos (SVG)
            └── logo.png            ← Archived original brand artwork (not used by pages)
```

---

## 🧠 Features

| Feature | Description |
|---|---|
| **BharatSec Score** | 0–100 risk score across 5 weighted categories |
| **Attack Surface Discovery** | DNS, subdomains, SSL, HTTP headers, WHOIS |
| **AI Threat Analyst** | Every finding explained in plain English |
| **Attack Path Simulation** | Visual attack chains from scan data |
| **Prioritized Remediation** | Top 5 actions ranked by impact × effort |
| **Security Copilot** | Context-aware AI chat assistant |
| **Executive Dashboard** | Non-technical one-screen summary |
| **Demo Mode** | Always-working demo with example.com data |

---

## ⚠️ Legal Disclaimer

BharatSec is designed for authorized security assessments only.
Only scan domains you own or have explicit written permission to test.
This tool performs passive reconnaissance and does NOT perform any active exploitation.

---

## 🛠️ Tech Stack

- **Frontend:** HTML5, CSS3 (Vanilla), JavaScript, Chart.js
- **Backend:** Python 3.11+, FastAPI, dnspython, python-whois, httpx
- **AI:** Rule-based engine + optional Gemini/OpenAI integration
- **Database:** In-memory (SQLite in Phase 2)
