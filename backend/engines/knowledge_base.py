"""Offline knowledge for BharatSec AI.

Used when no language-model provider is configured or reachable. Answers are short, factual and
written in Markdown. Each entry lists trigger phrases; the entry with the most matching phrases wins.
"""
import re
from typing import List, Optional, Tuple

KNOWLEDGE: List[Tuple[Tuple[str, ...], str]] = [
    # ── Cybersecurity fundamentals ───────────────────────────────────────────
    (("cia triad", "confidentiality", "integrity", "availability"),
     "**The CIA triad** is the foundation of information security:\n\n"
     "- **Confidentiality**: only authorised people can read data (encryption, access control).\n"
     "- **Integrity**: data is not altered without detection (hashing, signatures, change control).\n"
     "- **Availability**: systems stay usable when needed (redundancy, backups, DDoS protection)."),
    (("ddos", "denial of service", "dos attack"),
     "**DDoS (Distributed Denial of Service)** floods a service with traffic from many machines (often a botnet) until real users cannot reach it.\n\n"
     "**Defences:** a CDN/anti-DDoS provider, rate limiting, autoscaling, upstream ISP scrubbing, and a tested incident runbook."),
    (("social engineering", "pretexting", "vishing", "smishing"),
     "**Social engineering** manipulates people rather than systems: fake calls (vishing), SMS (smishing), urgent emails or impersonation.\n\n"
     "**Defences:** verify requests through a second channel, never share OTPs, use phishing-resistant MFA, and train staff with realistic simulations."),
    (("password", "passwords", "password manager", "passkey", "passkeys"),
     "**Strong authentication basics:**\n\n"
     "1. Use a **password manager** and a unique password for every account.\n"
     "2. Prefer long passphrases (16+ characters) over complex short passwords.\n"
     "3. Turn on **MFA** everywhere; **passkeys** (FIDO2/WebAuthn) are phishing-resistant and the best option where available.\n"
     "4. Never reuse work passwords on personal sites."),
    (("vpn", "virtual private network"),
     "A **VPN** encrypts traffic between your device and a VPN server, protecting it on untrusted networks such as public Wi-Fi.\n\n"
     "It does **not** make you anonymous or protect against malware or phishing. For company access, many teams now prefer **Zero Trust Network Access (ZTNA)** over a flat VPN."),
    (("siem", "security information"),
     "A **SIEM** (Security Information and Event Management) collects logs from servers, cloud, endpoints and network devices, correlates them, and raises alerts.\n\n"
     "Examples: Splunk, Microsoft Sentinel, Elastic, Wazuh (open source). It is the core tool of a **SOC**."),
    (("soc", "security operations center", "security operations centre"),
     "A **SOC (Security Operations Center)** is the team and tooling that monitors, detects, investigates and responds to security incidents around the clock.\n\n"
     "Typical tiers: **L1** triage alerts, **L2** investigates, **L3** hunts threats and handles complex incidents. BharatSec SOC helps you monitor domains, triage alerts and track incidents."),
    (("incident response", "ir plan", "breach response"),
     "**Incident response** follows a repeatable cycle (NIST SP 800-61):\n\n"
     "1. **Prepare**: runbooks, contacts, logging, backups.\n"
     "2. **Detect & analyse**: confirm scope and impact.\n"
     "3. **Contain**: isolate affected systems and accounts.\n"
     "4. **Eradicate & recover**: remove the cause, restore safely.\n"
     "5. **Lessons learned**: fix root causes.\n\n"
     "In India, report qualifying incidents to **CERT-In within 6 hours**."),
    (("vulnerability", "cve", "cvss", "patch", "patching"),
     "A **vulnerability** is a weakness attackers can exploit. Public ones get a **CVE ID** and a **CVSS** severity score (0–10).\n\n"
     "Prioritise patching by real risk: anything on the **CISA KEV** (Known Exploited Vulnerabilities) list or internet-facing first. BharatSec Threat Intel tracks KEV for you."),
    (("penetration test", "pentest", "pen test", "ethical hacking", "red team"),
     "A **penetration test** is an authorised, scoped simulation of an attack to find weaknesses before criminals do. **Red teaming** is a broader, goal-based exercise that also tests detection and response.\n\n"
     "Always get **written authorisation** and a defined scope first."),
    (("sql injection", "sqli"),
     "**SQL injection** happens when user input is placed into a database query unsafely, letting an attacker read or change data.\n\n"
     "**Fix:** use parameterised queries / prepared statements, an ORM, least-privilege database accounts, and input validation."),
    (("xss", "cross-site scripting", "cross site scripting"),
     "**Cross-site scripting (XSS)** lets an attacker run JavaScript in other users' browsers, stealing sessions or data.\n\n"
     "**Fix:** encode output for its context, avoid `innerHTML` with untrusted data, use a strict **Content-Security-Policy**, and set cookies `HttpOnly`."),
    (("csrf", "cross-site request forgery"),
     "**CSRF** tricks a signed-in user's browser into sending an unwanted request.\n\n"
     "**Fix:** `SameSite` cookies, anti-CSRF tokens, and checking the `Origin` header on state-changing requests."),
    (("dmarc", "spf", "dkim", "email security", "email spoofing"),
     "**Email authentication** stops attackers sending mail as your domain:\n\n"
     "- **SPF**: lists servers allowed to send for you.\n"
     "- **DKIM**: cryptographically signs your messages.\n"
     "- **DMARC**: tells receivers what to do when SPF/DKIM fail (`p=quarantine` or `p=reject`) and sends you reports.\n\n"
     "Start with `p=none`, review reports, then move to `p=reject`."),
    (("hsts", "security headers", "content security policy", "csp"),
     "**Key HTTP security headers:**\n\n"
     "- `Strict-Transport-Security`: forces HTTPS.\n"
     "- `Content-Security-Policy`: limits where scripts can load from (strong XSS defence).\n"
     "- `X-Frame-Options` / `frame-ancestors`: blocks clickjacking.\n"
     "- `X-Content-Type-Options: nosniff` and `Referrer-Policy`.\n\n"
     "Run a BharatSec scan to see which ones your site is missing."),
    (("cloud security", "s3 bucket", "iam", "misconfiguration"),
     "**Most cloud breaches come from misconfiguration**, not provider flaws:\n\n"
     "- Block public access on storage (S3, Blob, GCS).\n"
     "- Least-privilege IAM; no long-lived keys; MFA on admin and root.\n"
     "- Never expose SSH/RDP to `0.0.0.0/0`.\n"
     "- Turn on logging (CloudTrail, Activity Log, Audit Logs).\n\n"
     "BharatSec Cloud runs these checks read-only across AWS, Azure and GCP."),
    (("supply chain", "third party risk", "vendor risk", "sbom"),
     "**Supply-chain attacks** compromise a supplier, library or update channel to reach many victims (e.g. SolarWinds, malicious npm packages).\n\n"
     "**Defences:** vendor security reviews, an **SBOM**, dependency scanning, pinned and verified packages, and least-privilege integrations."),
    (("iso 27001", "soc 2", "compliance", "nist csf", "pci dss"),
     "**Common security frameworks:**\n\n"
     "- **ISO/IEC 27001**: certifiable information-security management system.\n"
     "- **SOC 2**: US attestation on security/availability/confidentiality controls.\n"
     "- **NIST CSF 2.0**: Govern, Identify, Protect, Detect, Respond, Recover.\n"
     "- **PCI DSS**: required if you handle card payments."),
    # ── India: law, regulation, ecosystem ────────────────────────────────────
    (("cert-in", "certin", "cert in"),
     "**CERT-In** (Indian Computer Emergency Response Team) is India's national agency for cyber incidents under MeitY.\n\n"
     "Its April 2022 directions require organisations to **report specified incidents within 6 hours**, keep ICT logs for **180 days** within India, and synchronise clocks with NTP sources such as NIC or NPL."),
    (("dpdp", "data protection act", "personal data protection", "privacy law india"),
     "The **Digital Personal Data Protection (DPDP) Act, 2023** is India's main data-protection law.\n\n"
     "- Personal data needs **consent** or a legitimate use.\n"
     "- **Data Fiduciaries** must protect data and report breaches to the **Data Protection Board** and affected people.\n"
     "- Penalties go up to **₹250 crore** per breach of security safeguards.\n\n"
     "The DPDP Rules (notified in 2025) phase in the detailed obligations."),
    (("it act", "information technology act", "section 66", "section 43"),
     "The **Information Technology Act, 2000** is India's core cyber law. Key sections:\n\n"
     "- **43 / 43A**: compensation for unauthorised access and for failing to protect sensitive data.\n"
     "- **66**: computer-related offences; **66C** identity theft; **66D** impersonation fraud.\n"
     "- **70**: protected (critical) systems.\n\n"
     "Report cybercrime at **cybercrime.gov.in** or call **1930**."),
    (("cyber crime", "cybercrime", "1930", "report fraud", "online fraud"),
     "**If you face online fraud in India:**\n\n"
     "1. Call the **1930** national cybercrime helpline immediately (faster recovery of money).\n"
     "2. File a complaint at **cybercrime.gov.in**.\n"
     "3. Inform your bank and block cards/UPI.\n"
     "4. Keep screenshots, transaction IDs and phone numbers as evidence."),
    (("upi", "upi fraud", "upi scam"),
     "**UPI safety:** you **never** need to enter your UPI PIN to *receive* money. Ignore 'collect requests' from strangers, don't scan QR codes to get refunds, and never share OTPs or screen-sharing access. Report fraud on **1930**."),
    # ── AI ───────────────────────────────────────────────────────────────────
    (("artificial intelligence", "what is ai", "ai", "machine learning", "deep learning"),
     "**Artificial Intelligence (AI)** builds systems that perform tasks needing human-like intelligence.\n\n"
     "- **Machine learning** learns patterns from data instead of hand-written rules.\n"
     "- **Deep learning** uses large neural networks (vision, speech, language).\n"
     "- **Generative AI** creates text, images, code and audio.\n\n"
     "In security, AI helps with anomaly detection, phishing classification and alert triage, and attackers also use it for convincing phishing and deepfakes."),
    (("llm", "large language model", "chatgpt", "gemini", "claude", "gpt"),
     "A **large language model (LLM)** is a neural network trained on huge amounts of text to predict the next token, which lets it answer questions, write and summarise.\n\n"
     "Popular families: OpenAI GPT, Google Gemini, Anthropic Claude, Meta Llama. LLMs can be wrong with confidence, so verify important facts."),
    (("prompt injection", "jailbreak", "ai security", "llm security"),
     "**Prompt injection** is the top LLM security risk (OWASP LLM01): instructions hidden in user input or retrieved content make the model ignore its rules or leak data.\n\n"
     "**Mitigations:** treat model output as untrusted, keep secrets out of prompts, limit tool permissions, and require human approval for sensitive actions."),
    (("deepfake", "deep fake", "voice clone"),
     "**Deepfakes** are AI-generated fake videos, images or voices. Criminals use cloned voices of executives or relatives to request urgent payments.\n\n"
     "**Defence:** agree on call-back verification and code words for payments; never act on urgency alone."),
    (("rag", "retrieval augmented generation", "vector database", "embeddings"),
     "**RAG (Retrieval-Augmented Generation)** lets an LLM answer from your own documents: text is split into chunks, converted to **embeddings**, stored in a **vector database**, and the most relevant chunks are added to the prompt at question time. It reduces hallucinations and keeps answers current."),
    # ── Business ─────────────────────────────────────────────────────────────
    (("startup", "start a business", "business plan", "entrepreneur"),
     "**Starting a business: a practical path**\n\n"
     "1. Validate a real problem with 20+ customer conversations.\n"
     "2. Build the smallest product that solves it (MVP).\n"
     "3. Find one repeatable acquisition channel.\n"
     "4. Track unit economics: **CAC**, **LTV**, gross margin, burn and runway.\n\n"
     "In India: register (LLP or Pvt Ltd), get GST registration if required, and check **Startup India** recognition for tax and compliance benefits."),
    (("gst", "goods and services tax"),
     "**GST** is India's indirect tax on goods and services (since July 2017). Registration is generally required above **₹40 lakh** turnover for goods (₹20 lakh for services; lower in special-category states). Main slabs have been simplified to **5% and 18%**, with a higher rate for select luxury and sin goods (2025 reform)."),
    (("marketing", "go to market", "gtm", "seo", "branding"),
     "**Go-to-market basics:** define the ideal customer profile, the core message (problem → outcome), and 1–2 channels you can win (SEO/content, partnerships, outbound, communities). Measure conversion at each funnel step and double down on what works."),
    (("cac", "ltv", "unit economics", "burn rate", "runway"),
     "**Unit economics:**\n\n"
     "- **CAC**: cost to acquire one customer.\n"
     "- **LTV**: gross profit a customer brings over their lifetime. Aim for **LTV:CAC ≥ 3:1**.\n"
     "- **Burn rate**: net cash spent per month; **runway** = cash ÷ burn (keep 12–18 months)."),
    (("cyber insurance", "risk quantification", "fair model", "annualized loss"),
     "**Cyber risk quantification** expresses security risk in money: *annualised loss expectancy = likelihood per year × impact per event*. The **FAIR** model is the most used method. BharatSec Risk turns scan findings into loss scenarios you can present to leadership and insurers."),
    # ── Technology & careers ─────────────────────────────────────────────────
    (("python", "javascript", "programming", "coding", "learn to code"),
     "**Learning to code:** start with **Python** (automation, data, security tooling) or **JavaScript** (web). Learn variables, control flow, functions and data structures, then build small real projects and use Git. For security work, add Linux, networking and HTTP fundamentals."),
    (("dns", "domain name system"),
     "**DNS** turns names like `example.com` into IP addresses. Key records: **A/AAAA** (addresses), **CNAME** (aliases), **MX** (mail), **TXT** (SPF/DMARC/verification), **NS** (delegation). Protect DNS with registrar lock, MFA on the registrar account and DNSSEC where possible."),
    (("blockchain", "crypto", "bitcoin", "web3"),
     "A **blockchain** is a shared, append-only ledger secured by cryptography and consensus. Bitcoin and Ethereum are the best known. Security risks include stolen private keys, phishing, smart-contract bugs and fake exchanges. In India, crypto gains are taxed at 30% plus 1% TDS on transfers."),
    (("cybersecurity career", "security career", "become ethical hacker", "career in cyber", "certification"),
     "**Breaking into cybersecurity:**\n\n"
     "1. Fundamentals: networking, Linux, Windows, Python.\n"
     "2. Entry certifications: **CompTIA Security+**, **ISC2 CC**, or **CEH** (popular in India).\n"
     "3. Hands-on practice: TryHackMe, Hack The Box, CTFs, home labs.\n"
     "4. Pick a track: SOC analyst, pentesting, cloud security, GRC.\n\n"
     "A GitHub portfolio and write-ups help a lot in interviews."),
]


def _phrase_hits(message: str, phrases: Tuple[str, ...]) -> int:
    hits = 0
    for phrase in phrases:
        if re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", message):
            hits += len(phrase.split())  # multi-word phrases are stronger signals
    return hits


def lookup(message: str) -> Optional[str]:
    """Return the best matching offline answer, or None."""
    text = (message or "").lower()
    best_score, best_answer = 0, None
    for phrases, answer in KNOWLEDGE:
        score = _phrase_hits(text, phrases)
        if score > best_score:
            best_score, best_answer = score, answer
    return best_answer
