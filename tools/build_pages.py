"""Generate BharatSec's company and trust pages (About, Pricing, Contact, Security, Privacy, Terms).

Run from the repo root:  python tools/build_pages.py
Edit the page bodies below, then re-run; every page shares the same head, navigation and footer.
House style: no em dashes.
"""
from pathlib import Path

SITE = "https://bharatsec.vercel.app"
EMAIL = "deveshjain718@gmail.com"
UPDATED = "26 October 2026"
OUT = Path(__file__).resolve().parent.parent / "frontend"

NAV = """<header class="lp-nav" id="navbar">
  <div class="lp-container lp-nav-inner">
    <a class="ds-brand" href="/" aria-label="BharatSec home">
      <img src="assets/images/brand/bharatsec-mark.svg" alt="" width="34" height="34" />
      <span class="ds-brand-name">Bharat<span>Sec</span></span>
    </a>
    <nav class="lp-nav-links" id="lp-nav-links" aria-label="Primary">
      <a href="/#products">Products</a>
      <a href="/pricing">Pricing</a>
      <a href="/about">About</a>
      <a href="/security">Security</a>
    </nav>
    <div class="lp-nav-actions">
      <button class="ds-theme-toggle" type="button" data-theme-toggle aria-label="Switch theme">
        <svg class="ds-icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 14.2A8.5 8.5 0 1 1 9.8 3.5a7 7 0 0 0 10.7 10.7Z"/></svg>
        <svg class="ds-icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
      </button>
      <a href="/#scan" class="ds-btn ds-btn--primary">Scan for free</a>
      <button class="ds-btn ds-btn--ghost ds-btn--icon lp-menu-btn" type="button" id="lp-menu-btn" aria-label="Open menu" aria-expanded="false" aria-controls="lp-nav-links">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
      </button>
    </div>
  </div>
</header>"""

FOOTER = """<footer class="lp-footer">
  <div class="lp-container">
    <div class="lp-footer-grid">
      <div class="lp-footer-brand">
        <a class="ds-brand" href="/" aria-label="BharatSec home">
          <img src="assets/images/brand/bharatsec-mark.svg" alt="" width="34" height="34" />
          <span class="ds-brand-name">Bharat<span>Sec</span></span>
        </a>
        <p>AI-powered cyber risk intelligence.<br />Built for India, trusted worldwide.</p>
      </div>
      <div class="lp-footer-col">
        <h4>Products</h4>
        <ul>
          <li><a href="/#scan">Domain scanner</a></li>
          <li><a href="/soc">SOC</a></li>
          <li><a href="/threat-intel">Threat Intel</a></li>
          <li><a href="/cloud">Cloud</a></li>
          <li><a href="/risk">Risk</a></li>
        </ul>
      </div>
      <div class="lp-footer-col">
        <h4>Free tools</h4>
        <ul>
          <li><a href="/ssl-checker">SSL checker</a></li>
          <li><a href="/email-security-checker">SPF, DKIM, DMARC</a></li>
          <li><a href="/security-headers-checker">Security headers</a></li>
          <li><a href="/cert-in-6-hour-rule">CERT-In guide</a></li>
          <li><a href="/dpdp-act-guide">DPDP Act guide</a></li>
        </ul>
      </div>
      <div class="lp-footer-col">
        <h4>Company</h4>
        <ul>
          <li><a href="/about">About</a></li>
          <li><a href="/pricing">Pricing</a></li>
          <li><a href="/contact">Contact</a></li>
        </ul>
      </div>
      <div class="lp-footer-col">
        <h4>Trust</h4>
        <ul>
          <li><a href="/security">Security</a></li>
          <li><a href="/privacy">Privacy policy</a></li>
          <li><a href="/terms">Terms of service</a></li>
        </ul>
      </div>
    </div>
    <div class="lp-footer-bottom">
      <span>© <span data-current-year>2026</span> BharatSec · Built in India</span>
      <span>Passive reconnaissance only · Scan only authorized targets</span>
    </div>
  </div>
</footer>"""


def page(slug, title, description, eyebrow, heading, lead, body, *, meta_line="", robots="", css=(), js=()):
    url = f"{SITE}/{slug}"
    meta = f'\n      <p class="pg-meta">{meta_line}</p>' if meta_line else ""
    robots_tag = f'\n  <meta name="robots" content="{robots}" />' if robots else ""
    extra_css = "".join(f'\n  <link rel="stylesheet" href="assets/css/{name}" />' for name in css)
    extra_js = "".join(f'\n<script src="assets/js/{name}"></script>' for name in js)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <meta name="description" content="{description}" />{robots_tag}
  <link rel="canonical" href="{url}" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="BharatSec" />
  <meta property="og:url" content="{url}" />
  <meta property="og:title" content="{title}" />
  <meta property="og:description" content="{description}" />
  <meta property="og:image" content="{SITE}/assets/images/og/bharatsec-og.png" />
  <meta name="twitter:card" content="summary_large_image" />
  <link rel="icon" type="image/svg+xml" href="assets/images/brand/bharatsec-mark.svg" />
  <script src="assets/js/theme.js"></script>
  <link rel="stylesheet" href="assets/css/design-system.css" />
  <link rel="stylesheet" href="assets/css/landing.css" />
  <link rel="stylesheet" href="assets/css/pages.css" />{extra_css}
</head>
<body class="landing-page">
<a class="lp-skip" href="#main">Skip to content</a>
{NAV}
<main id="main">
  <section class="pg-hero">
    <div class="lp-container">
      <p class="pg-eyebrow">{eyebrow}</p>
      <h1>{heading}</h1>
      <p>{lead}</p>{meta}
    </div>
  </section>
  <section class="pg-body">
    <div class="lp-container">
{body}
    </div>
  </section>
</main>
{FOOTER}
<script src="assets/js/pages.js"></script>{extra_js}
</body>
</html>
"""


PAGES = {}

PAGES["about"] = page(
    "about",
    "About BharatSec | India-built cyber risk intelligence",
    "BharatSec helps Indian businesses see what attackers can see about them and fix what matters first. Built in Jaipur, India.",
    "About",
    "Security that Indian businesses can actually use.",
    "BharatSec shows a company what the internet can see about it, explains the risk in plain language and in rupees, and tells it what to fix first.",
    f"""      <div class="pg-prose">
        <h2>Why BharatSec exists</h2>
        <p>India's small and mid-sized businesses are moving online faster than ever, and the law now asks more of them: CERT-In expects incidents to be reported within 6 hours, and the DPDP Act puts real duties and penalties on anyone holding personal data. Most of these companies have no security team. Enterprise tools are priced and written for people who already know what a DMARC record or an exposed subdomain is.</p>
        <p>BharatSec is built for everyone else. Enter a domain and in about a minute you see your score, the few things that matter most, how an attacker could chain them together, and what doing nothing could cost.</p>

        <h2>What we build</h2>
        <ul>
          <li><strong>Domain scanner:</strong> passive checks of DNS, WHOIS, email authentication (SPF, DKIM, DMARC), SSL/TLS, security headers and subdomains, with a 0 to 100 score and a prioritised fix list.</li>
          <li><strong>SOC:</strong> website and asset monitoring, alerts and incident tracking.</li>
          <li><strong>Threat Intel:</strong> actively exploited vulnerabilities from the CISA KEV catalog, mapped to MITRE ATT&amp;CK.</li>
          <li><strong>Cloud:</strong> read-only security posture checks for AWS, Azure and Google Cloud.</li>
          <li><strong>Risk:</strong> findings turned into expected annual loss in rupees.</li>
          <li><strong>BharatSec AI:</strong> an assistant that answers security and Indian compliance questions with cited sources.</li>
        </ul>

        <h2>How we work</h2>
        <ul>
          <li><strong>Passive by default.</strong> Scans read only public information. We never attack, exploit or overload anyone's systems.</li>
          <li><strong>Privacy first.</strong> No advertising, no tracking cookies, no selling of data. See our <a href="/privacy">privacy policy</a>.</li>
          <li><strong>India first.</strong> CERT-In, the DPDP Act and rupee impact are built in, not bolted on.</li>
          <li><strong>Honest results.</strong> A score is a starting point, not a guarantee, and we say so.</li>
        </ul>

        <h2>Founder</h2>
        <div class="pg-founder">
          <img src="assets/images/brand/bharatsec-mark-512.png" alt="" width="96" height="96" />
          <div><b>Devesh Jain</b><span>Founder &amp; Developer, BharatSec · Co-Founder, POORNAYU · Co-Lead, AWS Builder Group · Jaipur, India</span><br />
          <a href="https://www.linkedin.com/in/deveshjain-18dj0404/" rel="noopener">LinkedIn</a> · <a href="https://github.com/DJ018/BharatSec" rel="noopener">GitHub</a></div>
        </div>

        <h2>Supported by</h2>
        <p>BharatSec is part of the <strong>MongoDB for Startups</strong> program, which powers the knowledge base behind BharatSec AI.</p>

        <h2>Talk to us</h2>
        <p>Questions, partnerships or feedback: <a href="mailto:{EMAIL}">{EMAIL}</a>, or see the <a href="/contact">contact page</a>.</p>
      </div>""",
)

PAGES["pricing"] = page(
    "pricing",
    "Pricing | BharatSec",
    "BharatSec is free during beta: domain scans, AI assistant, SOC monitoring, threat intel, cloud checks and risk in rupees. Paid plans for teams are coming.",
    "Pricing",
    "Free while we're in beta.",
    "Every feature that exists today is free. Paid plans for continuous monitoring and teams will come later, and early users will hear first.",
    f"""      <div class="pg-grid">
        <article class="pg-card is-featured">
          <span class="pg-badge">Available now</span>
          <h3>Beta</h3>
          <p class="pg-price">₹0 <small>during beta</small></p>
          <p>Everything BharatSec does today, for individuals and small teams.</p>
          <ul class="pg-list">
            <li>Passive domain scans with score and fix list</li>
            <li>BharatSec AI with cited answers</li>
            <li>SOC monitoring, alerts and incidents</li>
            <li>Threat intel and cloud posture checks</li>
            <li>Risk in rupees</li>
          </ul>
          <a class="ds-btn ds-btn--brand" href="/#scan">Start a free scan</a>
        </article>
        <article class="pg-card">
          <span class="pg-badge is-soon">Coming soon</span>
          <h3>Pro</h3>
          <p class="pg-price">Soon</p>
          <p>For businesses that want BharatSec watching all the time.</p>
          <ul class="pg-list">
            <li>Continuous monitoring and weekly change reports</li>
            <li>Email alerts for expiring certificates and new exposure</li>
            <li>Branded PDF reports</li>
            <li>CERT-In and DPDP compliance pack</li>
          </ul>
          <a class="ds-btn ds-btn--secondary" href="mailto:{EMAIL}?subject=BharatSec%20Pro%20waitlist">Join the waitlist</a>
        </article>
        <article class="pg-card">
          <span class="pg-badge is-soon">Coming soon</span>
          <h3>Partners</h3>
          <p class="pg-price">Talk to us</p>
          <p>For IT service providers, agencies and consultants managing many clients.</p>
          <ul class="pg-list">
            <li>Many client domains in one place</li>
            <li>Client-ready reports</li>
            <li>Team roles and audit trail</li>
          </ul>
          <a class="ds-btn ds-btn--secondary" href="mailto:{EMAIL}?subject=BharatSec%20partner%20enquiry">Contact us</a>
        </article>
      </div>
      <div class="pg-prose" style="margin-top: var(--ds-space-10)">
        <p class="pg-note">Prices for paid plans will be published before they apply. Nothing you use for free today will be switched to paid without notice.</p>
      </div>""",
)

PAGES["contact"] = page(
    "contact",
    "Contact | BharatSec",
    "Contact BharatSec for questions, partnerships, feedback or security reports.",
    "Contact",
    "We'd like to hear from you.",
    "BharatSec is built by a small team in Jaipur, India. Email is the fastest way to reach us.",
    f"""      <div class="pg-grid">
        <article class="pg-card">
          <h3>General and partnerships</h3>
          <p>Questions about BharatSec, partnerships, startup programs or press.</p>
          <a href="mailto:{EMAIL}">{EMAIL}</a>
        </article>
        <article class="pg-card">
          <h3>Security reports</h3>
          <p>Found a vulnerability in BharatSec? Please follow our responsible disclosure policy.</p>
          <a href="/security">Security and disclosure</a>
        </article>
        <article class="pg-card">
          <h3>Privacy requests</h3>
          <p>Access, correct or delete your data, or raise a grievance under the DPDP Act.</p>
          <a href="mailto:{EMAIL}?subject=Privacy%20request">Email the grievance officer</a>
        </article>
      </div>
      <div class="pg-prose" style="margin-top: var(--ds-space-10)">
        <h2>Elsewhere</h2>
        <ul>
          <li>LinkedIn: <a href="https://www.linkedin.com/in/deveshjain-18dj0404/" rel="noopener">Devesh Jain, founder</a></li>
          <li>GitHub: <a href="https://github.com/DJ018/BharatSec" rel="noopener">DJ018/BharatSec</a></li>
          <li>Location: Jaipur, Rajasthan, India</li>
        </ul>
        <p>We usually reply within two working days.</p>
      </div>""",
)

PAGES["security"] = page(
    "security",
    "Security and responsible disclosure | BharatSec",
    "How BharatSec protects your data, and how to report a security vulnerability responsibly.",
    "Security",
    "How we protect BharatSec, and how to report a problem.",
    "A security product has to hold itself to a higher standard. Here is what we do today, and how researchers can reach us.",
    f"""      <div class="pg-prose">
        <h2>How we protect the platform</h2>
        <ul>
          <li><strong>Encryption in transit:</strong> HTTPS everywhere with HSTS.</li>
          <li><strong>Passwords:</strong> never stored in plain text; salted PBKDF2-SHA256 hashes only.</li>
          <li><strong>Sessions:</strong> signed, HttpOnly, Secure and SameSite cookies, with rate limiting on sign-in.</li>
          <li><strong>Browser hardening:</strong> a strict Content Security Policy, frame blocking, and Permissions and Referrer policies.</li>
          <li><strong>Safe scanning:</strong> scans are passive and read public information only. Guards block scans of private and internal network addresses.</li>
          <li><strong>Least privilege:</strong> cloud checks use read-only audit permissions.</li>
          <li><strong>Testing:</strong> an automated test suite runs against every change.</li>
        </ul>

        <h2>Report a vulnerability</h2>
        <p>If you believe you have found a security issue in BharatSec, email <a href="mailto:{EMAIL}?subject=Security%20report">{EMAIL}</a> with the subject <strong>Security report</strong>. Please include:</p>
        <ul>
          <li>what you found and where (URL or endpoint);</li>
          <li>steps to reproduce, and the impact you believe it has;</li>
          <li>how we can reach you for follow-up.</li>
        </ul>

        <h3>Our promises</h3>
        <ul>
          <li>We will acknowledge your report within 3 working days and keep you updated.</li>
          <li>We will not take legal action against good-faith research that follows these rules.</li>
          <li>With your permission, we will credit you once the issue is fixed.</li>
        </ul>

        <h3>Please don't</h3>
        <ul>
          <li>run denial-of-service tests, spam, or automated scanning that degrades the service;</li>
          <li>access, change or delete data that isn't yours, beyond the minimum needed to show the issue;</li>
          <li>use social engineering or physical attacks;</li>
          <li>share the issue publicly before we have had a reasonable chance to fix it.</li>
        </ul>

        <p class="pg-note">Machine-readable contact details: <a href="/.well-known/security.txt">/.well-known/security.txt</a></p>
      </div>""",
)

PAGES["privacy"] = page(
    "privacy",
    "Privacy policy | BharatSec",
    "What data BharatSec collects, why, who processes it, how long we keep it, and your rights under India's DPDP Act.",
    "Privacy policy",
    "Your data, explained plainly.",
    "This notice explains what BharatSec collects, why, and the rights you have under India's Digital Personal Data Protection Act, 2023.",
    f"""      <div class="pg-prose">
        <h2>Who we are</h2>
        <p>BharatSec (<a href="{SITE}">{SITE.split('//')[1]}</a>) is operated by its founder, Devesh Jain, Jaipur, Rajasthan, India. For any privacy question or request, contact our grievance officer, Devesh Jain, at <a href="mailto:{EMAIL}?subject=Privacy%20request">{EMAIL}</a>.</p>

        <h2>What we collect</h2>
        <h3>When you create an account</h3>
        <ul>
          <li>Username, display name and, if you add one, your email address.</li>
          <li>Your password, stored only as a salted hash. We cannot read it.</li>
          <li>If you sign in with Google, GitHub, Microsoft or Facebook: your account ID, name and email from that provider.</li>
        </ul>
        <h3>When you use BharatSec</h3>
        <ul>
          <li>The domains you scan and the results, the assets you monitor, and the alerts and incidents you create.</li>
          <li>Messages you send to BharatSec AI. They are sent to our AI provider to produce an answer; we do not keep your conversations on our servers after the answer is delivered.</li>
          <li>A session cookie that keeps you signed in. We use no advertising or tracking cookies, and no analytics.</li>
          <li>Basic technical logs (such as IP address and browser type) kept by our hosting provider for security and abuse prevention. Rate limiting stores a one-way hash of your IP address, not the address itself.</li>
        </ul>
        <p>Your browser also stores your theme choice and a few display preferences locally. These never leave your device.</p>

        <h2>Why we use it</h2>
        <ul>
          <li>To provide the service you asked for: scans, monitoring, alerts, AI answers.</li>
          <li>To keep accounts secure and prevent abuse.</li>
          <li>To answer your messages and requests.</li>
        </ul>
        <p>We do not sell your data, use it for advertising, or use it to train AI models.</p>

        <h2>Who processes it for us</h2>
        <ul>
          <li><strong>Vercel</strong>: hosting the website and application.</li>
          <li><strong>Neon</strong>: the database holding accounts, scans and monitoring data.</li>
          <li><strong>Google (Gemini API)</strong>: generating AI answers to the messages you send.</li>
          <li><strong>MongoDB Atlas</strong> (Mumbai): BharatSec AI's reference knowledge base. It holds public reference material, not your personal data.</li>
          <li><strong>Google Fonts</strong> and <strong>jsDelivr</strong>: delivering fonts and a script library to your browser.</li>
          <li>The sign-in provider you choose, if you use social sign-in.</li>
        </ul>
        <p>Some of these providers process data outside India. We choose providers with strong security practices and share only what each service needs.</p>

        <h2>How long we keep it</h2>
        <ul>
          <li>Account data: while your account is active.</li>
          <li>Scan, monitoring and incident data: until you delete it or your account is deleted.</li>
          <li>When you ask us to delete your account, we remove your personal data within 30 days, unless the law requires us to keep something longer.</li>
        </ul>

        <h2>Your rights</h2>
        <p>Under the DPDP Act you can ask us to:</p>
        <ul>
          <li>tell you what personal data we hold about you and how we use it;</li>
          <li>correct, complete or update it;</li>
          <li>erase it, and withdraw any consent you have given;</li>
          <li>nominate someone to exercise your rights if you cannot;</li>
          <li>resolve a grievance. If you are not satisfied with our response, you may approach the Data Protection Board of India.</li>
        </ul>
        <p>Email <a href="mailto:{EMAIL}?subject=Privacy%20request">{EMAIL}</a> with the subject <strong>Privacy request</strong>. We aim to respond within 7 days.</p>

        <h2>Security</h2>
        <p>We protect data with HTTPS, hashed passwords, signed sessions, a strict content security policy and access controls. See our <a href="/security">security page</a> for details.</p>

        <h2>Children</h2>
        <p>BharatSec is meant for businesses and professionals, and is not intended for anyone under 18.</p>

        <h2>Changes</h2>
        <p>If we change this policy in a way that matters, we will update the date below and, for significant changes, tell signed-in users.</p>
        <p class="pg-meta">Last updated: {UPDATED}</p>
      </div>""",
    meta_line=f"Last updated {UPDATED}",
)

PAGES["terms"] = page(
    "terms",
    "Terms of service | BharatSec",
    "The terms for using BharatSec, including acceptable use: scan only domains you own or are authorised to assess.",
    "Terms of service",
    "The rules for using BharatSec.",
    "By using BharatSec you agree to these terms. They are written to be read, not skimmed.",
    f"""      <div class="pg-prose">
        <h2>1. About these terms</h2>
        <p>BharatSec is operated by Devesh Jain, Jaipur, India ("we", "us"). These terms apply to the website and application at {SITE.split('//')[1]}. If you use BharatSec for an organisation, you confirm you are allowed to accept these terms for it.</p>

        <h2>2. Beta service</h2>
        <p>BharatSec is in beta. Features may change, and the service is provided "as is" and "as available". We work to keep it accurate and online, but we do not promise it will be error-free or uninterrupted.</p>

        <h2>3. Your account</h2>
        <ul>
          <li>You must be at least 18.</li>
          <li>Keep your sign-in details safe; you are responsible for activity on your account.</li>
          <li>Tell us promptly if you think your account has been misused.</li>
        </ul>

        <h2>4. Acceptable use</h2>
        <p><strong>Only scan, monitor or assess domains, websites and cloud accounts that you own or are authorised to assess.</strong> BharatSec's checks are passive, but responsibility for what you choose to scan is yours.</p>
        <p>You must not:</p>
        <ul>
          <li>use BharatSec to break the law, including the Information Technology Act, 2000;</li>
          <li>attack, overload or try to gain unauthorised access to BharatSec or anyone else's systems;</li>
          <li>scrape the service in bulk, resell it, or work around rate limits or access controls;</li>
          <li>upload malicious code or content that infringes others' rights.</li>
        </ul>
        <p>We may suspend accounts that break these rules.</p>

        <h2>5. Results and advice</h2>
        <p>Scores, findings, risk estimates and AI answers are information to help you decide what to do. They are not a guarantee of security, and not legal, financial or compliance advice. Check important decisions with a qualified professional.</p>

        <h2>6. Ownership</h2>
        <p>BharatSec's software, design, text and brand belong to Devesh Jain. Your data stays yours; you give us permission to process it only to provide the service, as described in our <a href="/privacy">privacy policy</a>.</p>

        <h2>7. Fees</h2>
        <p>BharatSec is free during beta. If we introduce paid plans, we will publish prices first, and nothing you use for free will become paid without notice.</p>

        <h2>8. Liability</h2>
        <p>To the extent the law allows, we are not liable for indirect or consequential losses, or for losses caused by your use of results or by systems you did not authorise us to assess. Our total liability for any claim is limited to the amount you paid us in the 12 months before the claim (₹0 during the free beta).</p>

        <h2>9. Ending use</h2>
        <p>You can stop using BharatSec and ask us to delete your account at any time. We may end or suspend access for serious or repeated breaches of these terms.</p>

        <h2>10. Law and disputes</h2>
        <p>These terms are governed by the laws of India, and the courts at Jaipur, Rajasthan have jurisdiction.</p>

        <h2>11. Changes and contact</h2>
        <p>We may update these terms and will change the date below when we do. Questions: <a href="mailto:{EMAIL}">{EMAIL}</a>.</p>
        <p class="pg-meta">Last updated: {UPDATED}</p>
      </div>""",
    meta_line=f"Last updated {UPDATED}",
)

def tool_page(slug, tool, title, description, heading, lead, button, explainer, faq):
    related = "".join(
        f'<a href="/{s}">{name}</a>' for s, name in [
            ("ssl-checker", "SSL checker"), ("email-security-checker", "Email security checker"),
            ("security-headers-checker", "Security headers checker"), ("cert-in-6-hour-rule", "CERT-In 6-hour rule"),
            ("dpdp-act-guide", "DPDP Act guide")] if s != slug)
    faq_html = "".join(f"<h3>{q}</h3><p>{a}</p>" for q, a in faq)
    faq_json = ",".join(
        '{"@type":"Question","name":"' + q.replace('"', "'") + '","acceptedAnswer":{"@type":"Answer","text":"'
        + a.replace('"', "'").replace("<code>", "").replace("</code>", "") + '"}}' for q, a in faq)
    body = f"""      <form class="tl-form" id="tool-form" data-tool="{tool}" novalidate>
        <input class="ds-input" type="text" name="domain" placeholder="yourcompany.com" autocomplete="off" spellcheck="false" autocapitalize="off" inputmode="url" aria-label="Domain to check" required />
        <button class="ds-btn ds-btn--brand" type="submit">{button}</button>
        <small>Free and passive: we only read public information. Check only domains you own or are authorised to assess.</small>
      </form>
      <div class="tl-result" id="tool-result" aria-live="polite"></div>
      <div class="pg-prose" style="margin-top: var(--ds-space-12)">
{explainer}
        <h2>Frequently asked questions</h2>
        {faq_html}
      </div>
      <nav class="tl-related" aria-label="More free tools and guides">{related}</nav>
      <script type="application/ld+json">{{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{faq_json}]}}</script>"""
    return page(slug, title, description, "Free tool", heading, lead, body, css=("tools.css",), js=("tools.js",))


PAGES["ssl-checker"] = tool_page(
    "ssl-checker", "ssl",
    "Free SSL Checker: certificate expiry and TLS grade | BharatSec",
    "Check any website's SSL certificate: validity, issuer, days until expiry and TLS grade, with clear advice. Free, no sign-up.",
    "Free SSL certificate checker",
    "See whether a website's certificate is valid, when it expires and how strong its TLS setup is.",
    "Check SSL",
    """        <h2>What this checks</h2>
        <ul>
          <li><strong>Validity:</strong> whether browsers will trust the certificate.</li>
          <li><strong>Expiry:</strong> how many days are left. An expired certificate puts a full-page warning in front of every visitor.</li>
          <li><strong>TLS grade:</strong> whether old, weak protocol versions are still accepted.</li>
        </ul>
        <h2>How to fix common problems</h2>
        <ul>
          <li><strong>Expiring soon:</strong> renew now, and turn on automatic renewal (free with Let's Encrypt and most hosts).</li>
          <li><strong>Low grade:</strong> allow only TLS 1.2 and TLS 1.3 in your web server, load balancer or CDN settings.</li>
          <li><strong>Not valid:</strong> make sure the certificate covers the exact domain name and includes the full chain.</li>
        </ul>""",
    [("Is this check safe to run?", "Yes. It opens one normal HTTPS connection, the same as a browser visiting the site."),
     ("How often should I check my certificate?", "Monthly, or set up BharatSec monitoring so you are warned before it expires."),
     ("Why does TLS 1.0 or 1.1 matter?", "They are deprecated and have known weaknesses. Modern browsers and PCI DSS expect TLS 1.2 or newer.")],
)

PAGES["email-security-checker"] = tool_page(
    "email-security-checker", "email",
    "Free SPF, DKIM and DMARC Checker | BharatSec",
    "Check a domain's email security: SPF, DKIM and DMARC records, DMARC policy and mail servers, with the exact records to add. Free.",
    "Free SPF, DKIM and DMARC checker",
    "Find out whether attackers could send email pretending to be your domain, and how to stop it.",
    "Check email security",
    """        <h2>Why email authentication matters</h2>
        <p>Without SPF, DKIM and DMARC, anyone can send email that appears to come from your domain. That is how most invoice fraud and CEO impersonation scams start. Since 2024, Gmail and Yahoo also require these records from bulk senders, and mail without them is more likely to land in spam.</p>
        <ul>
          <li><strong>SPF</strong> lists the servers allowed to send mail for your domain.</li>
          <li><strong>DKIM</strong> signs your messages so receivers can verify they weren't changed.</li>
          <li><strong>DMARC</strong> tells receivers what to do when SPF and DKIM fail, and sends you reports.</li>
        </ul>
        <h2>A safe rollout</h2>
        <ol>
          <li>Publish SPF and turn on DKIM in your mail provider.</li>
          <li>Add DMARC with <code>p=none</code> and a reporting address, and watch the reports for a few weeks.</li>
          <li>Move to <code>p=quarantine</code>, then <code>p=reject</code> once legitimate mail passes.</li>
        </ol>""",
    [("Can DMARC break my email?", "Only if you jump straight to p=reject before every sender is covered by SPF or DKIM. Start with p=none and review reports first."),
     ("Why is DKIM shown as not found when I have it?", "DKIM keys live under a selector name chosen by your provider. We check common selectors; yours may use a custom one."),
     ("Do I need these if I only receive email?", "Yes. Attackers can still send email pretending to be you. A domain that sends no mail should publish v=spf1 -all and a DMARC p=reject record.")],
)

PAGES["security-headers-checker"] = tool_page(
    "security-headers-checker", "headers",
    "Free Security Headers Checker: HSTS, CSP and more | BharatSec",
    "Check a website for HSTS, Content-Security-Policy, X-Frame-Options and other security headers, plus HTTPS redirects. Free, no sign-up.",
    "Free security headers checker",
    "See which browser security headers a website sends, and which ones it is missing.",
    "Check headers",
    """        <h2>Why headers matter</h2>
        <p>Security headers are instructions your website sends to browsers. They switch on protections against attacks like cross-site scripting, clickjacking and HTTPS downgrades, and they cost nothing to add.</p>
        <h2>Where to add them</h2>
        <ul>
          <li><strong>Nginx or Apache:</strong> in the site configuration (<code>add_header</code> or <code>Header set</code>).</li>
          <li><strong>Vercel, Netlify, Cloudflare:</strong> in the project's headers settings or configuration file.</li>
          <li><strong>Frameworks:</strong> middleware such as Helmet for Node.js, or your framework's security settings.</li>
        </ul>
        <p>Start with HSTS, X-Content-Type-Options and Referrer-Policy (safe for almost every site), then add a Content-Security-Policy carefully, testing it in report-only mode first.</p>""",
    [("Will adding headers break my site?", "Most headers are safe. Content-Security-Policy can block scripts you rely on, so test it with Content-Security-Policy-Report-Only first."),
     ("Is X-Frame-Options still needed with CSP?", "CSP's frame-ancestors directive replaces it in modern browsers, but sending both is harmless and helps older ones."),
     ("Does this check send any attack traffic?", "No. It makes one ordinary request to the site, like a browser.")],
)

PAGES["cert-in-6-hour-rule"] = page(
    "cert-in-6-hour-rule",
    "CERT-In 6-hour reporting rule explained | BharatSec",
    "What the CERT-In Directions of April 2022 require: reporting cyber incidents within 6 hours, 180-day log retention, NTP sync and more, in plain language.",
    "Guide",
    "The CERT-In 6-hour rule, explained.",
    "What Indian organisations must do under CERT-In's April 2022 directions, and a simple plan to be ready.",
    """      <div class="pg-prose">
        <h2>What the rule says</h2>
        <p>On 28 April 2022, CERT-In (the Indian Computer Emergency Response Team) issued directions under Section 70B(6) of the Information Technology Act. They came into force in June 2022 and apply to service providers, intermediaries, data centres, companies and government bodies.</p>
        <p>The headline requirement: <strong>report listed cyber incidents to CERT-In within 6 hours</strong> of noticing them or being told about them.</p>

        <h2>Which incidents count</h2>
        <p>The directions list incident types including:</p>
        <ul>
          <li>data breaches and data leaks;</li>
          <li>ransomware and other malicious code;</li>
          <li>unauthorised access to IT systems, data or social media accounts;</li>
          <li>website defacement or malicious code inserted into a website;</li>
          <li>phishing, identity theft and spoofing;</li>
          <li>denial-of-service attacks;</li>
          <li>attacks on servers, cloud systems, IoT devices, payment systems and critical infrastructure;</li>
          <li>targeted scanning or probing of critical networks.</li>
        </ul>

        <h2>The other duties</h2>
        <ul>
          <li><strong>Logs:</strong> enable logs for all ICT systems and keep them for a rolling 180 days within India.</li>
          <li><strong>Clocks:</strong> synchronise system clocks with NIC or NPL time servers, so logs line up.</li>
          <li><strong>Point of contact:</strong> name a person to deal with CERT-In.</li>
          <li><strong>Providers:</strong> VPN, cloud, VPS and data centre providers must keep subscriber details for 5 years.</li>
        </ul>
        <p>Not complying can be punished under Section 70B(7) with imprisonment of up to one year, a fine of up to ₹1 lakh, or both.</p>

        <h2>How to report</h2>
        <p>Email <strong>incident@cert-in.org.in</strong> or use the incident reporting form on cert-in.org.in. The first report can be short: what happened, when you noticed, what is affected and who to contact. Send details as your investigation continues.</p>

        <h2>A one-page readiness plan</h2>
        <ol>
          <li>Name your CERT-In point of contact and a backup.</li>
          <li>Write down who decides that an incident is reportable, and who sends the report.</li>
          <li>Keep a short report template ready.</li>
          <li>Turn on logging for servers, cloud accounts and admin consoles, with 180-day retention.</li>
          <li>Point system clocks at NIC or NPL time servers.</li>
          <li>Practise once: run a 30-minute tabletop exercise.</li>
        </ol>
        <p class="pg-note">BharatSec's free <a href="/#scan">domain scan</a> and SOC monitoring help you notice problems quickly, and the Compliance checklist tracks these steps for your team. This guide is general information, not legal advice; read the <a href="https://www.cert-in.org.in/Directions70B.jsp" rel="noopener">official directions</a> for the full text.</p>
      </div>""",
)

PAGES["dpdp-act-guide"] = page(
    "dpdp-act-guide",
    "DPDP Act 2023 for small businesses: a practical guide | BharatSec",
    "What India's Digital Personal Data Protection Act and 2025 Rules mean for small businesses: consent, security, breach notification, penalties and a checklist.",
    "Guide",
    "The DPDP Act for small businesses.",
    "A plain-language guide to India's Digital Personal Data Protection Act, 2023 and its 2025 Rules, with a practical checklist.",
    """      <div class="pg-prose">
        <h2>Does it apply to you?</h2>
        <p>Almost certainly. The DPDP Act covers digital personal data of people in India: customer names, phone numbers, emails, addresses, employee records, even contact-form submissions. If your business stores any of this, you are a <strong>Data Fiduciary</strong> under the Act.</p>

        <h2>Your main duties</h2>
        <ul>
          <li><strong>Notice and consent:</strong> tell people clearly what you collect and why, and get their consent (or rely on a listed legitimate use). Let them withdraw consent as easily as they gave it.</li>
          <li><strong>Security:</strong> take reasonable security safeguards, such as encryption, access control, logging and backups.</li>
          <li><strong>Breach notification:</strong> tell affected people and the Data Protection Board of India without delay if personal data is breached.</li>
          <li><strong>Rights:</strong> let people access, correct and erase their data, and offer a way to raise grievances.</li>
          <li><strong>Retention:</strong> delete data once its purpose is served, unless the law requires keeping it.</li>
          <li><strong>Children:</strong> get verifiable parental consent for under-18s, and don't track them or target them with ads.</li>
          <li><strong>Vendors:</strong> you remain responsible for data your processors (hosting, CRM, payroll) handle for you.</li>
        </ul>

        <h2>Timelines under the 2025 Rules</h2>
        <p>The DPDP Rules were notified in November 2025 with a phased start. Most business obligations (notice, security safeguards, breach intimation, retention and erasure) apply about 18 months after notification. For a breach, the Rules expect a prompt notice to affected people and to the Board, followed by a detailed report to the Board within 72 hours. Check MeitY's latest notifications for exact dates.</p>

        <h2>Penalties</h2>
        <ul>
          <li>Up to <strong>₹250 crore</strong> for failing to take reasonable security safeguards.</li>
          <li>Up to <strong>₹200 crore</strong> for failing to notify a breach, or breaching duties towards children.</li>
          <li>Up to <strong>₹50 crore</strong> for other breaches of the Act or Rules.</li>
        </ul>

        <h2>A 10-step starter checklist</h2>
        <ol>
          <li>List what personal data you collect, where it is stored and who can access it.</li>
          <li>Publish a clear privacy notice.</li>
          <li>Record consent, and add an easy way to withdraw it.</li>
          <li>Name a contact for privacy requests and grievances.</li>
          <li>Turn on multi-factor sign-in for email, cloud and admin accounts.</li>
          <li>Encrypt data at rest and in transit, and restrict access to those who need it.</li>
          <li>Keep access logs and tested backups.</li>
          <li>Write a breach plan that covers both DPDP notices and CERT-In's 6-hour report.</li>
          <li>Set retention periods and delete old data.</li>
          <li>Check that your vendors have contracts covering security and deletion.</li>
        </ol>
        <p class="pg-note">BharatSec's Compliance checklist tracks these steps for your team, and a free <a href="/#scan">domain scan</a> shows the security gaps attackers see first. This guide is general information, not legal advice.</p>
      </div>""",
)

PAGES["report"] = page(
    "report",
    "Security report | BharatSec",
    "A BharatSec passive security report: score, email security, SSL/TLS, headers, subdomains and a prioritised fix list.",
    "Security report",
    "Your domain's security report.",
    "Passive checks only: we read public DNS, certificates, headers and subdomains. Nothing is attacked or changed.",
    """      <div class="rp-wrap" id="report-root"><div class="rp-state"><h2>Loading report…</h2><p>One moment.</p></div></div>""",
    robots="noindex, follow",
    css=("report.css",),
    js=("report.js",),
)


if __name__ == "__main__":
    for slug, html in PAGES.items():
        (OUT / f"{slug}.html").write_text(html, encoding="utf-8", newline="\n")
        print("wrote", f"{slug}.html")
