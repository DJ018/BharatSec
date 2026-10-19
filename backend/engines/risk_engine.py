"""
BharatSec — Risk Engine
Calculates BharatSec Risk Score and generates prioritized findings
"""
import uuid
from typing import List, Tuple
from models.scan_models import (
    ScanResult, Finding, RiskScore, SeverityLevel
)
from config import SECURITY_HEADERS, SEVERITY_SCORE_MAP, SCORE_WEIGHTS


# ── Severity helpers ──────────────────────────────────────────────────────────

def sev(level: str) -> SeverityLevel:
    return SeverityLevel(level)


def uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


SENSITIVE_SUBDOMAIN_LABELS = {"dev", "test", "staging", "admin", "old", "backup", "db", "database"}
DEV_SUBDOMAIN_LABELS = {"dev", "test", "staging"}


def subdomain_label(subdomain: str, domain: str) -> str:
    """Return the part of the host left of the scanned domain (``admin`` for admin.example.com)."""
    host = subdomain.lower().rstrip(".")
    suffix = "." + domain.lower()
    return host[: -len(suffix)] if host.endswith(suffix) else host.split(".", 1)[0]


# ── Generate Findings ─────────────────────────────────────────────────────────

def generate_findings(scan: ScanResult) -> List[Finding]:
    findings: List[Finding] = []

    # ── SSL findings ──────────────────────────────────────────────────────────
    if not scan.ssl.valid:
        findings.append(Finding(
            id=uid("ssl_invalid"),
            category="SSL/TLS",
            title="Invalid or Missing SSL Certificate",
            description="The SSL certificate is invalid, expired, or unreachable on port 443.",
            severity=sev("CRITICAL"),
            evidence="; ".join(scan.ssl.vulnerabilities) or "Certificate check failed",
            ai_analysis="",
            fix="Obtain and install a valid SSL certificate. Let's Encrypt provides free certificates via Certbot.",
            effort="Low", impact="Critical"
        ))
    elif scan.ssl.days_remaining <= 14:
        findings.append(Finding(
            id=uid("ssl_expiring"),
            category="SSL/TLS",
            title=f"SSL Certificate Expires in {scan.ssl.days_remaining} Days",
            description="The SSL certificate is about to expire. If it lapses, browsers will block all visitors.",
            severity=sev("CRITICAL"),
            evidence=f"Expires: {scan.ssl.expires} ({scan.ssl.days_remaining} days remaining)",
            ai_analysis="",
            fix="Renew the SSL certificate immediately. Enable auto-renewal to prevent future lapses.",
            effort="Low", impact="Critical"
        ))
    elif scan.ssl.days_remaining <= 30:
        findings.append(Finding(
            id=uid("ssl_soon"),
            category="SSL/TLS",
            title=f"SSL Certificate Expiring Soon ({scan.ssl.days_remaining} Days)",
            description="The SSL certificate will expire within 30 days.",
            severity=sev("HIGH"),
            evidence=f"Expires: {scan.ssl.expires}",
            ai_analysis="",
            fix="Schedule certificate renewal within the next week.",
            effort="Low", impact="High"
        ))

    # TLS version issues
    for vuln in scan.ssl.vulnerabilities:
        if "TLS 1.0" in vuln or "TLS 1.1" in vuln:
            findings.append(Finding(
                id=uid("tls_old"),
                category="SSL/TLS",
                title="Outdated TLS Protocol in Use",
                description=vuln,
                severity=sev("HIGH"),
                evidence=f"Protocol detected: {scan.ssl.protocol}",
                ai_analysis="",
                fix="Disable TLS 1.0 and 1.1. Configure server to support TLS 1.2 and TLS 1.3 only.",
                effort="Medium", impact="High"
            ))

    # ── HTTP Headers findings ─────────────────────────────────────────────────
    for header in scan.web.headers.missing:
        meta = SECURITY_HEADERS.get(header, {})
        severity_str = meta.get("severity", "MEDIUM")
        findings.append(Finding(
            id=uid(f"header_{header.lower().replace('-','_')}"),
            category="Security Headers",
            title=f"Missing Security Header: {header}",
            description=meta.get("description", f"The {header} header is not present."),
            severity=sev(severity_str),
            evidence=f"Header '{header}' absent from HTTP response",
            ai_analysis="",
            fix=meta.get("fix", f"Add the {header} header to your web server configuration."),
            effort="Low", impact=severity_str.title()
        ))

    # ── HTTPS redirect finding ────────────────────────────────────────────────
    if not scan.web.https_redirect and scan.ssl.valid:
        findings.append(Finding(
            id=uid("no_redirect"),
            category="Configuration",
            title="HTTP Not Redirected to HTTPS",
            description="Visiting the HTTP version of the site does not automatically redirect to HTTPS.",
            severity=sev("MEDIUM"),
            evidence=f"http://{scan.domain} did not respond with a redirect to https://",
            ai_analysis="",
            fix="Configure a 301 redirect from http:// to https:// in your web server (Nginx/Apache) or hosting platform.",
            effort="Low", impact="Medium"
        ))

    # ── DNS / Email security findings ─────────────────────────────────────────
    sends_mail = bool(scan.dns.mx_records)
    if not scan.dns.has_spf:
        findings.append(Finding(
            id=uid("no_spf"),
            category="Email Security",
            title="Missing SPF Record",
            description=(
                "No SPF record found. Attackers can send spoofed emails appearing to come from your domain."
                if sends_mail else
                "This domain has no mail servers, but without SPF attackers can still send email that claims to come from it."
            ),
            severity=sev("HIGH"),
            evidence=f"DNS TXT query for {scan.domain} returned no SPF record",
            ai_analysis="",
            fix=(
                "Add DNS TXT record: v=spf1 include:_spf.yourmailprovider.com ~all"
                if sends_mail else
                f"This domain does not send email: add TXT record on {scan.domain}: v=spf1 -all"
            ),
            effort="Low", impact="High"
        ))

    if not scan.dns.has_dmarc:
        findings.append(Finding(
            id=uid("no_dmarc"),
            category="Email Security",
            title="Missing DMARC Policy",
            description="No DMARC policy configured. Without DMARC, spoofed emails are likely to be delivered.",
            severity=sev("HIGH"),
            evidence=f"DNS query _dmarc.{scan.domain} returned no record",
            ai_analysis="",
            fix=(
                f"Add DNS TXT record for _dmarc.{scan.domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{scan.domain}"
                if sends_mail else
                f"This domain does not send email: add TXT record for _dmarc.{scan.domain}: v=DMARC1; p=reject;"
            ),
            effort="Low", impact="High"
        ))

    if scan.dns.wildcard_dns:
        findings.append(Finding(
            id=uid("wildcard_dns"),
            category="Attack Surface",
            title="Wildcard DNS Record in Use",
            description=(
                "Every subdomain of this domain resolves (a catch-all DNS record). BharatSec filtered subdomains that only "
                "return the catch-all response, but wildcards make look-alike hosts such as login.yourdomain resolve, "
                "which phishing campaigns can abuse."
            ),
            severity=sev("INFO"),
            evidence=f"Random names such as bs-<random>.{scan.domain} resolve",
            ai_analysis="",
            fix="Remove the wildcard (*) DNS record unless you need it, and create explicit records only for hosts you use.",
            effort="Low", impact="Low"
        ))

    if not scan.dns.has_dkim and scan.dns.mx_records:
        # DKIM keys live under provider-specific selectors that DNS cannot enumerate,
        # so a miss at the common selectors is a low-confidence signal.
        findings.append(Finding(
            id=uid("no_dkim"),
            category="Email Security",
            title="DKIM Not Detected at Common Selectors",
            description="No DKIM public key was found at common selectors. If your provider uses a custom selector, DKIM may still be configured.",
            severity=sev("LOW"),
            evidence="No v=DKIM1 record at common <selector>._domainkey names",
            ai_analysis="",
            fix="Confirm DKIM signing is enabled with your email provider and its public key is published as a DNS TXT record.",
            effort="Medium", impact="Medium"
        ))

    # ── WHOIS / Domain findings ───────────────────────────────────────────────
    if scan.whois.expiration_date and scan.whois.days_until_expiry <= 0:
        findings.append(Finding(
            id=uid("domain_expired"),
            category="Domain Security",
            title="Domain Registration Has Expired",
            description="The domain registration has lapsed. It can stop resolving and may be registered by someone else.",
            severity=sev("CRITICAL"),
            evidence=f"Expiration: {scan.whois.expiration_date}",
            ai_analysis="",
            fix="Renew the domain with your registrar immediately and enable auto-renewal.",
            effort="Low", impact="Critical"
        ))
    elif 0 < scan.whois.days_until_expiry <= 30:
        findings.append(Finding(
            id=uid("domain_expiring"),
            category="Domain Security",
            title=f"Domain Expires in {scan.whois.days_until_expiry} Days",
            description="The domain registration is expiring soon. If lapsed, attackers could register it.",
            severity=sev("CRITICAL"),
            evidence=f"Expiration: {scan.whois.expiration_date}",
            ai_analysis="",
            fix="Renew domain registration immediately. Enable auto-renewal.",
            effort="Low", impact="Critical"
        ))
    elif 30 < scan.whois.days_until_expiry <= 90:
        findings.append(Finding(
            id=uid("domain_expiring_soon"),
            category="Domain Security",
            title=f"Domain Expires in {scan.whois.days_until_expiry} Days",
            description="Domain registration will expire within 90 days.",
            severity=sev("MEDIUM"),
            evidence=f"Expiration: {scan.whois.expiration_date}",
            ai_analysis="",
            fix="Renew domain registration. Enable auto-renewal to prevent accidental lapse.",
            effort="Low", impact="Medium"
        ))

    # ── Subdomain findings ────────────────────────────────────────────────────
    alive_subs = [sd for sd in scan.subdomains if sd.alive]
    exposure_reported = False
    for sub in alive_subs:
        if subdomain_label(sub.subdomain, scan.domain) in SENSITIVE_SUBDOMAIN_LABELS:
            findings.append(Finding(
                id=uid("sensitive_sub"),
                category="Attack Surface",
                title=f"Sensitive Subdomain Exposed: {sub.subdomain}",
                description="A subdomain with a sensitive name is publicly accessible. These often host less-secure environments.",
                severity=sev("HIGH"),
                evidence=f"HTTP {sub.status_code} at {sub.subdomain} (IP: {sub.ip})",
                ai_analysis="",
                fix=f"Restrict access to {sub.subdomain} via IP allowlisting or VPN. Remove if not in use.",
                effort="Medium", impact="High"
            ))
        elif len(alive_subs) > 5 and not exposure_reported:
            # Only flag normal subs if there are many (large attack surface), and only once
            exposure_reported = True
            findings.append(Finding(
                id=uid("sub_exposure"),
                category="Attack Surface",
                title=f"{len(alive_subs)} Active Subdomains",
                description="Each active subdomain adds to the overall attack surface.",
                severity=sev("INFO"),
                evidence=", ".join(sd.subdomain for sd in alive_subs[:10]),
                ai_analysis="",
                fix="Audit all subdomains. Ensure each has proper security controls and is kept up to date.",
                effort="Low", impact="Low"
            ))

    # ── Sort findings by severity ─────────────────────────────────────────────
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f.severity.value, 5))

    return findings


# ── Calculate Risk Score ──────────────────────────────────────────────────────

def calculate_score(scan: ScanResult) -> RiskScore:
    score = RiskScore()

    findings = scan.findings
    score.critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    score.high_count     = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
    score.medium_count   = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
    score.low_count      = sum(1 for f in findings if f.severity in (SeverityLevel.LOW, SeverityLevel.INFO))

    def sub_score(cats: List[str]) -> int:
        """Average score for findings in given categories."""
        # INFO findings are context, not risk, so they never change a score.
        rel = [f for f in findings if f.category in cats and f.severity != SeverityLevel.INFO]
        if not rel:
            return 100
        worst = min(SEVERITY_SCORE_MAP.get(f.severity.value, 50) for f in rel)
        avg   = sum(SEVERITY_SCORE_MAP.get(f.severity.value, 50) for f in rel) / len(rel)
        return int((worst * 0.6) + (avg * 0.4))

    score.attack_surface    = sub_score(["Attack Surface"])
    score.web_security      = sub_score(["Security Headers", "SSL/TLS"])
    score.identity_exposure = sub_score(["Email Security", "Domain Security"])
    score.configuration     = sub_score(["Configuration"])
    score.credential_risk   = 75 if not scan.dns.has_spf else 90  # Simple heuristic

    # Penalize for missing HTTPS
    if not scan.ssl.valid:
        score.web_security = min(score.web_security, 20)

    # Overall weighted score
    score.overall = int(
        score.attack_surface    * SCORE_WEIGHTS["attack_surface"]    +
        score.web_security      * SCORE_WEIGHTS["web_security"]       +
        score.identity_exposure * SCORE_WEIGHTS["identity_exposure"]  +
        score.configuration     * SCORE_WEIGHTS["configuration"]       +
        score.credential_risk   * SCORE_WEIGHTS["credential_risk"]
    )

    score.level = (
        "CRITICAL" if score.overall < 35 else
        "HIGH"     if score.overall < 55 else
        "MEDIUM"   if score.overall < 70 else
        "LOW"      if score.overall < 85 else
        "SECURE"
    )

    return score


# ── Attack Path Generator ─────────────────────────────────────────────────────

def generate_attack_paths(scan: ScanResult) -> List[dict]:
    paths = []

    # Email spoofing path
    if not scan.dns.has_spf or not scan.dns.has_dmarc:
        paths.append({
            "name": "Email Spoofing → Phishing",
            "risk": "HIGH",
            "steps": [
                {"node": f"{scan.domain}", "type": "entry", "label": "Target Domain"},
                {"node": "Missing SPF/DMARC", "type": "weakness", "label": "No Email Auth"},
                {"node": "Spoofed Email", "type": "attack", "label": "Attacker sends email as you"},
                {"node": "Employee Clicks", "type": "impact", "label": "Credential theft / malware"},
                {"node": "Business Compromise", "type": "impact", "label": "Data breach / financial loss"},
            ]
        })

    # Web exposure path
    missing_headers = scan.web.headers.missing
    if len(missing_headers) >= 2:
        paths.append({
            "name": "Web Exposure → XSS Attack",
            "risk": "MEDIUM",
            "steps": [
                {"node": f"https://{scan.domain}", "type": "entry", "label": "Web Application"},
                {"node": "Missing CSP/HSTS", "type": "weakness", "label": "No security headers"},
                {"node": "Script Injection", "type": "attack", "label": "Attacker injects XSS payload"},
                {"node": "User Session Hijack", "type": "impact", "label": "Cookie/credential theft"},
                {"node": "Account Takeover", "type": "impact", "label": "Unauthorized access"},
            ]
        })

    # Subdomain takeover path
    alive_subs = [sd for sd in scan.subdomains if sd.alive]
    dev_subs = [sd for sd in alive_subs if subdomain_label(sd.subdomain, scan.domain) in DEV_SUBDOMAIN_LABELS]
    if dev_subs:
        sub = dev_subs[0].subdomain
        paths.append({
            "name": "Exposed Dev Environment",
            "risk": "HIGH",
            "steps": [
                {"node": sub, "type": "entry", "label": "Exposed Subdomain"},
                {"node": "Dev Environment", "type": "weakness", "label": "Less hardened than production"},
                {"node": "Auth Bypass", "type": "attack", "label": "Weak credentials / no auth"},
                {"node": "Code/DB Access", "type": "impact", "label": "Source code / database exposure"},
                {"node": "Pivot to Production", "type": "impact", "label": "Lateral movement"},
            ]
        })

    return paths


# ── Top Priority Findings ─────────────────────────────────────────────────────

def get_top_priorities(findings: List[Finding], n: int = 5) -> List[Finding]:
    """
    Return the top N findings to fix, ranked by:
    severity (most critical first) × effort (low effort first)
    """
    effort_weight = {"Low": 3, "Medium": 2, "High": 1}
    severity_weight = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

    def priority_key(f: Finding) -> float:
        return -(
            severity_weight.get(f.severity.value, 0) * 2 +
            effort_weight.get(f.effort, 1)
        )

    sorted_findings = sorted(findings, key=priority_key)
    # Exclude INFO findings from top priorities
    return [f for f in sorted_findings if f.severity != SeverityLevel.INFO][:n]
