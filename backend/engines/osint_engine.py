"""
BharatSec: OSINT Engine
Performs authorized reconnaissance: DNS, WHOIS, subdomains, technology detection
"""
import asyncio
import logging
import re
import secrets
import time
import warnings
from typing import List, Optional, Tuple
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import httpx
import dns.asyncresolver
import dns.exception
import whois

from config import SUBDOMAIN_WORDLIST, SCAN_TIMEOUT, USER_AGENT
from engines.net_guard import PublicOnlyTransport

from models.scan_models import (
    DNSResults, WHOISInfo, SubdomainResult, WebInfo, HeadersResult
)

# Suppress InsecureRequestWarning for verify=False
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Common HTTP headers for all requests
HTTP_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# DKIM selectors used by common mail providers (Google, Microsoft 365, Mailchimp, generic).
DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2", "dkim", "mail", "smtp"]

logger = logging.getLogger("bharatsec.osint")

# Thread pool for blocking WHOIS calls (python-whois sets a 10s socket timeout per query)
_whois_executor = ThreadPoolExecutor(max_workers=8)


# ── DNS Analysis ──────────────────────────────────────────────────────────────

async def get_dns_records(domain: str) -> DNSResults:
    result = DNSResults()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4

    # Use public DNS servers as fallback for reliability
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1'] + resolver.nameservers

    record_types = {
        "A":     "a_records",
        "MX":    "mx_records",
        "TXT":   "txt_records",
        "NS":    "ns_records",
        "CNAME": "cname_records",
    }

    async def resolve_record(rtype: str, field: str):
        try:
            answers = await resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            return field, records
        except dns.exception.DNSException:
            return field, []

    # Query record types concurrently. The old synchronous resolver blocked the
    # event loop, preventing the browser from reading scan progress while DNS ran.
    records = await asyncio.gather(*(
        resolve_record(rtype, field) for rtype, field in record_types.items()
    ))
    for field, values in records:
        setattr(result, field, values)

    # Check email security records
    for txt in result.txt_records:
        txt_lower = txt.lower()
        if "v=spf1" in txt_lower:
            result.has_spf = True
        if "v=dmarc1" in txt_lower:
            result.has_dmarc = True

    # Check DMARC separately
    try:
        dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_answers:
            if "v=dmarc1" in str(r).lower():
                result.has_dmarc = True
    except Exception:
        pass

    # DKIM keys are published at <selector>._domainkey.<domain>; probe common selectors.
    async def has_dkim_key(selector: str) -> bool:
        try:
            answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
        except dns.exception.DNSException:
            return False
        return any("v=dkim1" in str(r).lower() or "p=" in str(r).lower() for r in answers)

    dkim_hits = await asyncio.gather(*(has_dkim_key(selector) for selector in DKIM_SELECTORS))
    result.has_dkim = any(dkim_hits)

    return result


# ── WHOIS Lookup ──────────────────────────────────────────────────────────────

def _blocking_whois(domain: str):
    """Run the blocking whois call with a timeout wrapper."""
    try:
        return whois.whois(domain)
    except Exception:
        return None


async def get_whois(domain: str) -> WHOISInfo:
    result = WHOISInfo()
    try:
        loop = asyncio.get_running_loop()
        # Run WHOIS in a thread with timeout to prevent hanging
        w = await asyncio.wait_for(
            loop.run_in_executor(_whois_executor, _blocking_whois, domain),
            timeout=20.0
        )

        if w is None:
            return result

        result.registrar = str(w.registrar or "").strip()
        name_servers = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        result.name_servers = [ns.lower() for ns in name_servers if ns]

        # Parse dates
        def parse_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d
            return None

        creation = parse_date(w.creation_date)
        expiration = parse_date(w.expiration_date)

        if creation:
            result.creation_date = creation.strftime("%Y-%m-%d")
        if expiration:
            result.expiration_date = expiration.strftime("%Y-%m-%d")
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            exp_naive = expiration.replace(tzinfo=None) if expiration.tzinfo else expiration
            result.days_until_expiry = (exp_naive - now).days

        # Check for WHOIS privacy
        privacy_indicators = ["privacy", "redacted", "protected", "proxy", "guard", "domains by proxy"]
        whois_text = (result.registrar + " " + str(getattr(w, 'org', '') or '')).lower()
        if any(p in whois_text for p in privacy_indicators):
            result.privacy_protected = True

    except asyncio.TimeoutError:
        logger.warning("WHOIS lookup timed out for %s", domain)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)

    return result


# ── Subdomain Enumeration ─────────────────────────────────────────────────────

async def _probe_http(client: httpx.AsyncClient, host: str) -> Optional[Tuple[int, int]]:
    """Return (status code, body length) for host over HTTPS, falling back to HTTP."""
    for scheme in ["https", "http"]:
        try:
            resp = await client.get(f"{scheme}://{host}", follow_redirects=True, timeout=5)
            return resp.status_code, len(resp.content)
        except Exception:
            continue
    return None


def _same_response(a: Optional[Tuple[int, int]], b: Optional[Tuple[int, int]]) -> bool:
    """Responses match when the status is equal and body sizes are within 5% (catch-all pages)."""
    if a is None or b is None:
        return a == b
    if a[0] != b[0]:
        return False
    return abs(a[1] - b[1]) <= max(32, 0.05 * max(a[1], b[1]))


async def _wildcard_baseline(
    client: httpx.AsyncClient, resolver: dns.asyncresolver.Resolver, domain: str,
) -> Tuple[bool, Optional[Tuple[int, int]]]:
    """Detect wildcard DNS by resolving random labels; return (is_wildcard, catch-all response)."""
    for _ in range(2):
        probe = f"bs-{secrets.token_hex(6)}.{domain}"
        try:
            await resolver.resolve(probe, "A", lifetime=3)
        except dns.exception.DNSException:
            return False, None
    return True, await _probe_http(client, f"bs-{secrets.token_hex(6)}.{domain}")


async def _check_subdomain(
    client: httpx.AsyncClient,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    sub: str,
    domain: str,
    wildcard_response: Optional[Tuple[int, int]] = None,
    wildcard: bool = False,
) -> Optional[SubdomainResult]:
    full = f"{sub}.{domain}"
    async with semaphore:
        try:
            answers = await resolver.resolve(full, "A", lifetime=3)
            ip = answers[0].address
        except (dns.exception.DNSException, IndexError):
            return None

        response = await _probe_http(client, full)
        # Under wildcard DNS every name resolves; only keep hosts that serve something different.
        if wildcard and _same_response(response, wildcard_response):
            return None
        result = SubdomainResult(subdomain=full, ip=ip, alive=response is not None)
        if response is not None:
            result.status_code = response[0]
        return result


async def enumerate_subdomains(domain: str, dns_result: Optional[DNSResults] = None) -> List[SubdomainResult]:
    """Brute-force common subdomains. If `dns_result` is given, its `wildcard_dns` flag is set when detected."""
    found = []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1'] + resolver.nameservers
    semaphore = asyncio.Semaphore(10)
    async with httpx.AsyncClient(transport=PublicOnlyTransport(verify=False), headers=HTTP_HEADERS, timeout=5) as client:
        wildcard, wildcard_response = await _wildcard_baseline(client, resolver, domain)
        if dns_result is not None:
            dns_result.wildcard_dns = wildcard
        tasks = [
            _check_subdomain(client, resolver, semaphore, sub, domain, wildcard_response, wildcard)
            for sub in SUBDOMAIN_WORDLIST
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if r and not isinstance(r, Exception):
            found.append(r)

    return found


# ── Technology Detection ──────────────────────────────────────────────────────

TECH_SIGNATURES = {
    "WordPress":    ["wp-content", "wp-includes", "WordPress"],
    "Drupal":       ["Drupal", "drupal.js", "sites/default"],
    "Joomla":       ["Joomla", "/components/com_"],
    "Shopify":      ["cdn.shopify.com", "Shopify.shop"],
    "Wix":          ["wix.com", "_wix_"],
    "React":        ["__react", "react-dom", "data-reactroot"],
    "Angular":      ["ng-version", "angular.js", "ng-app"],
    "Vue.js":       ["vue.js", "vuejs.org", "__vue__"],
    "jQuery":       ["jquery", "jQuery"],
    "Bootstrap":    ["bootstrap.css", "bootstrap.min.js"],
    "Laravel":      ["laravel_session", "X-Powered-By: PHP"],
    "Django":       ["csrfmiddlewaretoken", "django"],
    "Ruby on Rails":["X-Powered-By: Phusion Passenger", "_session_id"],
    "Next.js":      ["__NEXT_DATA__", "_next/static"],
    "Nginx":        ["nginx"],
    "Apache":       ["Apache"],
    "IIS":          ["Microsoft-IIS"],
    "Cloudflare":   ["cf-ray", "cloudflare"],
    "Google Analytics": ["google-analytics.com", "gtag/js"],
}


async def detect_technologies(url: str, response_text: str, headers: dict) -> List[str]:
    detected = []
    combined = response_text[:50000] + " " + str(headers)

    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined.lower():
                detected.append(tech)
                break

    # Check server header
    server = headers.get("server", "").lower()
    x_powered = headers.get("x-powered-by", "").lower()

    if "php" in x_powered and "PHP" not in detected:
        detected.append(f"PHP ({x_powered})")

    return list(set(detected))


# ── Full Web Info ─────────────────────────────────────────────────────────────

async def get_web_info(domain: str) -> WebInfo:
    info = WebInfo()

    async with httpx.AsyncClient(
        transport=PublicOnlyTransport(verify=False), follow_redirects=True, headers=HTTP_HEADERS
    ) as client:
        # Check the plain-HTTP endpoint independently; a successful HTTPS
        # request must not cause redirect analysis to be skipped.
        try:
            http_response = await client.get(
                f"http://{domain}", follow_redirects=False, timeout=8
            )
            location = http_response.headers.get("location", "")
            info.https_redirect = (
                http_response.status_code in (301, 302, 307, 308)
                and location.lower().startswith("https://")
            )
        except Exception:
            info.https_redirect = False

        for scheme in ["https", "http"]:
            try:
                start = time.monotonic()
                resp = await client.get(f"{scheme}://{domain}", timeout=SCAN_TIMEOUT)
                elapsed = (time.monotonic() - start) * 1000

                info.status_code = resp.status_code
                info.response_time_ms = round(elapsed, 1)

                headers_dict = dict(resp.headers)
                info.server = headers_dict.get("server", "")
                # Header analysis
                from config import SECURITY_HEADERS
                present = [h for h in SECURITY_HEADERS if h.lower() in {k.lower() for k in headers_dict}]
                missing = [h for h in SECURITY_HEADERS if h not in present]
                info.headers = HeadersResult(
                    present=present,
                    missing=missing,
                    all_headers={k: v for k, v in headers_dict.items()}
                )

                # Technology detection
                info.technologies = await detect_technologies(
                    f"{scheme}://{domain}",
                    resp.text,
                    headers_dict
                )

                break
            except Exception:
                continue

    return info
