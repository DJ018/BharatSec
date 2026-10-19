"""
BharatSec — API Router: Scan
Handles scan lifecycle: start, status, results
"""
import uuid
import asyncio
import re
import logging
from datetime import datetime, timezone
from typing import Dict

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from models.scan_models import ScanRequest, ScanResult, ScanStatus
from engines.osint_engine import get_dns_records, get_whois, enumerate_subdomains, get_web_info
from engines.security_engine import get_ssl_info
from engines.net_guard import BlockedDestinationError, resolve_public_address
from engines.risk_engine import generate_findings, calculate_score, generate_attack_paths, get_top_priorities
from engines.ai_engine import get_ai_analysis, generate_ai_summary

logger = logging.getLogger("bharatsec.scan")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# httpx logs full request URLs at INFO; keep provider URLs out of the application log.
logging.getLogger("httpx").setLevel(logging.WARNING)

router = APIRouter(prefix="/api/scan", tags=["scan"])

# In-memory scan store (use DB in production)
scans: Dict[str, ScanResult] = {}


# ── Domain validation ─────────────────────────────────────────────────────────

# Hostname regex: alphanumeric + hyphens, at least one dot, valid TLD
_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _validate_domain(domain: str) -> str:
    """Normalize and validate a domain string. Returns the clean domain or raises HTTPException."""
    if not domain or not domain.strip():
        raise HTTPException(422, "Domain is required.")

    d = domain.strip().lower()
    # Strip protocol
    d = re.sub(r'^https?://', '', d)
    # Strip www. prefix
    d = re.sub(r'^www\.', '', d)
    # Strip path, query, hash
    d = d.split('/')[0].split('?')[0].split('#')[0]

    if not _DOMAIN_RE.match(d):
        raise HTTPException(422, f"'{domain}' is not a valid domain. Provide a hostname like example.com.")

    # Reject IP addresses
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d):
        raise HTTPException(422, "IP addresses are not supported. Provide a domain name like example.com.")

    return d


async def _reject_non_public_target(domain: str) -> None:
    """Refuse targets that resolve to private or reserved addresses.

    Unresolvable domains are allowed so the scan can report DNS findings; every
    connection the engines make is still pinned to a public address by net_guard.
    """
    try:
        await asyncio.wait_for(asyncio.to_thread(resolve_public_address, domain, 443), timeout=5)
    except BlockedDestinationError as exc:
        raise HTTPException(422, "This domain resolves to a private or reserved address and cannot be scanned.") from exc
    except (OSError, asyncio.TimeoutError):
        pass


# ── Background scan task ──────────────────────────────────────────────────────

async def run_scan(scan_id: str, domain: str):
    scan = scans[scan_id]
    scan.status = ScanStatus.RUNNING

    try:
        # Step 1: DNS Records
        try:
            logger.info(f"[{scan_id}] Step 1/5: DNS records for {domain}")
            scan.dns = await get_dns_records(domain)
            scan.progress = 10
        except Exception as e:
            logger.warning(f"[{scan_id}] DNS step failed: {e}")

        # Step 2: WHOIS Lookup
        try:
            logger.info(f"[{scan_id}] Step 2/5: WHOIS for {domain}")
            scan.whois = await get_whois(domain)
            scan.progress = 20
        except Exception as e:
            logger.warning(f"[{scan_id}] WHOIS step failed: {e}")

        # Step 3: Web Analysis
        try:
            logger.info(f"[{scan_id}] Step 3/5: Web analysis for {domain}")
            scan.web = await get_web_info(domain)
            scan.progress = 40
        except Exception as e:
            logger.warning(f"[{scan_id}] Web analysis step failed: {e}")

        # Step 4: SSL Certificate
        try:
            logger.info(f"[{scan_id}] Step 4/5: SSL check for {domain}")
            loop = asyncio.get_running_loop()
            scan.ssl = await loop.run_in_executor(None, get_ssl_info, domain)
            scan.progress = 60
        except Exception as e:
            logger.warning(f"[{scan_id}] SSL step failed: {e}")

        # Step 5: Subdomain Enumeration
        try:
            logger.info(f"[{scan_id}] Step 5/5: Subdomain enum for {domain}")
            scan.subdomains = await enumerate_subdomains(domain, scan.dns)
            scan.progress = 80
        except Exception as e:
            logger.warning(f"[{scan_id}] Subdomain step failed: {e}")

        # Risk analysis
        scan.progress = 90
        logger.info(f"[{scan_id}] Running risk analysis...")
        scan.findings = generate_findings(scan)

        # AI analysis for each finding
        for f in scan.findings:
            # Finding IDs look like "ssl_invalid_e0e2395d" or "no_spf_8735df52"
            # Strip the last _hexchars UUID suffix to get the template key
            parts = f.id.rsplit("_", 1)
            key = parts[0] if len(parts) == 2 and len(parts[1]) == 8 else f.id

            # Map risk_engine finding prefixes → ai_engine template keys
            key_map = {
                "ssl_invalid": "no_https",
                "ssl_expiring": "ssl_expiring_soon",
                "ssl_soon": "ssl_expiring_soon",
                "tls_old": "tls_outdated",
                "no_redirect": "no_http_redirect",
                "no_spf": "no_spf",
                "no_dmarc": "no_dmarc",
                "no_dkim": "no_dkim",
                "sensitive_sub": "exposed_subdomain",
                "sub_exposure": "exposed_subdomain",
                "domain_expiring": "domain_expiring",
                "domain_expired": "domain_expiring",
                "domain_expiring_soon": "domain_expiring",
            }

            # Check for header findings
            if key.startswith("header_strict"):
                mapped_key = "missing_hsts"
            elif key.startswith("header_content_security"):
                mapped_key = "missing_csp"
            elif key.startswith("header_x_frame"):
                mapped_key = "missing_x_frame"
            elif key.startswith("header_x_content"):
                mapped_key = "missing_x_content_type"
            else:
                mapped_key = key_map.get(key, key)

            analysis = get_ai_analysis(mapped_key)
            if analysis and analysis != "This finding requires manual review by a security professional.":
                f.ai_analysis = analysis

        scan.score = calculate_score(scan)
        scan.top_priorities = get_top_priorities(scan.findings)
        scan.attack_paths = generate_attack_paths(scan)
        scan.ai_summary = generate_ai_summary(scan)

        scan.status = ScanStatus.COMPLETE
        scan.progress = 100
        scan.completed_at = datetime.now(timezone.utc).isoformat()
        logger.info(f"[{scan_id}] Scan complete for {domain} — score: {scan.score.overall}/100")

    except Exception as e:
        scan.status = ScanStatus.ERROR
        scan.ai_summary = "The scan stopped because of an internal scan error. Check the backend log and retry."
        logger.exception("[%s] Scan failed for %s: %s", scan_id, domain, e)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.authorized:
        raise HTTPException(400, "You must confirm authorization to scan this target.")

    domain = _validate_domain(request.domain)
    await _reject_non_public_target(domain)

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    scan = ScanResult(
        scan_id=scan_id,
        domain=domain,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    scans[scan_id] = scan
    background_tasks.add_task(run_scan, scan_id, domain)

    return {"scan_id": scan_id, "domain": domain, "status": "started"}


@router.get("/recent")
async def get_recent_scans():
    completed_scans = (scan for scan in scans.values() if scan.status == ScanStatus.COMPLETE)
    return sorted(completed_scans, key=lambda item: item.completed_at, reverse=True)[:20]


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "domain": scan.domain,
        "error": scan.ai_summary if scan.status == ScanStatus.ERROR else None,
    }


@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(202, "Scan still in progress")
    return scan


@router.get("/{scan_id}/score")
async def get_scan_score(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan.score


@router.get("/")
async def list_scans():
    return [
        {"scan_id": s.scan_id, "domain": s.domain, "status": s.status, "score": s.score.overall}
        for s in scans.values()
    ]