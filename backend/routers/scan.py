"""
BharatSec: API Router: Scan
Scan lifecycle: create (start), execute (run), status, results.

Scans are persisted (engines/scan_store) and executed inside their own request, so the flow works
on serverless platforms: the client calls /start, then /{id}/run, and polls /{id}/status meanwhile.
"""
import uuid
import asyncio
import re
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

import auth as auth_service

from models.scan_models import ScanRequest, ScanResult, ScanStatus
from engines.osint_engine import get_dns_records, get_whois, enumerate_subdomains, get_web_info
from engines.security_engine import get_ssl_info
from engines.net_guard import BlockedDestinationError, resolve_public_address
from engines.risk_engine import generate_findings, calculate_score, generate_attack_paths, get_top_priorities
from engines.ai_engine import get_ai_analysis, generate_ai_summary
from engines import scan_store

logger = logging.getLogger("bharatsec.scan")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# httpx logs full request URLs at INFO; keep provider URLs out of the application log.
logging.getLogger("httpx").setLevel(logging.WARNING)

router = APIRouter(prefix="/api/scan", tags=["scan"])
# Free scans for signed-out visitors. Their IDs start with "pub_"; they are served only by these
# endpoints and never appear in signed-in users' scan lists.
public_router = APIRouter(prefix="/api/public/scan", tags=["public-scan"])
PUBLIC_PREFIX = scan_store.PUBLIC_PREFIX
PUBLIC_SCANS_PER_VISITOR = 3      # per hour
PUBLIC_SCANS_TOTAL = 60           # per hour, across everyone, to protect the service


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


# ── Scan execution ────────────────────────────────────────────────────────────

async def _checkpoint(scan: ScanResult) -> None:
    """Persist progress so status polls (possibly served by another instance) see it."""
    await asyncio.to_thread(scan_store.save, scan)


async def run_scan(scan_id: str, domain: str):
    scan = await asyncio.to_thread(scan_store.get, scan_id)
    if scan is None:
        return
    scan.status = ScanStatus.RUNNING
    await _checkpoint(scan)

    try:
        # Step 1: DNS Records
        try:
            logger.info(f"[{scan_id}] Step 1/5: DNS records for {domain}")
            scan.dns = await get_dns_records(domain)
            scan.progress = 10
            await _checkpoint(scan)
        except Exception as e:
            logger.warning(f"[{scan_id}] DNS step failed: {e}")

        # Step 2: WHOIS Lookup
        try:
            logger.info(f"[{scan_id}] Step 2/5: WHOIS for {domain}")
            scan.whois = await get_whois(domain)
            scan.progress = 20
            await _checkpoint(scan)
        except Exception as e:
            logger.warning(f"[{scan_id}] WHOIS step failed: {e}")

        # Step 3: Web Analysis
        try:
            logger.info(f"[{scan_id}] Step 3/5: Web analysis for {domain}")
            scan.web = await get_web_info(domain)
            scan.progress = 40
            await _checkpoint(scan)
        except Exception as e:
            logger.warning(f"[{scan_id}] Web analysis step failed: {e}")

        # Step 4: SSL Certificate
        try:
            logger.info(f"[{scan_id}] Step 4/5: SSL check for {domain}")
            loop = asyncio.get_running_loop()
            scan.ssl = await loop.run_in_executor(None, get_ssl_info, domain)
            scan.progress = 60
            await _checkpoint(scan)
        except Exception as e:
            logger.warning(f"[{scan_id}] SSL step failed: {e}")

        # Step 5: Subdomain Enumeration
        try:
            logger.info(f"[{scan_id}] Step 5/5: Subdomain enum for {domain}")
            scan.subdomains = await enumerate_subdomains(domain, scan.dns)
            scan.progress = 80
            await _checkpoint(scan)
        except Exception as e:
            logger.warning(f"[{scan_id}] Subdomain step failed: {e}")

        # Risk analysis
        scan.progress = 90
        await _checkpoint(scan)
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
        logger.info(f"[{scan_id}] Scan complete for {domain} | score: {scan.score.overall}/100")

    except Exception as e:
        scan.status = ScanStatus.ERROR
        scan.ai_summary = "The scan stopped because of an internal scan error. Check the backend log and retry."
        logger.exception("[%s] Scan failed for %s: %s", scan_id, domain, e)
    await _checkpoint(scan)


# ── Endpoints ─────────────────────────────────────────────────────────────────

def _load(scan_id: str) -> ScanResult:
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


async def _create_scan(request: ScanRequest, prefix: str) -> dict:
    if not request.authorized:
        raise HTTPException(400, "You must confirm authorization to scan this target.")

    domain = _validate_domain(request.domain)
    await _reject_non_public_target(domain)

    scan_id = f"{prefix}{uuid.uuid4().hex[:12]}"
    scan = ScanResult(
        scan_id=scan_id,
        domain=domain,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    await asyncio.to_thread(scan_store.save, scan)
    return {"scan_id": scan_id, "domain": domain, "status": "started"}


async def _run_once(scan_id: str) -> dict:
    scan = _load(scan_id)
    if await asyncio.to_thread(scan_store.claim_for_run, scan_id):
        await run_scan(scan_id, scan.domain)
        scan = _load(scan_id)
    return {"scan_id": scan_id, "status": scan.status, "progress": scan.progress}


def _status(scan: ScanResult) -> dict:
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "domain": scan.domain,
        "error": scan.ai_summary if scan.status == ScanStatus.ERROR else None,
    }


@router.post("/start")
async def start_scan(request: ScanRequest):
    """Create a scan. The client then calls /{scan_id}/run to execute it."""
    return await _create_scan(request, "scan_")


@router.post("/{scan_id}/run")
async def execute_scan(scan_id: str):
    """Run a created scan to completion inside this request (each scan runs at most once)."""
    return await _run_once(scan_id)


@router.get("/recent")
async def get_recent_scans():
    return await asyncio.to_thread(scan_store.recent_completed, 20)


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    return _status(_load(scan_id))


@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: str):
    scan = _load(scan_id)
    if scan.status in (ScanStatus.RUNNING, ScanStatus.PENDING):
        raise HTTPException(202, "Scan still in progress")
    return scan


@router.get("/{scan_id}/score")
async def get_scan_score(scan_id: str):
    return _load(scan_id).score


@router.get("/")
async def list_scans():
    return await asyncio.to_thread(scan_store.list_summaries)


# ── Free public scans ─────────────────────────────────────────────────────────

def _load_public(scan_id: str) -> ScanResult:
    if not scan_id.startswith(PUBLIC_PREFIX):
        raise HTTPException(404, "Scan not found")
    return _load(scan_id)


@public_router.post("/start")
async def start_public_scan(body: ScanRequest, request: Request):
    """One free scan without an account; limited per visitor and overall."""
    visitor = auth_service.client_ip(request)
    try:
        auth_service.check_rate_limit("public-scan", visitor, limit=PUBLIC_SCANS_PER_VISITOR, window_seconds=3600)
        auth_service.check_rate_limit("public-scan-total", "all", limit=PUBLIC_SCANS_TOTAL, window_seconds=3600)
    except HTTPException as exc:
        raise HTTPException(429, "You've used the free scans for this hour. Sign in to keep scanning.") from exc
    started = await _create_scan(body, PUBLIC_PREFIX)
    auth_service.record_rate_limited_attempt("public-scan", visitor, window_seconds=3600)
    auth_service.record_rate_limited_attempt("public-scan-total", "all", window_seconds=3600)
    return started


@public_router.post("/{scan_id}/run")
async def run_public_scan(scan_id: str):
    _load_public(scan_id)
    return await _run_once(scan_id)


@public_router.get("/{scan_id}/status")
async def public_scan_status(scan_id: str):
    return _status(_load_public(scan_id))


@public_router.get("/{scan_id}/report")
async def public_scan_report(scan_id: str):
    scan = _load_public(scan_id)
    if scan.status in (ScanStatus.RUNNING, ScanStatus.PENDING):
        raise HTTPException(202, "Scan still in progress")
    return scan
