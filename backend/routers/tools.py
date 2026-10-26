"""
BharatSec: API Router: Free tools
Single-purpose public checks (SSL/TLS, email authentication, security headers) used by the free tool
pages. Same validation and private-address guards as full scans, and rate limited per visitor.
"""
import asyncio
import re
from typing import List, Optional

import dns.asyncresolver
import dns.exception
from fastapi import APIRouter, HTTPException, Request

import auth as auth_service
from engines.osint_engine import get_dns_records, get_web_info
from engines.security_engine import get_ssl_info
from routers.scan import _reject_non_public_target, _validate_domain

router = APIRouter(prefix="/api/public/tools", tags=["free-tools"])
CHECKS_PER_HOUR = 30  # per visitor, across all three tools

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS for future visits (max-age=31536000; includeSubDomains).",
    "Content-Security-Policy": "Limits where scripts and content can load from; the main defence against XSS.",
    "X-Frame-Options": "Stops other sites framing yours (clickjacking). DENY or SAMEORIGIN.",
    "X-Content-Type-Options": "Stops browsers guessing file types. Use nosniff.",
    "Referrer-Policy": "Controls how much of your URLs leak to other sites. strict-origin-when-cross-origin is a good default.",
    "Permissions-Policy": "Turns off browser features you don't use (camera, microphone, location).",
}


async def _prepare(domain: str, request: Request) -> str:
    clean = _validate_domain(domain)
    visitor = auth_service.client_ip(request)
    try:
        auth_service.check_rate_limit("public-tools", visitor, limit=CHECKS_PER_HOUR, window_seconds=3600)
    except HTTPException as exc:
        raise HTTPException(429, "You've reached the free check limit for this hour. Please try again later.") from exc
    auth_service.record_rate_limited_attempt("public-tools", visitor, window_seconds=3600)
    await _reject_non_public_target(clean)
    return clean


@router.get("/ssl")
async def check_ssl(domain: str, request: Request):
    clean = await _prepare(domain, request)
    info = await asyncio.get_running_loop().run_in_executor(None, get_ssl_info, clean)
    verdicts: List[str] = []
    if not info.valid:
        verdicts.append("No valid certificate could be read on port 443.")
    else:
        if info.days_remaining < 30:
            verdicts.append(f"Certificate expires in {info.days_remaining} days. Renew it now and turn on auto-renewal.")
        if not str(info.grade).startswith("A"):
            verdicts.append("The TLS setup can be improved. Allow only TLS 1.2 and 1.3.")
    verdicts.extend(info.vulnerabilities)
    return {"domain": clean, "ssl": info, "advice": verdicts}


async def _dmarc_record(domain: str) -> Optional[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout, resolver.lifetime = 2, 4
    try:
        answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
    except dns.exception.DNSException:
        return None
    for answer in answers:
        text = "".join(part.decode(errors="replace") for part in answer.strings)
        if text.lower().startswith("v=dmarc1"):
            return text
    return None


@router.get("/email")
async def check_email(domain: str, request: Request):
    clean = await _prepare(domain, request)
    records, dmarc = await asyncio.gather(get_dns_records(clean), _dmarc_record(clean))
    spf = next((txt.strip('"') for txt in records.txt_records if "v=spf1" in txt.lower()), None)
    policy = None
    if dmarc:
        match = re.search(r"\bp=(\w+)", dmarc, re.I)
        policy = match.group(1).lower() if match else None
    advice: List[str] = []
    if not spf:
        advice.append(f'Add an SPF record: a TXT record on {clean} such as "v=spf1 include:<your mail provider> ~all".')
    if not records.has_dkim:
        advice.append("Turn on DKIM signing in your mail provider and publish the key it gives you.")
    if not dmarc:
        advice.append(f'Add a DMARC record: a TXT record on _dmarc.{clean} such as "v=DMARC1; p=none; rua=mailto:dmarc@{clean}", then move to p=quarantine or p=reject.')
    elif policy == "none":
        advice.append("DMARC is in monitor-only mode (p=none). Once reports look clean, move to p=quarantine, then p=reject.")
    def mx_priority(record: str) -> int:
        first = record.split()[0] if record.split() else ""
        return int(first) if first.isdigit() else 999

    return {
        "domain": clean,
        "mx": [record.rstrip(".") for record in sorted(records.mx_records, key=mx_priority)],
        "spf": {"present": bool(spf), "record": spf},
        "dkim": {"present": records.has_dkim},
        "dmarc": {"present": bool(dmarc), "record": dmarc, "policy": policy},
        "advice": advice,
    }


@router.get("/headers")
async def check_headers(domain: str, request: Request):
    clean = await _prepare(domain, request)
    web = await get_web_info(clean)
    present = set(web.headers.present)
    headers = [
        {"name": name, "present": name in present, "why": why}
        for name, why in RECOMMENDED_HEADERS.items()
    ]
    return {
        "domain": clean,
        "status_code": web.status_code,
        "https_redirect": web.https_redirect,
        "server": web.server,
        "headers": headers,
        "missing": [h["name"] for h in headers if not h["present"]],
    }
