"""Threat-intelligence feeds, IOC workflow, environment matches, and breach watches."""
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from engines import threat_intel_engine as intel
from routers.soc import _normalize_domain

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])

IndicatorType = Literal["auto", "domain", "url", "ip", "cve", "md5", "sha1", "sha256"]
IndicatorStatus = Literal["new", "investigating", "confirmed", "ignored"]


class IndicatorCreate(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2048)
    ioc_type: IndicatorType = "auto"
    title: str = Field("", max_length=300)
    threat_type: str = Field("", max_length=120)
    confidence: int = Field(50, ge=0, le=100)
    tags: list[str] = Field(default_factory=list, max_length=30)


class IndicatorUpdate(BaseModel):
    status: IndicatorStatus


class BreachWatchCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    authorized: bool = False


@router.get("/overview")
async def overview():
    return intel.get_overview()


@router.get("/feeds")
async def feeds():
    return intel.feed_status()


@router.post("/feeds/sync")
async def sync_feeds():
    return await intel.sync_feeds()


@router.get("/indicators")
async def indicators(
    query: str = Query("", max_length=200),
    source: str = Query("", max_length=200),
    status: IndicatorStatus | None = Query(None),
    limit: int = Query(250, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    return intel.list_indicators(query, source, status or "", limit, offset)


@router.post("/indicators", status_code=201)
async def add_indicator(request: IndicatorCreate):
    try:
        indicator_id = intel.upsert_indicator(
            request.ioc,
            request.ioc_type,
            "Analyst",
            request.title,
            request.threat_type,
            request.confidence,
            request.tags,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return intel.get_indicator(indicator_id)


@router.patch("/indicators/{indicator_id}")
async def update_indicator(indicator_id: int, request: IndicatorUpdate):
    indicator = intel.set_indicator_status(indicator_id, request.status)
    if indicator is None:
        raise HTTPException(404, "Indicator not found.")
    return indicator


@router.post("/indicators/{indicator_id}/enrich")
async def enrich_indicator(indicator_id: int):
    indicator = await intel.enrich_indicator(indicator_id)
    if indicator is None:
        raise HTTPException(404, "Indicator not found.")
    return indicator


@router.get("/correlations")
async def correlations():
    return intel.list_correlations()


@router.get("/techniques")
async def techniques():
    from engines.threat_intel_engine import ATTACK_TECHNIQUES
    return [{"id": technique_id, **technique} for technique_id, technique in ATTACK_TECHNIQUES.items()]


@router.get("/breach-watches")
async def breach_watches():
    return {
        "configured": bool(intel.HIBP_API_KEY),
        "provider": "Have I Been Pwned verified-domain search",
        "scope": "Historical breach corpus; this is not live dark-web access.",
        "watches": intel.list_breach_watches(),
    }


@router.post("/breach-watches", status_code=201)
async def add_breach_watch(request: BreachWatchCreate):
    if not request.authorized:
        raise HTTPException(400, "Confirm that you own or are authorized to monitor this domain.")
    if not intel.HIBP_API_KEY:
        raise HTTPException(503, "Breach exposure checks require a server-side HIBP_API_KEY.")
    try:
        domain = _normalize_domain(request.domain)
    except HTTPException:
        raise
    watch = intel.add_breach_watch(domain)
    return watch


@router.delete("/breach-watches/{watch_id}", status_code=204)
async def remove_breach_watch(watch_id: int):
    if not intel.delete_breach_watch(watch_id):
        raise HTTPException(404, "Breach watch not found.")


@router.get("/breach-exposures")
async def breach_exposures():
    return intel.list_breach_exposures()


@router.post("/breach-watches/{watch_id}/check")
async def check_breach_watch(watch_id: int):
    watch = next((item for item in intel.list_breach_watches() if item["id"] == watch_id), None)
    if watch is None:
        raise HTTPException(404, "Breach watch not found.")
    try:
        return await intel.check_breach_domain(watch["domain"])
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, "Breach provider request failed; check the server log and provider configuration.") from exc