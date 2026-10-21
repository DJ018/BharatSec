"""SOC asset monitoring, alert triage, and incident response endpoints."""
import ipaddress
import logging
import re
import database
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from engines import soc_engine

logger = logging.getLogger("bharatsec.soc.api")
router = APIRouter(prefix="/api/soc", tags=["soc"])

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
AlertState = Literal["open", "acknowledged", "investigating", "resolved"]
IncidentStatus = Literal["open", "investigating", "contained", "resolved"]


class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    name: str = Field("", max_length=100)
    check_interval_seconds: int = Field(300, ge=60, le=86400)
    authorized: bool = False


class AssetUpdate(BaseModel):
    enabled: bool


class AlertUpdate(BaseModel):
    state: AlertState


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    severity: Severity = "MEDIUM"
    description: str = Field("", max_length=4000)
    asset_id: int | None = Field(None, gt=0)
    owner: str = Field("", max_length=100)
    author: str = Field("Analyst", min_length=1, max_length=100)
    alert_id: int | None = Field(None, gt=0)


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    owner: str | None = Field(None, max_length=100)
    author: str = Field("Analyst", min_length=1, max_length=100)


class IncidentNote(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    author: str = Field("Analyst", min_length=1, max_length=100)


def _normalize_domain(value: str) -> str:
    raw = value.strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(422, "Enter a valid domain without a port.") from exc
    if parsed.username or parsed.password or port or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise HTTPException(422, "Enter a domain only, without a port, path, or credentials.")

    host = parsed.hostname
    if not host:
        raise HTTPException(422, "Enter a valid public domain name.")
    try:
        domain = host.encode("idna").decode("ascii").lower().rstrip(".")
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    except UnicodeError as exc:
        raise HTTPException(422, "Enter a valid international or ASCII domain name.") from exc
    else:
        raise HTTPException(422, "IP addresses are not supported; add a public domain name.")

    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(domain) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", domain):
        raise HTTPException(422, "Enter a valid domain name such as example.com.")
    if domain.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise HTTPException(422, "Only public internet domains can be monitored.")
    return domain


def _author(http_request: Request) -> str:
    """Attribute SOC activity to the signed-in account, never to a client-supplied name."""
    user = getattr(http_request.state, "user", None) or {}
    return (user.get("name") or user.get("username") or "Analyst")[:100]


def _not_found(resource: str) -> HTTPException:
    return HTTPException(404, f"{resource} not found.")


@router.get("/overview")
async def overview():
    return soc_engine.get_overview()


@router.get("/assets")
async def assets():
    return soc_engine.list_assets()


@router.post("/assets", status_code=201)
async def add_asset(request: AssetCreate):
    if not request.authorized:
        raise HTTPException(400, "Confirm that you are authorized to monitor this domain.")
    domain = _normalize_domain(request.domain)
    try:
        return soc_engine.create_asset(domain, request.name.strip(), request.check_interval_seconds)
    except database.IntegrityError as exc:
        raise HTTPException(409, "This domain is already in the monitored asset list.") from exc


@router.patch("/assets/{asset_id}")
async def update_asset(asset_id: int, request: AssetUpdate):
    asset = soc_engine.update_asset(asset_id, enabled=request.enabled)
    if asset is None:
        raise _not_found("Asset")
    return asset


@router.delete("/assets/{asset_id}", status_code=204)
async def remove_asset(asset_id: int):
    if not soc_engine.delete_asset(asset_id):
        raise _not_found("Asset")


@router.post("/assets/{asset_id}/check")
async def check_asset(asset_id: int):
    if soc_engine.get_asset(asset_id) is None:
        raise _not_found("Asset")
    result = await soc_engine.check_asset(asset_id)
    logger.info("Manual SOC check completed for asset %s: %s", asset_id, result["status"])
    return result


@router.get("/alerts")
async def alerts(state: AlertState | None = Query(None)):
    return soc_engine.list_alerts(state)


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: int, request: AlertUpdate):
    try:
        alert = soc_engine.update_alert_state(alert_id, request.state)
    except soc_engine.AlertConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    if alert is None:
        raise _not_found("Alert")
    return alert


@router.post("/alerts/{alert_id}/incident", status_code=201)
async def incident_from_alert(alert_id: int, request: IncidentCreate, http_request: Request):
    alert = soc_engine.get_alert(alert_id)
    if alert is None:
        raise _not_found("Alert")
    incident = soc_engine.create_incident(
        request.title,
        request.severity,
        request.description or alert["detail"],
        alert["asset_id"],
        request.owner,
        _author(http_request),
        alert_id,
    )
    return incident


@router.get("/incidents")
async def incidents(status: IncidentStatus | None = Query(None)):
    return soc_engine.list_incidents(status)


@router.post("/incidents", status_code=201)
async def create_incident(request: IncidentCreate, http_request: Request):
    if request.asset_id is not None and soc_engine.get_asset(request.asset_id) is None:
        raise _not_found("Asset")
    if request.alert_id is not None and soc_engine.get_alert(request.alert_id) is None:
        raise _not_found("Alert")
    return soc_engine.create_incident(
        request.title,
        request.severity,
        request.description,
        request.asset_id,
        request.owner,
        _author(http_request),
        request.alert_id,
    )


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: int):
    incident = soc_engine.get_incident(incident_id)
    if incident is None:
        raise _not_found("Incident")
    incident["events"] = soc_engine.list_incident_events(incident_id)
    return incident


@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: int, request: IncidentUpdate, http_request: Request):
    fields = request.model_fields_set
    incident = soc_engine.update_incident(
        incident_id,
        status=request.status if "status" in fields else None,
        owner=request.owner if "owner" in fields else None,
        author=_author(http_request),
    )
    if incident is None:
        raise _not_found("Incident")
    return incident


@router.post("/incidents/{incident_id}/events", status_code=201)
async def add_incident_event(incident_id: int, request: IncidentNote, http_request: Request):
    incident = soc_engine.add_incident_note(incident_id, _author(http_request), request.message)
    if incident is None:
        raise _not_found("Incident")
    return incident