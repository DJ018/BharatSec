"""Cloud security posture scan API.

Like domain scans, a cloud scan is created by POST /scans and executed by POST /scans/{id}/run,
inside that request, so it works on serverless platforms where background work is not kept alive.
"""
import asyncio
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from engines import cloud_engine

router = APIRouter(prefix="/api/cloud", tags=["cloud"])


class CloudScanRequest(BaseModel):
    provider: Literal["aws", "azure", "gcp"]
    authorized: bool = False


@router.get("/providers")
async def providers():
    return cloud_engine.list_providers()


@router.get("/scans")
async def scans(limit: int = Query(50, ge=1, le=200)):
    return cloud_engine.list_scans(limit)


@router.post("/scans", status_code=202)
async def start_scan(request: CloudScanRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm that you own or are authorized to assess this cloud account.")
    return cloud_engine.create_scan(request.provider)


@router.post("/scans/{scan_id}/run")
async def run_scan(scan_id: str):
    """Execute a created scan once; provider SDKs block, so they run in a worker thread."""
    scan = cloud_engine.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Cloud scan not found.")
    if cloud_engine.claim_for_run(scan_id):
        await asyncio.to_thread(cloud_engine.run_scan, scan_id, scan["provider"])
    return cloud_engine.get_scan(scan_id)


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = cloud_engine.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Cloud scan not found.")
    return scan
