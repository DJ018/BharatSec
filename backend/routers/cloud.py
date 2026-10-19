"""Cloud security posture scan API."""
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
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
async def start_scan(request: CloudScanRequest, background_tasks: BackgroundTasks):
    if not request.authorized:
        raise HTTPException(400, "Confirm that you own or are authorized to assess this cloud account.")
    scan = cloud_engine.create_scan(request.provider)
    background_tasks.add_task(cloud_engine.run_scan, scan["scan_id"], request.provider)
    return scan


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = cloud_engine.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Cloud scan not found.")
    return scan
