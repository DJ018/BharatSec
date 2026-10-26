"""
BharatSec: API Router: Public status
Live health of each part of the platform and the daily scan of BharatSec's own website.
"""
import asyncio

from fastapi import APIRouter

from engines import status_monitor

router = APIRouter(prefix="/api/public/status", tags=["status"])


@router.get("")
async def public_status():
    return await asyncio.to_thread(status_monitor.snapshot)
