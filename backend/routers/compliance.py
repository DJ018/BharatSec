"""
BharatSec: API Router: Compliance
Team-wide CERT-In and DPDP checklist.
"""
import asyncio
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from engines import compliance_engine

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class ItemUpdate(BaseModel):
    done: bool
    note: Optional[str] = Field(None, max_length=500)


@router.get("")
async def get_checklist():
    return await asyncio.to_thread(compliance_engine.checklist)


@router.put("/{item_id}")
async def update_item(item_id: str, body: ItemUpdate, request: Request):
    user = getattr(request.state, "user", None) or {}
    name = str(user.get("name") or user.get("username") or "")
    try:
        return await asyncio.to_thread(compliance_engine.update, item_id, body.done, body.note, name)
    except KeyError as exc:
        raise HTTPException(404, "Unknown checklist item.") from exc
