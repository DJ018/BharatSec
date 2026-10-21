"""
BharatSec — API Router: AI
General assistant chat, scan-grounded Copilot (plain and streaming), finding analysis.
"""
import json
from typing import Any, AsyncIterator, Dict, List

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import auth as auth_service
from config import AI_RATE_LIMIT_PER_MINUTE
from engines.ai_engine import (
    ai_status,
    copilot_respond,
    copilot_stream,
    general_ai_respond,
    general_ai_stream,
    get_ai_analysis,
)
from models.scan_models import AIAnalyzeRequest, CopilotRequest, CopilotTurn
from engines import scan_store

router = APIRouter(prefix="/api/ai", tags=["ai"])


class GeneralChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    context: str = Field("", max_length=500)
    history: List[CopilotTurn] = Field(default_factory=list, max_length=12)


def _enforce_rate_limit(request: Request) -> None:
    """Per-user limit on AI calls so one account cannot exhaust the provider quota."""
    user = getattr(request.state, "user", None) or {}
    identifier = str(user.get("id") or (request.client.host if request.client else "unknown"))
    try:
        auth_service.check_rate_limit("ai", identifier, limit=AI_RATE_LIMIT_PER_MINUTE, window_seconds=60)
    except HTTPException as exc:
        raise HTTPException(429, "You're sending messages too quickly. Please wait a moment and try again.") from exc
    auth_service.record_rate_limited_attempt("ai", identifier, window_seconds=60)


def _sse(events: AsyncIterator[Dict[str, Any]]) -> StreamingResponse:
    async def body():
        async for event in events:
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def _scan_or_404(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found. Start a scan first.")
    return scan


@router.get("/status")
async def status():
    """Whether BharatSec AI is backed by a language model or running on offline knowledge."""
    return ai_status()


@router.post("/chat")
async def general_chat(request: GeneralChatRequest, http_request: Request):
    """General assistant: cybersecurity, AI, business, technology and general knowledge."""
    _enforce_rate_limit(http_request)
    response = await general_ai_respond(request.message, request.context, request.history)
    return {
        "role": "assistant",
        "content": response["content"],
        "source": response["source"],
        "model": response.get("model"),
    }


@router.post("/chat/stream")
async def general_chat_stream(request: GeneralChatRequest, http_request: Request):
    """Same as /chat, streamed as server-sent events: meta → delta… → done (or error)."""
    _enforce_rate_limit(http_request)
    return _sse(general_ai_stream(request.message, request.history))


@router.post("/copilot")
async def copilot_chat(request: CopilotRequest, http_request: Request):
    """Security Copilot: context-aware chat about a scan."""
    scan = _scan_or_404(request.scan_id)
    _enforce_rate_limit(http_request)
    response = await copilot_respond(request.message, scan, request.history)
    return {
        "role": "assistant",
        "content": response["content"],
        "source": response["source"],
        "model": response.get("model"),
        "scan_id": request.scan_id,
    }


@router.post("/copilot/stream")
async def copilot_chat_stream(request: CopilotRequest, http_request: Request):
    """Scan-grounded Copilot, streamed as server-sent events."""
    scan = _scan_or_404(request.scan_id)
    _enforce_rate_limit(http_request)
    return _sse(copilot_stream(request.message, scan, request.history))


@router.post("/analyze")
async def analyze_finding(request: AIAnalyzeRequest):
    """Get AI analysis for a specific finding type."""
    analysis = get_ai_analysis(
        request.finding_type,
        context=request.context
    )
    return {
        "finding_id": request.finding_id,
        "ai_analysis": analysis,
        "finding_type": request.finding_type,
    }


@router.get("/summary/{scan_id}")
async def get_summary(scan_id: str):
    """Get the AI-generated summary for a scan."""
    scan = _scan_or_404(scan_id)
    return {
        "scan_id": scan_id,
        "summary": scan.ai_summary,
        "top_priorities": [p.model_dump() for p in scan.top_priorities],
        "attack_paths": scan.attack_paths,
    }
