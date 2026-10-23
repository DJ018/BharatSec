"""Provider-agnostic language-model calls for BharatSec AI.

Supports Google Gemini and OpenAI chat models with:
- automatic failover: providers are tried in order until one answers;
- one retry per provider on rate limits, upstream errors and timeouts;
- fast switching: a model with a backup gets one short attempt, so an overloaded free-tier model
  does not keep the user waiting before the backup answers;
- streaming (server-sent events) for token-by-token answers.
API keys travel only in request headers, never in URLs, so they cannot leak into access logs.
"""
import asyncio
import json
import logging
from dataclasses import dataclass, replace
from typing import AsyncIterator, Dict, List, Sequence, Tuple

import httpx

logger = logging.getLogger("bharatsec.ai.llm")

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}
RETRY_DELAY_SECONDS = 0.8
# A model that has a backup gets one attempt and this long to start answering before the backup is tried.
SWITCH_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class Provider:
    name: str      # "gemini" | "openai"
    api_key: str
    model: str
    # Tried in order when `model` is retired (404) or stays overloaded after a retry (429/5xx).
    fallback_models: Tuple[str, ...] = ()


def _model_gone(exc: Exception) -> bool:
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404


def _candidates(provider: Provider) -> List[Provider]:
    return [provider] + [replace(provider, model=model, fallback_models=()) for model in provider.fallback_models]


def _attempt_plan(candidates: List[Provider], index: int, timeout: float) -> Tuple[Tuple[int, ...], httpx.Timeout]:
    """(attempts, timeout) for one candidate: short and single when a backup model follows, full otherwise."""
    if index < len(candidates) - 1:
        return (1,), _timeout(min(timeout, SWITCH_TIMEOUT_SECONDS))
    return (1, 2), _timeout(timeout)


def _try_next_model(exc: Exception | None) -> bool:
    """A retired or overloaded model is worth swapping; a rejected key or bad request is not."""
    return exc is not None and (_model_gone(exc) or _retryable(exc))


class ProviderError(Exception):
    """No configured provider produced an answer."""


Message = Dict[str, str]  # {"role": "user" | "assistant", "content": str}


# ── Request builders ─────────────────────────────────────────────────────────

def _gemini_payload(system: str, messages: Sequence[Message], temperature: float, max_tokens: int, model: str) -> dict:
    generation = {"temperature": temperature, "maxOutputTokens": max_tokens}
    if "2.5-flash" in model:
        # Gemini 2.5 Flash "thinking" tokens count against maxOutputTokens; chat answers do not need them.
        # (2.5 Pro cannot disable thinking, so it keeps its default budget.)
        generation["thinkingConfig"] = {"thinkingBudget": 0}
    elif model.startswith("gemini-3"):
        # Gemini 3 models think by default; a low level keeps chat answers fast and within the token budget.
        generation["thinkingConfig"] = {"thinkingLevel": "low"}
    return {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [
            {"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]}
            for m in messages
        ],
        "generationConfig": generation,
    }


def _openai_payload(system: str, messages: Sequence[Message], temperature: float, max_tokens: int, model: str, stream: bool) -> dict:
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, *messages],
        "max_completion_tokens": max_tokens,
    }
    if not model.startswith(("o1", "o3", "o4", "gpt-5")):
        payload["temperature"] = temperature  # reasoning models only accept the default
    if stream:
        payload["stream"] = True
    return payload


def _gemini_text(data: dict) -> str:
    parts = data["candidates"][0]["content"]["parts"]
    return "".join(part.get("text", "") for part in parts)


def _timeout(seconds: float) -> httpx.Timeout:
    return httpx.Timeout(seconds, connect=10.0)


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRYABLE_STATUS
    return isinstance(exc, (httpx.TimeoutException, httpx.TransportError))


# ── Single-shot completion ───────────────────────────────────────────────────

async def _complete_once(client: httpx.AsyncClient, provider: Provider, system: str, messages: Sequence[Message],
                         temperature: float, max_tokens: int, timeout: httpx.Timeout) -> str:
    if provider.name == "gemini":
        response = await client.post(
            f"{GEMINI_BASE}/{provider.model}:generateContent",
            headers={"x-goog-api-key": provider.api_key},
            json=_gemini_payload(system, messages, temperature, max_tokens, provider.model),
            timeout=timeout,
        )
        response.raise_for_status()
        return _gemini_text(response.json()).strip()
    response = await client.post(
        OPENAI_URL,
        headers={"Authorization": f"Bearer {provider.api_key}"},
        json=_openai_payload(system, messages, temperature, max_tokens, provider.model, stream=False),
        timeout=timeout,
    )
    response.raise_for_status()
    return (response.json()["choices"][0]["message"]["content"] or "").strip()


def _describe(exc: Exception) -> str:
    """Error summary safe for logs: the HTTP status and the provider's short message, never request headers."""
    if isinstance(exc, httpx.HTTPStatusError):
        detail = ""
        try:
            body = exc.response.json()
            error = body[0].get("error") if isinstance(body, list) and body else body.get("error")
            detail = (error.get("message") if isinstance(error, dict) else str(error or ""))[:200]
        except (ValueError, AttributeError, TypeError, IndexError):
            pass
        return f"HTTP {exc.response.status_code}{': ' + detail if detail else ''}"
    return type(exc).__name__


async def complete(providers: Sequence[Provider], system: str, messages: Sequence[Message], *,
                   temperature: float, max_tokens: int, timeout: float) -> Tuple[str, Provider]:
    """Return (answer, provider) from the first provider that answers."""
    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=_timeout(timeout)) as client:
        for configured in providers:
            candidates = _candidates(configured)
            for index, provider in enumerate(candidates):
                attempts, request_timeout = _attempt_plan(candidates, index, timeout)
                for attempt in attempts:
                    try:
                        answer = await _complete_once(client, provider, system, messages, temperature, max_tokens,
                                                      request_timeout)
                        if answer:
                            return answer, provider
                        last_error = ValueError("empty answer")
                        break
                    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                        last_error = exc
                        logger.warning("%s %s request failed (attempt %s): %s",
                                       provider.name, provider.model, attempt, _describe(exc))
                        if attempt < attempts[-1] and _retryable(exc):
                            await asyncio.sleep(RETRY_DELAY_SECONDS)
                            continue
                        break
                if not _try_next_model(last_error):
                    break
    raise ProviderError(f"No AI provider answered ({type(last_error).__name__ if last_error else 'none configured'}).")


# ── Streaming ────────────────────────────────────────────────────────────────

async def _sse_data(response: httpx.Response) -> AsyncIterator[str]:
    async for line in response.aiter_lines():
        if line.startswith("data:"):
            yield line[5:].strip()


async def _stream_once(client: httpx.AsyncClient, provider: Provider, system: str, messages: Sequence[Message],
                       temperature: float, max_tokens: int, timeout: httpx.Timeout) -> AsyncIterator[str]:
    if provider.name == "gemini":
        request = client.stream(
            "POST",
            f"{GEMINI_BASE}/{provider.model}:streamGenerateContent",
            params={"alt": "sse"},
            headers={"x-goog-api-key": provider.api_key},
            json=_gemini_payload(system, messages, temperature, max_tokens, provider.model),
            timeout=timeout,
        )
    else:
        request = client.stream(
            "POST",
            OPENAI_URL,
            headers={"Authorization": f"Bearer {provider.api_key}"},
            json=_openai_payload(system, messages, temperature, max_tokens, provider.model, stream=True),
            timeout=timeout,
        )
    async with request as response:
        if response.status_code >= 400:
            await response.aread()
            response.raise_for_status()
        async for data in _sse_data(response):
            if not data or data == "[DONE]":
                continue
            event = json.loads(data)
            if provider.name == "gemini":
                candidates = event.get("candidates") or []
                text = "".join(p.get("text", "") for p in (candidates[0].get("content", {}).get("parts", []) if candidates else []))
            else:
                choices = event.get("choices") or []
                text = (choices[0].get("delta", {}).get("content") or "") if choices else ""
            if text:
                yield text


async def stream(providers: Sequence[Provider], system: str, messages: Sequence[Message], *,
                 temperature: float, max_tokens: int, timeout: float) -> AsyncIterator[Tuple[str, object]]:
    """Yield ("provider", Provider) once, then ("delta", text) chunks.

    Fails over to the next provider only while nothing has been sent yet; an interruption after
    the first chunk raises ProviderError so the caller can tell the user the answer was cut short.
    """
    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=_timeout(timeout)) as client:
        for configured in providers:
            candidates = _candidates(configured)
            for index, provider in enumerate(candidates):
                attempts, request_timeout = _attempt_plan(candidates, index, timeout)
                for attempt in attempts:
                    started = False
                    try:
                        async for chunk in _stream_once(client, provider, system, messages, temperature, max_tokens,
                                                        request_timeout):
                            if not started:
                                started = True
                                yield "provider", provider
                            yield "delta", chunk
                        if started:
                            return
                        last_error = ValueError("empty answer")
                        break
                    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                        if started:
                            raise ProviderError("The answer was interrupted by the AI provider.") from exc
                        last_error = exc
                        logger.warning("%s %s stream failed (attempt %s): %s",
                                       provider.name, provider.model, attempt, _describe(exc))
                        if attempt < attempts[-1] and _retryable(exc):
                            await asyncio.sleep(RETRY_DELAY_SECONDS)
                            continue
                        break
                if not _try_next_model(last_error):
                    break
    raise ProviderError(f"No AI provider answered ({type(last_error).__name__ if last_error else 'none configured'}).")


def normalize_history(history: Sequence[object] | None, limit: int = 12) -> List[Message]:
    """Keep the last `limit` well-formed user/assistant turns, in order."""
    turns: List[Message] = []
    for turn in list(history or [])[-limit:]:
        role = turn.get("role") if isinstance(turn, dict) else getattr(turn, "role", None)
        content = turn.get("content") if isinstance(turn, dict) else getattr(turn, "content", None)
        if role in ("user", "assistant") and isinstance(content, str) and content.strip():
            turns.append({"role": role, "content": content.strip()})
    # Gemini requires the conversation to start with a user turn.
    while turns and turns[0]["role"] != "user":
        turns.pop(0)
    return turns
