"""BharatSec AI knowledge base on MongoDB Atlas Vector Search.

Reference notes (Indian cyber law, fix guides, recent CISA KEV entries, the offline answers) are embedded
and stored in Atlas. Before answering, BharatSec AI retrieves the closest notes and cites them.

Everything here is optional: without MONGODB_URI and an embedding key the assistant works as before,
and any Atlas or embedding failure only means an answer without reference notes.
"""
import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from config import GEMINI_API_KEY, MONGODB_DB, MONGODB_URI, VOYAGE_API_KEY

logger = logging.getLogger("bharatsec.knowledge")

COLLECTION = "knowledge_notes"
INDEX_NAME = "knowledge_vector"
DIMENSIONS = 1024
SYNC_INTERVAL_SECONDS = 900      # cheap when nothing changed; lets a large first load finish over a few ticks
EMBED_BATCH = 50
KEV_NOTES = 300                  # newest KEV entries only, to stay inside free embedding quotas
MIN_SCORE = 0.62                 # Atlas cosine scores are normalised to 0..1
RETRIEVAL_TIMEOUT = 4.0
VOYAGE_BASES = ("https://ai.mongodb.com/v1", "https://api.voyageai.com/v1")
GEMINI_EMBED_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:batchEmbedContents"

INDEX_DEFINITION = {
    "fields": [
        {"type": "vector", "path": "embedding", "numDimensions": DIMENSIONS, "similarity": "cosine"},
        {"type": "filter", "path": "embed_model"},
    ]
}


class EmbeddingError(Exception):
    """The embedding provider refused or failed; `retry_later` is set for quota and overload errors."""

    def __init__(self, message: str, retry_later: bool = False):
        super().__init__(message)
        self.retry_later = retry_later


@dataclass(frozen=True)
class Embedder:
    model: str    # stored on every note so vectors from different models never mix in one search
    provider: str


def embedder() -> Optional[Embedder]:
    if VOYAGE_API_KEY:
        return Embedder("voyage-4", "voyage")
    if GEMINI_API_KEY:
        return Embedder("gemini-embedding-001", "gemini")
    return None


def configured() -> bool:
    return bool(MONGODB_URI) and embedder() is not None


# ── Embeddings ────────────────────────────────────────────────────────────────

async def embed(texts: List[str], kind: str) -> List[List[float]]:
    """Embed texts as 'document' or 'query' vectors of DIMENSIONS floats."""
    chosen = embedder()
    if chosen is None:
        raise EmbeddingError("No embedding key is configured.")
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=8)) as client:
        if chosen.provider == "voyage":
            return await _voyage(client, texts, kind, chosen.model)
        return await _gemini(client, texts, kind)


def _raise_for(response: httpx.Response, provider: str) -> None:
    if response.status_code < 400:
        return
    retry_later = response.status_code == 429 or response.status_code >= 500
    raise EmbeddingError(f"{provider} embeddings failed: HTTP {response.status_code}", retry_later=retry_later)


async def _voyage(client: httpx.AsyncClient, texts: List[str], kind: str, model: str) -> List[List[float]]:
    body = {"input": texts, "model": model, "input_type": kind, "output_dimension": DIMENSIONS}
    response = None
    # Atlas model API keys use MongoDB's endpoint; keys made on Voyage's own site use theirs.
    for base in VOYAGE_BASES:
        response = await client.post(f"{base}/embeddings", json=body, headers={"Authorization": f"Bearer {VOYAGE_API_KEY}"})
        if response.status_code not in (401, 403):
            break
    _raise_for(response, "Voyage AI")
    data = sorted(response.json().get("data", []), key=lambda item: item.get("index", 0))
    return [item["embedding"] for item in data]


async def _gemini(client: httpx.AsyncClient, texts: List[str], kind: str) -> List[List[float]]:
    task = "RETRIEVAL_QUERY" if kind == "query" else "RETRIEVAL_DOCUMENT"
    requests = [
        {"model": "models/gemini-embedding-001", "content": {"parts": [{"text": text}]},
         "taskType": task, "outputDimensionality": DIMENSIONS}
        for text in texts
    ]
    response = await client.post(GEMINI_EMBED_URL, json={"requests": requests}, headers={"x-goog-api-key": GEMINI_API_KEY})
    _raise_for(response, "Gemini")
    return [item["values"] for item in response.json().get("embeddings", [])]


# ── Atlas ─────────────────────────────────────────────────────────────────────

_client = None


def _collection():
    """The notes collection, or None when MongoDB is not configured. One client per warm instance."""
    global _client
    if not MONGODB_URI:
        return None
    if _client is None:
        from pymongo import MongoClient
        _client = MongoClient(MONGODB_URI, appname="bharatsec", serverSelectionTimeoutMS=5000,
                              connectTimeoutMS=5000, maxPoolSize=4)
    return _client[MONGODB_DB][COLLECTION]


def _index_state(collection) -> str:
    """Create the vector index when missing; return its status (READY, PENDING, BUILDING, FAILED, ...)."""
    existing = list(collection.list_search_indexes(INDEX_NAME))
    if existing:
        return str(existing[0].get("status") or ("READY" if existing[0].get("queryable") else "PENDING"))
    from pymongo.operations import SearchIndexModel
    collection.create_search_index(SearchIndexModel(definition=INDEX_DEFINITION, name=INDEX_NAME, type="vectorSearch"))
    return "PENDING"


# ── Notes ─────────────────────────────────────────────────────────────────────

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def _strip_markdown(text: str) -> str:
    return re.sub(r"[*`]", "", text)


def collect_notes() -> List[Dict[str, str]]:
    """Every note the knowledge base should hold, built fresh from code and the threat-intel database."""
    from engines import ai_engine, kb_documents, knowledge_base, threat_intel_engine

    notes: List[Dict[str, str]] = [dict(note) for note in kb_documents.NOTES]
    for phrases, answer in knowledge_base.KNOWLEDGE:
        title = phrases[0].upper() if len(phrases[0]) <= 4 else phrases[0].capitalize()
        notes.append({"id": f"offline:{_slug(phrases[0])}", "title": title, "source": "BharatSec knowledge",
                      "url": "", "text": _strip_markdown(answer)})
    for key, template in ai_engine.FINDING_TEMPLATES.items():
        notes.append({
            "id": f"finding:{key}", "title": f"Fix guide: {key.replace('_', ' ')}", "source": "BharatSec fix guide", "url": "",
            "text": f"{template['ai_analysis']} Fix: {template['fix']} Effort: {template['effort']}. Impact: {template['impact']}.",
        })
    try:
        kev_entries = threat_intel_engine.recent_kev_entries(KEV_NOTES)
    except Exception as exc:  # the threat-intel tables may not exist yet on a fresh install
        logger.info("KEV notes skipped: %s", exc)
        kev_entries = []
    for entry in kev_entries:
        products = ", ".join(entry["products"]) or "unspecified product"
        ransomware = "It is known to be used in ransomware campaigns. " if entry["ransomware"] else ""
        notes.append({
            "id": f"kev:{entry['cve']}", "title": f"{entry['cve']}: {entry['name']}", "source": "CISA KEV",
            "url": f"https://nvd.nist.gov/vuln/detail/{entry['cve']}",
            "text": (f"{entry['cve']} ({entry['name']}) affects {products}. CISA added it to the Known Exploited Vulnerabilities "
                     f"catalog on {entry['date_added'][:10] or 'an unknown date'}, meaning it is exploited in the wild. {ransomware}"
                     "Patch or mitigate it before other findings, especially on internet-facing systems."),
        })
    for note in notes:
        note["hash"] = hashlib.sha256(f"{note['title']}\n{note['text']}\n{note['url']}".encode()).hexdigest()
    return notes


def _embedding_text(note: Dict[str, str]) -> str:
    return f"{note['title']}\n\n{note['text']}"


# ── Sync ──────────────────────────────────────────────────────────────────────

async def sync(time_budget: float = 25.0) -> Dict[str, Any]:
    """Embed new or changed notes, delete retired ones and make sure the vector index exists.

    Work stops at `time_budget` seconds or on a quota error; the next run continues where this one stopped.
    """
    chosen, collection = embedder(), _collection()
    if chosen is None or collection is None:
        return {"status": "disabled"}
    started = time.monotonic()
    notes = collect_notes()
    stored = await asyncio.to_thread(lambda: {
        doc["_id"]: doc for doc in collection.find({}, {"hash": 1, "embed_model": 1})
    })
    wanted = {note["id"] for note in notes}
    retired = [note_id for note_id in stored if note_id not in wanted]
    if retired:
        await asyncio.to_thread(collection.delete_many, {"_id": {"$in": retired}})
    stale = [note for note in notes
             if stored.get(note["id"], {}).get("hash") != note["hash"]
             or stored.get(note["id"], {}).get("embed_model") != chosen.model]

    embedded, detail = 0, ""
    for start in range(0, len(stale), EMBED_BATCH):
        if time.monotonic() - started > time_budget:
            break
        batch = stale[start:start + EMBED_BATCH]
        try:
            vectors = await _embed_with_quota_wait(batch, started, time_budget)
        except (EmbeddingError, httpx.HTTPError) as exc:
            detail = str(exc)
            logger.warning("Knowledge sync paused: %s", exc)
            break
        now = datetime.now(timezone.utc).isoformat()
        documents = [
            {"_id": note["id"], "title": note["title"], "text": note["text"], "source": note["source"], "url": note["url"],
             "hash": note["hash"], "embed_model": chosen.model, "embedding": vector, "updated_at": now}
            for note, vector in zip(batch, vectors)
        ]
        await asyncio.to_thread(_replace_all, collection, documents)
        embedded += len(documents)

    try:
        index = await asyncio.to_thread(_index_state, collection)
    except Exception as exc:  # e.g. a cluster tier that only allows creating indexes in the Atlas UI
        logger.warning("Vector index check failed: %s", exc)
        index = f"unavailable: {exc}"[:200]
    return {
        "status": "ok" if not detail else "partial",
        "notes": len(notes),
        "embedded": embedded,
        "remaining": len(stale) - embedded,
        "removed": len(retired),
        "embed_model": chosen.model,
        "index": index,
        "detail": detail,
    }


QUOTA_WAIT_SECONDS = 62  # free embedding tiers limit requests per minute


async def _embed_with_quota_wait(batch: List[Dict[str, str]], started: float, time_budget: float) -> List[List[float]]:
    """Embed a batch; on a per-minute quota error, wait for the next minute once if the budget allows."""
    texts = [_embedding_text(note) for note in batch]
    try:
        return await embed(texts, "document")
    except EmbeddingError as exc:
        if not exc.retry_later or time.monotonic() - started + QUOTA_WAIT_SECONDS > time_budget:
            raise
    await asyncio.sleep(QUOTA_WAIT_SECONDS)
    return await embed(texts, "document")


def _replace_all(collection, documents: List[Dict[str, Any]]) -> None:
    for document in documents:
        collection.replace_one({"_id": document["_id"]}, document, upsert=True)


def status() -> Dict[str, Any]:
    """Counts and index state for the admin view."""
    chosen, collection = embedder(), _collection()
    if chosen is None or collection is None:
        return {
            "enabled": False,
            "mongodb_configured": bool(MONGODB_URI),
            "embedding_configured": chosen is not None,
        }
    stored = collection.count_documents({"embed_model": chosen.model})
    try:
        indexes = list(collection.list_search_indexes(INDEX_NAME))
        index = str(indexes[0].get("status")) if indexes else "missing"
    except Exception as exc:
        index = f"unavailable: {exc}"[:200]
    return {
        "enabled": True,
        "database": MONGODB_DB,
        "collection": COLLECTION,
        "index_name": INDEX_NAME,
        "index": index,
        "index_definition": INDEX_DEFINITION,
        "embed_model": chosen.model,
        "notes_stored": stored,
    }


# ── Retrieval ─────────────────────────────────────────────────────────────────

async def retrieve(question: str, limit: int = 4) -> List[Dict[str, Any]]:
    """Closest notes for a question, best first. Never raises: no notes is always a safe answer."""
    text = (question or "").strip()
    if not configured() or len(text) < 8:
        return []
    try:
        return await asyncio.wait_for(_search(text, limit), RETRIEVAL_TIMEOUT)
    except Exception as exc:
        logger.warning("Knowledge retrieval skipped: %s", exc)
        return []


async def _search(text: str, limit: int) -> List[Dict[str, Any]]:
    chosen, collection = embedder(), _collection()
    vector = (await embed([text[:2000]], "query"))[0]
    pipeline = [
        {"$vectorSearch": {"index": INDEX_NAME, "path": "embedding", "queryVector": vector,
                           "numCandidates": 100, "limit": limit, "filter": {"embed_model": chosen.model}}},
        {"$project": {"_id": 0, "title": 1, "text": 1, "source": 1, "url": 1, "score": {"$meta": "vectorSearchScore"}}},
    ]
    results = await asyncio.to_thread(lambda: list(collection.aggregate(pipeline)))
    return [result for result in results if result.get("score", 0) >= MIN_SCORE]
