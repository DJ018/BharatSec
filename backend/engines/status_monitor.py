"""Public status: live checks of each part of BharatSec, and the daily scan of BharatSec's own website."""
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlsplit

import auth as auth_service
import database
import seo
from engines import ai_engine, scan_store, threat_intel_engine, vector_knowledge

SELF_DOMAIN = urlsplit(seo.SITE_URL).hostname
SELF_SCAN_PREFIX = f"{scan_store.PUBLIC_PREFIX}self_"  # public, so anyone can open the report
SELF_SCAN_INTERVAL_SECONDS = 20 * 3600                 # once a day on the daily schedule
JOBS_STALE_SECONDS = 26 * 3600                         # the schedule runs daily; allow some slack
CACHE_SECONDS = 30                                     # the page is public: don't hit the database per view

OPERATIONAL, DEGRADED, DOWN, OFF = "operational", "degraded", "down", "off"
_cache: Dict[str, Any] = {"at": 0.0, "payload": None}


def _component(name: str, state: str, detail: str) -> Dict[str, str]:
    return {"name": name, "status": state, "detail": detail}


def _database_check() -> Dict[str, str]:
    started = time.perf_counter()
    try:
        with database.transaction(auth_service.AUTH_DB_PATH) as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception:
        return _component("Database", DOWN, "The database did not answer.")
    elapsed = round((time.perf_counter() - started) * 1000)
    return _component("Database", OPERATIONAL if elapsed < 2000 else DEGRADED, f"Answered in {elapsed} ms.")


def _scanner_check(latest: Dict[str, Any] | None) -> Dict[str, str]:
    if latest is None:
        return _component("Domain scanner", OPERATIONAL, "Ready. The daily self-scan has not run yet.")
    if latest["status"] == "complete":
        return _component("Domain scanner", OPERATIONAL, "The latest daily self-scan finished normally.")
    return _component("Domain scanner", DEGRADED, "The latest daily self-scan did not finish.")


def _feeds_check() -> Dict[str, str]:
    feeds = threat_intel_engine.feed_status()
    synced = [feed for feed in feeds if feed["status"] not in {"not_synced", "error"}]
    failed = [feed for feed in feeds if feed["status"] == "error"]
    if not synced and not failed:
        return _component("Threat intelligence feeds", OPERATIONAL, "Waiting for the first sync.")
    if failed and not synced:
        return _component("Threat intelligence feeds", DEGRADED, "The feeds could not be reached at the last sync.")
    detail = f"{len(synced)} of {len(feeds)} feeds synced."
    return _component("Threat intelligence feeds", DEGRADED if failed else OPERATIONAL, detail)


def _jobs_check() -> Dict[str, str]:
    last = auth_service.job_last_run("cron-tick")
    if last is None:
        return _component("Scheduled jobs", OPERATIONAL, "Waiting for the first run.")
    age = datetime.now(timezone.utc).timestamp() - last
    if age > JOBS_STALE_SECONDS:
        return _component("Scheduled jobs", DEGRADED, "The daily jobs have not run in over a day.")
    return _component("Scheduled jobs", OPERATIONAL, "Monitoring checks and feed syncs are running on schedule.")


def self_scans(limit: int = 14) -> List[Dict[str, Any]]:
    return scan_store.history_by_prefix(SELF_SCAN_PREFIX, limit)


def snapshot() -> Dict[str, Any]:
    now = time.monotonic()
    if _cache["payload"] is not None and now - _cache["at"] < CACHE_SECONDS:
        return _cache["payload"]
    scans = self_scans()
    latest = scans[-1] if scans else None
    components = [
        _component("Website and API", OPERATIONAL, "Serving pages and requests."),
        _database_check(),
        _scanner_check(latest),
        _component("BharatSec AI", OPERATIONAL, "Answering questions.") if ai_engine._providers()
        else _component("BharatSec AI", OFF, "Not switched on."),
        _component("AI knowledge base", OPERATIONAL, "Cited answers from the security knowledge base.")
        if vector_knowledge.configured() else _component("AI knowledge base", OFF, "Not switched on."),
        _feeds_check(),
        _jobs_check(),
    ]
    states = {item["status"] for item in components}
    overall = DOWN if DOWN in states else DEGRADED if DEGRADED in states else OPERATIONAL
    completed = [scan for scan in scans if scan["status"] == "complete"]
    payload = {
        "status": overall,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "components": components,
        "self_scan": {
            "domain": SELF_DOMAIN,
            "latest": completed[-1] if completed else None,
            "history": completed,
        },
    }
    _cache.update(at=now, payload=payload)
    return payload
