"""Threat-feed ingestion, IOC enrichment, environment correlation, and breach exposure."""
import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

import httpx

from config import DATA_DIR, USER_AGENT

logger = logging.getLogger("bharatsec.threat_intel")
DB_PATH = Path(os.getenv("THREAT_INTEL_DATABASE_PATH", str(DATA_DIR / "threat_intel.db")))
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
SYNC_INTERVAL_SECONDS = max(300, int(os.getenv("TI_SYNC_INTERVAL_SECONDS", "900")))
INITIAL_SYNC_DELAY_SECONDS = max(1, int(os.getenv("TI_INITIAL_SYNC_DELAY_SECONDS", "5")))
BREACH_SYNC_INTERVAL_SECONDS = max(86400, int(os.getenv("TI_BREACH_SYNC_INTERVAL_SECONDS", "86400")))

FEEDS = {
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "Vulnerabilities confirmed exploited in the wild.",
    },
    "urlhaus": {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/json_recent/",
        "description": "Recently reported malware distribution URLs.",
    },
}

ATTACK_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1105/"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with _db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ti_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                threat_type TEXT NOT NULL DEFAULT '',
                confidence INTEGER NOT NULL DEFAULT 50,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                tags_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'new',
                enrichment_json TEXT NOT NULL DEFAULT '{}',
                enriched_at TEXT,
                UNIQUE(ioc, source)
            );
            CREATE INDEX IF NOT EXISTS ti_indicators_ioc ON ti_indicators(ioc);
            CREATE INDEX IF NOT EXISTS ti_indicators_seen ON ti_indicators(last_seen_at DESC);
            CREATE TABLE IF NOT EXISTS ti_feed_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_key TEXT NOT NULL,
                status TEXT NOT NULL,
                fetched_count INTEGER NOT NULL DEFAULT 0,
                detail TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ti_feed_runs_recent ON ti_feed_runs(feed_key, checked_at DESC);
            CREATE TABLE IF NOT EXISTS ti_breach_watches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_checked_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ti_breach_exposures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                breach_name TEXT NOT NULL,
                affected_accounts INTEGER NOT NULL DEFAULT 0,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(domain, breach_name)
            );
            """
        )


def _indicator_row(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["tags"] = json.loads(value.pop("tags_json"))
    value["enrichment"] = json.loads(value.pop("enrichment_json"))
    return value


def normalize_ioc(value: str, requested_type: str = "auto") -> tuple[str, str]:
    raw = value.strip()
    if not raw or len(raw) > 2048:
        raise ValueError("Indicator must be between 1 and 2048 characters.")
    kind = requested_type.lower()
    if kind == "auto":
        if re.fullmatch(r"CVE-\d{4}-\d{4,8}", raw, re.IGNORECASE):
            kind = "cve"
        elif re.fullmatch(r"[a-fA-F0-9]{32}", raw):
            kind = "md5"
        elif re.fullmatch(r"[a-fA-F0-9]{40}", raw):
            kind = "sha1"
        elif re.fullmatch(r"[a-fA-F0-9]{64}", raw):
            kind = "sha256"
        elif raw.startswith(("http://", "https://")):
            kind = "url"
        else:
            try:
                ipaddress.ip_address(raw)
                kind = "ip"
            except ValueError:
                kind = "domain"

    if kind == "cve":
        if not re.fullmatch(r"CVE-\d{4}-\d{4,8}", raw, re.IGNORECASE):
            raise ValueError("CVE indicators must use the CVE-YYYY-NNNN format.")
        return raw.upper(), kind
    if kind in ("md5", "sha1", "sha256"):
        expected_length = {"md5": 32, "sha1": 40, "sha256": 64}[kind]
        if not re.fullmatch(rf"[a-fA-F0-9]{{{expected_length}}}", raw):
            raise ValueError(f"{kind.upper()} indicators must contain {expected_length} hexadecimal characters.")
        return raw.lower(), kind
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(raw)), kind
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 indicator.") from exc
    if kind == "url":
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("URL indicators must use HTTP or HTTPS and must not include credentials.")
        try:
            host = parts.hostname.encode("idna").decode("ascii").lower()
            port = parts.port
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Enter a valid URL indicator.") from exc
        netloc = f"{host}:{port}" if port else host
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")), kind
    if kind == "domain":
        candidate = raw.rstrip(".").lower()
        if candidate.startswith("*."):
            candidate = candidate[2:]
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Enter a valid domain indicator.") from exc
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if len(candidate) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", candidate):
            raise ValueError("Enter a valid domain indicator.")
        return candidate, kind
    raise ValueError("Supported indicator types: auto, domain, URL, IP, CVE, MD5, SHA-1, SHA-256.")


def _upsert_indicator_in_connection(
    connection: sqlite3.Connection,
    value: str,
    kind: str = "auto",
    source: str = "Analyst",
    title: str = "",
    threat_type: str = "",
    confidence: int = 50,
    tags: list[str] | None = None,
    first_seen_at: str | None = None,
) -> int:
    ioc, ioc_type = normalize_ioc(value, kind)
    timestamp = _now()
    first_seen = first_seen_at or timestamp
    connection.execute(
        """INSERT INTO ti_indicators
           (ioc, ioc_type, source, title, threat_type, confidence, first_seen_at, last_seen_at, tags_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ioc, source) DO UPDATE SET
               title = CASE WHEN excluded.title = '' THEN ti_indicators.title ELSE excluded.title END,
               threat_type = CASE WHEN excluded.threat_type = '' THEN ti_indicators.threat_type ELSE excluded.threat_type END,
               confidence = MAX(ti_indicators.confidence, excluded.confidence),
               last_seen_at = excluded.last_seen_at,
               tags_json = excluded.tags_json""",
        (ioc, ioc_type, source, title[:300], threat_type[:120], max(0, min(100, confidence)), first_seen, timestamp, json.dumps((tags or [])[:30])),
    )
    row = connection.execute("SELECT id FROM ti_indicators WHERE ioc = ? AND source = ?", (ioc, source)).fetchone()
    return row["id"]


def upsert_indicator(
    value: str,
    kind: str = "auto",
    source: str = "Analyst",
    title: str = "",
    threat_type: str = "",
    confidence: int = 50,
    tags: list[str] | None = None,
    first_seen_at: str | None = None,
) -> int:
    with _db() as connection:
        return _upsert_indicator_in_connection(
            connection, value, kind, source, title, threat_type, confidence, tags, first_seen_at
        )


def list_indicators(
    query: str = "",
    source: str = "",
    status: str = "",
    limit: int = 250,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    parameters: list[Any] = []
    if query:
        clauses.append("(ioc LIKE ? OR title LIKE ? OR threat_type LIKE ?)")
        needle = f"%{query[:200]}%"
        parameters.extend((needle, needle, needle))
    if source:
        clauses.append("source = ?")
        parameters.append(source)
    if status:
        clauses.append("status = ?")
        parameters.append(status)
    sql = "SELECT * FROM ti_indicators"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY last_seen_at DESC LIMIT ? OFFSET ?"
    parameters.extend((max(1, min(limit, 1000)), max(0, offset)))
    with _db() as connection:
        rows = connection.execute(sql, parameters).fetchall()
    return [_indicator_row(row) for row in rows]


def get_indicator(indicator_id: int) -> dict[str, Any] | None:
    with _db() as connection:
        row = connection.execute("SELECT * FROM ti_indicators WHERE id = ?", (indicator_id,)).fetchone()
    return _indicator_row(row) if row else None


def set_indicator_status(indicator_id: int, status: str) -> dict[str, Any] | None:
    with _db() as connection:
        connection.execute("UPDATE ti_indicators SET status = ? WHERE id = ?", (status, indicator_id))
    return get_indicator(indicator_id)


def feed_status() -> list[dict[str, Any]]:
    with _db() as connection:
        results = []
        for feed_key, feed in FEEDS.items():
            row = connection.execute(
                "SELECT * FROM ti_feed_runs WHERE feed_key = ? ORDER BY id DESC LIMIT 1", (feed_key,)
            ).fetchone()
            results.append({
                "key": feed_key,
                "name": feed["name"],
                "description": feed["description"],
                "status": row["status"] if row else "not_synced",
                "fetched_count": row["fetched_count"] if row else 0,
                "detail": row["detail"] if row else "Awaiting first synchronization.",
                "checked_at": row["checked_at"] if row else None,
            })
    return results


def _save_feed_run(feed_key: str, status: str, fetched_count: int, detail: str) -> None:
    with _db() as connection:
        connection.execute(
            "INSERT INTO ti_feed_runs(feed_key, status, fetched_count, detail, checked_at) VALUES (?, ?, ?, ?, ?)",
            (feed_key, status, fetched_count, detail[:500], _now()),
        )


def _cisa_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cveID", "")
        if not cve:
            continue
        tags = [item.get("vendorProject", ""), item.get("product", "")]
        if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known":
            tags.append("ransomware")
        records.append({
            "ioc": cve,
            "type": "cve",
            "title": item.get("vulnerabilityName") or cve,
            "threat_type": "known exploited vulnerability",
            "confidence": 100,
            "first_seen_at": item.get("dateAdded"),
            "tags": [tag for tag in tags if tag],
        })
    return records


def _urlhaus_items(payload: Any) -> list[Any]:
    """Flatten URLhaus payloads; json_recent maps each URL id to a list of entries."""
    values = payload.get("urls", payload) if isinstance(payload, dict) else payload
    if isinstance(values, dict):
        values = list(values.values())
    if not isinstance(values, list):
        return []
    items = []
    for value in values:
        items.extend(value if isinstance(value, list) else [value])
    return items


def _urlhaus_records(payload: Any) -> list[dict[str, Any]]:
    records = []
    for item in _urlhaus_items(payload):
        if not isinstance(item, dict):
            continue
        indicator = item.get("url") or item.get("host")
        if not indicator:
            continue
        if not str(indicator).startswith(("http://", "https://")):
            indicator = f"http://{indicator}/"
        records.append({
            "ioc": indicator,
            "type": "url",
            "title": f"URLhaus malware URL ({item.get('url_status') or 'reported'})",
            "threat_type": item.get("threat") or "malware distribution",
            "confidence": 90 if item.get("url_status") == "online" else 80,
            "first_seen_at": item.get("dateadded"),
            "tags": item.get("tags") or [],
        })
    return records


def _import_records(source: str, records: list[dict[str, Any]]) -> int:
    imported = 0
    with _db() as connection:
        for record in records:
            try:
                _upsert_indicator_in_connection(
                    connection,
                    record["ioc"],
                    record["type"],
                    source,
                    record["title"],
                    record["threat_type"],
                    record["confidence"],
                    record["tags"],
                    record.get("first_seen_at"),
                )
                imported += 1
            except ValueError:
                continue
    return imported


async def _sync_one_feed(feed_key: str) -> dict[str, Any]:
    feed = FEEDS[feed_key]
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(25, connect=8),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        ) as client:
            response = await client.get(feed["url"])
            response.raise_for_status()
            payload = response.json()
        records = _cisa_records(payload) if feed_key == "cisa_kev" else _urlhaus_records(payload)
        if payload and not records:
            raise ValueError("Feed returned data in an unrecognized format; no indicators were parsed.")
        # Tens of thousands of upserts: run them off the event loop so the API stays responsive.
        imported = await asyncio.to_thread(_import_records, feed["name"], records)
        detail = f"Imported or refreshed {imported:,} indicators."
        _save_feed_run(feed_key, "ok", imported, detail)
        return {"key": feed_key, "status": "ok", "fetched_count": imported, "detail": detail}
    except Exception as exc:
        detail = f"Feed sync failed: {type(exc).__name__}: {str(exc)[:240]}"
        logger.warning("Threat intel feed %s failed: %s", feed_key, exc)
        _save_feed_run(feed_key, "error", 0, detail)
        return {"key": feed_key, "status": "error", "fetched_count": 0, "detail": detail}


async def sync_feeds() -> list[dict[str, Any]]:
    return await asyncio.gather(*(_sync_one_feed(feed_key) for feed_key in FEEDS))


def _domain_for_ioc(ioc: str, kind: str) -> str | None:
    if kind == "url":
        return urlsplit(ioc).hostname
    if kind == "domain":
        return ioc
    return None


def _monitored_assets() -> list[dict[str, Any]]:
    try:
        from engines.soc_engine import list_assets
        return list_assets()
    except Exception:
        logger.exception("SOC assets unavailable for threat correlation")
        return []


def _monitored_scan_texts(assets: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """(domain, upper-cased findings text) for completed scans of monitored assets."""
    try:
        from routers.scan import scans
    except ImportError:
        logger.debug("Scan router unavailable for CVE correlation")
        return []
    asset_domains = {asset["domain"].lower() for asset in assets}
    return [
        (scan.domain, " ".join(f"{f.title} {f.description} {f.evidence}" for f in scan.findings).upper())
        for scan in list(scans.values())
        if scan.domain.lower() in asset_domains
    ]


def _asset_correlations(
    indicator: dict[str, Any], assets: list[dict[str, Any]], scan_texts: list[tuple[str, str]]
) -> list[dict[str, Any]]:
    domain = (_domain_for_ioc(indicator["ioc"], indicator["ioc_type"]) or "").lower().rstrip(".")
    matches: list[dict[str, Any]] = []
    if domain:
        for asset in assets:
            asset_domain = asset["domain"].lower()
            if domain == asset_domain or domain.endswith(f".{asset_domain}"):
                matches.append({
                    "asset_id": asset["id"], "asset_name": asset["name"],
                    "asset_domain": asset_domain, "match_type": "domain overlap",
                })
    if indicator["ioc_type"] == "cve":
        cve = indicator["ioc"].upper()
        for scan_domain, text in scan_texts:
            if cve in text:
                matches.append({
                    "asset_id": None, "asset_name": scan_domain,
                    "asset_domain": scan_domain, "match_type": "scan finding",
                })
    return matches


def _correlated_indicators() -> list[tuple[int, list[dict[str, Any]]]]:
    """Match every active domain/URL/CVE indicator against monitored assets in one pass."""
    assets = _monitored_assets()
    if not assets:
        return []
    scan_texts = _monitored_scan_texts(assets)
    with _db() as connection:
        rows = connection.execute(
            "SELECT id, ioc, ioc_type FROM ti_indicators WHERE status != 'ignored' AND ioc_type IN ('domain', 'url', 'cve')"
        ).fetchall()
    correlated = []
    for row in rows:
        matches = _asset_correlations(dict(row), assets, scan_texts)
        if matches:
            correlated.append((row["id"], matches))
    return correlated


def list_correlations() -> list[dict[str, Any]]:
    results = []
    for indicator_id, matches in _correlated_indicators():
        indicator = get_indicator(indicator_id)
        if indicator:
            results.append({**indicator, "matches": matches})
    return results


def _local_enrichment(indicator: dict[str, Any]) -> dict[str, Any]:
    ioc, kind = indicator["ioc"], indicator["ioc_type"]
    enrichment: dict[str, Any] = {"method": "local", "summary": "Local enrichment only; no commercial reputation key is configured."}
    if kind == "cve":
        enrichment.update({"cisa_kev": indicator["source"] == FEEDS["cisa_kev"]["name"], "techniques": ["T1190"]})
    elif kind in ("domain", "url"):
        hostname = _domain_for_ioc(ioc, kind)
        try:
            answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            enrichment["resolved_ips"] = list(dict.fromkeys(answer[4][0] for answer in answers))[:12]
        except (socket.gaierror, OSError):
            enrichment["resolved_ips"] = []
        enrichment["techniques"] = ["T1105", "T1071"] if indicator["source"] == FEEDS["urlhaus"]["name"] else []
    elif kind == "ip":
        try:
            enrichment["reverse_dns"] = socket.gethostbyaddr(ioc)[0]
        except (socket.herror, socket.gaierror, OSError):
            enrichment["reverse_dns"] = None
        enrichment["is_global"] = ipaddress.ip_address(ioc).is_global
    return enrichment


async def enrich_indicator(indicator_id: int) -> dict[str, Any] | None:
    indicator = get_indicator(indicator_id)
    if indicator is None:
        return None
    enrichment = await asyncio.to_thread(_local_enrichment, indicator)
    if VIRUSTOTAL_API_KEY and indicator["ioc_type"] in {"ip", "domain", "url", "md5", "sha1", "sha256"}:
        try:
            target = indicator["ioc"]
            if indicator["ioc_type"] == "url":
                target = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/{'files' if indicator['ioc_type'] in {'md5', 'sha1', 'sha256'} else {'ip': 'ip_addresses', 'domain': 'domains', 'url': 'urls'}[indicator['ioc_type']]}/{target}"
            async with httpx.AsyncClient(timeout=httpx.Timeout(12, connect=5)) as client:
                response = await client.get(endpoint, headers={"x-apikey": VIRUSTOTAL_API_KEY})
                if response.status_code == 200:
                    attributes = response.json().get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "reputation": attributes.get("reputation"),
                        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                        "categories": attributes.get("categories", {}),
                    }
                    enrichment["method"] = "local + VirusTotal"
                else:
                    enrichment["virustotal_error"] = f"Provider returned HTTP {response.status_code}."
        except Exception as exc:
            enrichment["virustotal_error"] = f"Provider lookup failed: {type(exc).__name__}."
    timestamp = _now()
    with _db() as connection:
        connection.execute(
            "UPDATE ti_indicators SET enrichment_json = ?, enriched_at = ? WHERE id = ?",
            (json.dumps(enrichment), timestamp, indicator_id),
        )
    return get_indicator(indicator_id)


def get_overview() -> dict[str, Any]:
    with _db() as connection:
        counts = connection.execute(
            """SELECT
               (SELECT COUNT(*) FROM ti_indicators WHERE status != 'ignored') AS active_indicators,
               (SELECT COUNT(*) FROM ti_indicators WHERE source = 'CISA Known Exploited Vulnerabilities' AND status != 'ignored') AS kev_count,
               (SELECT COUNT(*) FROM ti_indicators WHERE source = 'abuse.ch URLhaus' AND status != 'ignored') AS urlhaus_count,
               (SELECT COUNT(*) FROM ti_breach_watches WHERE enabled = 1) AS watched_domains,
               (SELECT COUNT(*) FROM ti_breach_exposures) AS breach_exposures,
               (SELECT MAX(checked_at) FROM ti_feed_runs) AS last_feed_sync"""
        ).fetchone()
    return {
        **dict(counts),
        "environment_matches": len(_correlated_indicators()),
        "feed_count": len(FEEDS),
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "hibp_configured": bool(HIBP_API_KEY),
    }


def list_breach_watches() -> list[dict[str, Any]]:
    with _db() as connection:
        rows = connection.execute("SELECT * FROM ti_breach_watches ORDER BY domain").fetchall()
    return [dict(row) for row in rows]


def add_breach_watch(domain: str) -> dict[str, Any]:
    with _db() as connection:
        connection.execute(
            "INSERT INTO ti_breach_watches(domain, created_at) VALUES (?, ?) ON CONFLICT(domain) DO UPDATE SET enabled = 1",
            (domain, _now()),
        )
        row = connection.execute("SELECT * FROM ti_breach_watches WHERE domain = ?", (domain,)).fetchone()
    return dict(row)


def delete_breach_watch(watch_id: int) -> bool:
    with _db() as connection:
        cursor = connection.execute("DELETE FROM ti_breach_watches WHERE id = ?", (watch_id,))
    return cursor.rowcount > 0


def list_breach_exposures() -> list[dict[str, Any]]:
    with _db() as connection:
        rows = connection.execute(
            "SELECT * FROM ti_breach_exposures ORDER BY last_seen_at DESC, domain"
        ).fetchall()
    return [dict(row) for row in rows]


async def check_breach_domain(domain: str) -> dict[str, Any]:
    if not HIBP_API_KEY:
        raise RuntimeError("Set HIBP_API_KEY on the server to enable verified-domain breach checks.")
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(20, connect=8)) as client:
        response = await client.get(url, headers={"hibp-api-key": HIBP_API_KEY, "user-agent": USER_AGENT})
    if response.status_code == 404:
        aliases: dict[str, Any] = {}
    else:
        response.raise_for_status()
        aliases = response.json()
        if not isinstance(aliases, dict):
            raise ValueError("Unexpected HIBP breached-domain response format.")
    # HIBP returns {"alias": ["BreachName", ...], ...} for the verified domain.
    counts: dict[str, int] = {}
    for breaches in aliases.values():
        for breach in {str(name).strip() for name in breaches or [] if str(name).strip()}:
            counts[breach] = counts.get(breach, 0) + 1
    timestamp = _now()
    with _db() as connection:
        for breach, count in counts.items():
            connection.execute(
                """INSERT INTO ti_breach_exposures(domain, breach_name, affected_accounts, first_seen_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?) ON CONFLICT(domain, breach_name) DO UPDATE SET
                   affected_accounts = excluded.affected_accounts, last_seen_at = excluded.last_seen_at""",
                (domain, breach, count, timestamp, timestamp),
            )
        placeholders = ",".join("?" for _ in counts)
        connection.execute(
            f"DELETE FROM ti_breach_exposures WHERE domain = ? AND breach_name NOT IN ({placeholders})",
            (domain, *counts),
        )
        connection.execute("UPDATE ti_breach_watches SET last_checked_at = ? WHERE domain = ?", (timestamp, domain))
    return {"domain": domain, "breach_count": len(counts), "affected_accounts": len(aliases), "checked_at": timestamp}


async def sync_breach_watches() -> None:
    if not HIBP_API_KEY:
        return
    now = datetime.now(timezone.utc)
    for watch in list_breach_watches():
        if not watch["enabled"]:
            continue
        last_checked = watch.get("last_checked_at")
        if last_checked:
            try:
                elapsed = (now - datetime.fromisoformat(last_checked)).total_seconds()
            except ValueError:
                elapsed = BREACH_SYNC_INTERVAL_SECONDS
            if elapsed < BREACH_SYNC_INTERVAL_SECONDS:
                continue
        try:
            await check_breach_domain(watch["domain"])
        except Exception as exc:
            logger.warning("Breach exposure check failed for %s: %s", watch["domain"], exc)


async def feed_loop() -> None:
    await asyncio.sleep(INITIAL_SYNC_DELAY_SECONDS)
    while True:
        try:
            await sync_feeds()
            await sync_breach_watches()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Threat intel sync cycle failed")
        await asyncio.sleep(SYNC_INTERVAL_SECONDS)