"""Persistent asset monitoring and incident data for the SOC workspace."""
import asyncio
from contextlib import contextmanager
import logging
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import database
from config import DATA_DIR, USER_AGENT
from engines.net_guard import is_public_address

logger = logging.getLogger("bharatsec.soc")
DB_PATH = Path(os.getenv("SOC_DATABASE_PATH", str(DATA_DIR / "soc.db")))
MONITOR_TICK_SECONDS = max(5, int(os.getenv("SOC_MONITOR_TICK_SECONDS", "15")))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _connect() -> Iterator[Any]:
    with database.transaction(DB_PATH, timeout=10) as connection:
        yield connection


def init_db() -> None:
    with _connect() as connection:
        database.schema_lock(connection, "soc")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS soc_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                check_interval_seconds INTEGER NOT NULL DEFAULT 300,
                status TEXT NOT NULL DEFAULT 'unknown',
                http_status INTEGER,
                response_time_ms REAL,
                tls_valid INTEGER,
                tls_days_remaining INTEGER,
                https_redirect INTEGER,
                last_error TEXT NOT NULL DEFAULT '',
                last_checked_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS soc_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL REFERENCES soc_assets(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'open',
                occurrences INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                incident_id INTEGER
            );
            CREATE UNIQUE INDEX IF NOT EXISTS soc_alert_active_fingerprint
                ON soc_alerts(asset_id, fingerprint)
                WHERE state IN ('open', 'acknowledged', 'investigating');
            CREATE INDEX IF NOT EXISTS soc_alerts_state_seen
                ON soc_alerts(state, last_seen_at DESC);
            CREATE TABLE IF NOT EXISTS soc_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER REFERENCES soc_assets(id) ON DELETE SET NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                owner TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE INDEX IF NOT EXISTS soc_incidents_status_updated
                ON soc_incidents(status, updated_at DESC);
            CREATE TABLE IF NOT EXISTS soc_incident_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES soc_incidents(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT 'Analyst',
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def _row(row: Any) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def list_assets() -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM soc_assets ORDER BY enabled DESC, name COLLATE NOCASE"
        ).fetchall()
    return [dict(row) for row in rows]


def get_asset(asset_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        return _row(connection.execute("SELECT * FROM soc_assets WHERE id = ?", (asset_id,)).fetchone())


def create_asset(domain: str, name: str, interval_seconds: int) -> dict[str, Any]:
    timestamp = _now()
    with _connect() as connection:
        asset_id = connection.execute(
            """INSERT INTO soc_assets
               (domain, name, check_interval_seconds, created_at)
               VALUES (?, ?, ?, ?) RETURNING id""",
            (domain, name or domain, interval_seconds, timestamp),
        ).fetchone()[0]
    return get_asset(asset_id)


def update_asset(asset_id: int, *, enabled: bool | None = None) -> dict[str, Any] | None:
    if enabled is not None:
        with _connect() as connection:
            connection.execute(
                "UPDATE soc_assets SET enabled = ? WHERE id = ?",
                (int(enabled), asset_id),
            )
    return get_asset(asset_id)


def delete_asset(asset_id: int) -> bool:
    with _connect() as connection:
        cursor = connection.execute("DELETE FROM soc_assets WHERE id = ?", (asset_id,))
    return cursor.rowcount > 0


def list_due_assets() -> list[dict[str, Any]]:
    """Enabled assets whose check interval has elapsed, never-checked first, then oldest check first."""
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM soc_assets WHERE enabled = 1").fetchall()
    now = datetime.now(timezone.utc)

    def overdue(asset: dict[str, Any]) -> bool:
        if not asset["last_checked_at"]:
            return True
        try:
            checked = datetime.fromisoformat(asset["last_checked_at"])
        except ValueError:
            return True
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        return (now - checked).total_seconds() >= asset["check_interval_seconds"]

    due = [dict(row) for row in rows if overdue(dict(row))]
    return sorted(due, key=lambda asset: (asset["last_checked_at"] is not None, asset["last_checked_at"] or ""))


def list_alerts(state: str | None = None) -> list[dict[str, Any]]:
    query = """SELECT al.*, a.domain AS asset_domain, a.name AS asset_name
               FROM soc_alerts al JOIN soc_assets a ON a.id = al.asset_id"""
    parameters: tuple[Any, ...] = ()
    if state:
        query += " WHERE al.state = ?"
        parameters = (state,)
    query += " ORDER BY CASE al.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, al.last_seen_at DESC"
    with _connect() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def get_alert(alert_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            """SELECT al.*, a.domain AS asset_domain, a.name AS asset_name
               FROM soc_alerts al JOIN soc_assets a ON a.id = al.asset_id
               WHERE al.id = ?""",
            (alert_id,),
        ).fetchone()
    return _row(row)


class AlertConflictError(Exception):
    pass


def update_alert_state(alert_id: int, state: str) -> dict[str, Any] | None:
    with _connect() as connection:
        try:
            connection.execute(
                "UPDATE soc_alerts SET state = ?, updated_at = ? WHERE id = ?",
                (state, _now(), alert_id),
            )
        except database.IntegrityError as exc:
            # Only one active alert per asset condition may exist (partial unique index).
            raise AlertConflictError(
                "An active alert for this condition already exists; update that alert instead."
            ) from exc
        row = connection.execute(
            """SELECT al.*, a.domain AS asset_domain, a.name AS asset_name
               FROM soc_alerts al JOIN soc_assets a ON a.id = al.asset_id
               WHERE al.id = ?""",
            (alert_id,),
        ).fetchone()
    return _row(row)


def list_incidents(status: str | None = None) -> list[dict[str, Any]]:
    query = """SELECT i.*, a.domain AS asset_domain, a.name AS asset_name
               FROM soc_incidents i LEFT JOIN soc_assets a ON a.id = i.asset_id"""
    parameters: tuple[Any, ...] = ()
    if status:
        query += " WHERE i.status = ?"
        parameters = (status,)
    query += " ORDER BY CASE i.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, i.updated_at DESC"
    with _connect() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def get_incident(incident_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            """SELECT i.*, a.domain AS asset_domain, a.name AS asset_name
               FROM soc_incidents i LEFT JOIN soc_assets a ON a.id = i.asset_id
               WHERE i.id = ?""",
            (incident_id,),
        ).fetchone()
    return _row(row)


def list_incident_events(incident_id: int) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM soc_incident_events WHERE incident_id = ? ORDER BY created_at, id",
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _add_event(connection: Any, incident_id: int, event_type: str, author: str, message: str) -> None:
    connection.execute(
        """INSERT INTO soc_incident_events
           (incident_id, event_type, author, message, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (incident_id, event_type, author, message, _now()),
    )


def create_incident(
    title: str,
    severity: str,
    description: str,
    asset_id: int | None,
    owner: str,
    author: str,
    alert_id: int | None = None,
) -> dict[str, Any]:
    timestamp = _now()
    with _connect() as connection:
        incident_id = connection.execute(
            """INSERT INTO soc_incidents
               (asset_id, title, severity, description, owner, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (asset_id, title, severity, description, owner, timestamp, timestamp),
        ).fetchone()[0]
        _add_event(connection, incident_id, "created", author, "Incident opened.")
        if alert_id is not None:
            connection.execute(
                "UPDATE soc_alerts SET incident_id = ?, updated_at = ? WHERE id = ?",
                (incident_id, timestamp, alert_id),
            )
            _add_event(connection, incident_id, "alert_linked", author, f"Alert #{alert_id} linked to this incident.")
    return get_incident(incident_id)


def update_incident(
    incident_id: int,
    *,
    status: str | None = None,
    owner: str | None = None,
    author: str = "Analyst",
) -> dict[str, Any] | None:
    incident = get_incident(incident_id)
    if incident is None:
        return None
    timestamp = _now()
    with _connect() as connection:
        if status is not None:
            resolved_at = timestamp if status == "resolved" else None
            connection.execute(
                "UPDATE soc_incidents SET status = ?, resolved_at = ?, updated_at = ? WHERE id = ?",
                (status, resolved_at, timestamp, incident_id),
            )
            _add_event(connection, incident_id, "status", author, f"Status changed to {status}.")
        if owner is not None:
            connection.execute(
                "UPDATE soc_incidents SET owner = ?, updated_at = ? WHERE id = ?",
                (owner, timestamp, incident_id),
            )
            _add_event(connection, incident_id, "assignment", author, f"Assigned to {owner or 'unassigned'}.")
    return get_incident(incident_id)


def add_incident_note(incident_id: int, author: str, message: str) -> dict[str, Any] | None:
    if get_incident(incident_id) is None:
        return None
    with _connect() as connection:
        timestamp = _now()
        _add_event(connection, incident_id, "note", author, message)
        connection.execute("UPDATE soc_incidents SET updated_at = ? WHERE id = ?", (timestamp, incident_id))
    return get_incident(incident_id)


def get_overview() -> dict[str, Any]:
    with _connect() as connection:
        counts = connection.execute(
            """SELECT
                   (SELECT COUNT(*) FROM soc_assets WHERE enabled = 1) AS monitored_assets,
                   (SELECT COUNT(*) FROM soc_assets WHERE enabled = 1 AND status = 'online') AS online_assets,
                   (SELECT COUNT(*) FROM soc_alerts WHERE state IN ('open', 'acknowledged', 'investigating')) AS open_alerts,
                   (SELECT COUNT(*) FROM soc_alerts WHERE severity = 'CRITICAL' AND state IN ('open', 'acknowledged', 'investigating')) AS critical_alerts,
                   (SELECT COUNT(*) FROM soc_incidents WHERE status != 'resolved') AS active_incidents,
                   (SELECT MAX(last_checked_at) FROM soc_assets) AS last_check_at"""
        ).fetchone()
    return dict(counts)


# Upper bound for one asset check so a slow-dripping server cannot stall the monitor loop.
PROBE_DEADLINE_SECONDS = 45


class TargetBlockedError(Exception):
    pass


def _public_addresses(domain: str) -> list[str]:
    records = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or not all(is_public_address(address) for address in addresses):
        raise TargetBlockedError("The domain resolved to a non-public address; monitoring was blocked.")
    return addresses


def _request_ip(address: str, domain: str, *, secure: bool, verify_tls: bool = True) -> tuple[int, dict[str, str], float]:
    port = 443 if secure else 80
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(6)
    started = time.monotonic()
    try:
        raw.connect((address, port))
        stream = raw
        if secure:
            context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
            stream = context.wrap_socket(raw, server_hostname=domain)
        stream.settimeout(6)
        stream.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        response = stream.makefile("rb")
        status_line = response.readline(4096).decode("latin-1").strip()
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise OSError("Server returned an invalid HTTP response.")
        headers: dict[str, str] = {}
        for _ in range(64):
            line = response.readline(4096)
            if not line or line in (b"\r\n", b"\n"):
                break
            if b":" in line:
                key, value = line.decode("latin-1").split(":", 1)
                headers[key.strip().lower()] = value.strip()
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        return int(parts[1]), headers, elapsed_ms
    finally:
        raw.close()


def _probe_public_domain(domain: str) -> dict[str, Any]:
    addresses = _public_addresses(domain)
    tls_error = ""
    tls_days_remaining: int | None = None
    https_status: int | None = None
    http_status: int | None = None
    http_location = ""
    response_time_ms: float | None = None

    for address in addresses:
        try:
            https_status, _, response_time_ms = _request_ip(address, domain, secure=True)
            with socket.create_connection((address, 443), timeout=6) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as tls_socket:
                    certificate = tls_socket.getpeercert()
                    expiry = certificate.get("notAfter")
                    if expiry:
                        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), timezone.utc)
                        tls_days_remaining = (expires_at - datetime.now(timezone.utc)).days
            tls_error = ""  # an earlier address may have failed; this one succeeded
            break
        except ssl.SSLCertVerificationError as exc:
            tls_error = str(exc)[:180]
            try:
                https_status, _, response_time_ms = _request_ip(address, domain, secure=True, verify_tls=False)
                break
            except Exception:
                continue
        except Exception as exc:
            tls_error = str(exc)[:180]

    for address in addresses:
        try:
            http_status, http_headers, elapsed = _request_ip(address, domain, secure=False)
            http_location = http_headers.get("location", "")
            response_time_ms = response_time_ms or elapsed
            break
        except Exception:
            continue

    online = https_status is not None or http_status is not None
    tls_valid = https_status is not None and not tls_error
    if not online:
        status = "offline"
        last_error = tls_error or "No HTTPS or HTTP response was received."
    elif not tls_valid:
        status = "degraded"
        last_error = tls_error or "HTTPS did not respond; HTTP is available."
    else:
        status = "online"
        last_error = ""

    return {
        "status": status,
        "http_status": https_status or http_status,
        "http_responded": http_status is not None,
        "response_time_ms": response_time_ms,
        "tls_valid": tls_valid,
        "tls_days_remaining": tls_days_remaining,
        "https_redirect": http_status is not None and 300 <= http_status < 400 and http_location.lower().startswith("https://"),
        "last_error": last_error,
    }


def _save_monitor_result(asset_id: int, result: dict[str, Any]) -> None:
    timestamp = _now()
    conditions: list[tuple[str, str, str, str]] = []
    if result["status"] == "offline":
        conditions.append(("availability", "HIGH", "Asset is unreachable", result["last_error"]))
    if result["status"] == "blocked":
        conditions.append(("target-blocked", "MEDIUM", "Monitoring blocked", result["last_error"]))
    elif result["tls_valid"] is False and result["status"] != "offline":
        conditions.append(("tls-invalid", "CRITICAL", "HTTPS certificate is invalid or unavailable", result["last_error"]))
    elif result["tls_days_remaining"] is not None and result["tls_days_remaining"] <= 14:
        conditions.append(("tls-expiry", "CRITICAL", "TLS certificate expires soon", f"Certificate expires in {result['tls_days_remaining']} days."))
    elif result["tls_days_remaining"] is not None and result["tls_days_remaining"] <= 30:
        conditions.append(("tls-expiry", "HIGH", "TLS certificate expires soon", f"Certificate expires in {result['tls_days_remaining']} days."))
    if result.get("http_responded") and not result["https_redirect"] and result["status"] != "offline":
        conditions.append(("https-redirect", "MEDIUM", "HTTP does not redirect to HTTPS", "The HTTP endpoint responded without redirecting to HTTPS."))

    with _connect() as connection:
        asset = connection.execute("SELECT name, domain FROM soc_assets WHERE id = ?", (asset_id,)).fetchone()
        if asset is None:
            return
        connection.execute(
            """UPDATE soc_assets SET status = ?, http_status = ?, response_time_ms = ?,
               tls_valid = ?, tls_days_remaining = ?, https_redirect = ?, last_error = ?, last_checked_at = ?
               WHERE id = ?""",
            (
                result["status"], result["http_status"], result["response_time_ms"],
                None if result["tls_valid"] is None else int(result["tls_valid"]),
                result["tls_days_remaining"],
                None if result["https_redirect"] is None else int(result["https_redirect"]),
                result["last_error"], timestamp, asset_id,
            ),
        )
        current_fingerprints = {condition[0] for condition in conditions}
        active_alerts = connection.execute(
            """SELECT id, fingerprint FROM soc_alerts WHERE asset_id = ?
               AND state IN ('open', 'acknowledged', 'investigating')""",
            (asset_id,),
        ).fetchall()
        for alert in active_alerts:
            if alert["fingerprint"] not in current_fingerprints:
                connection.execute(
                    "UPDATE soc_alerts SET state = 'resolved', updated_at = ? WHERE id = ?",
                    (timestamp, alert["id"]),
                )
        for fingerprint, severity, title, detail in conditions:
            existing = connection.execute(
                """SELECT id FROM soc_alerts WHERE asset_id = ? AND fingerprint = ?
                   AND state IN ('open', 'acknowledged', 'investigating')""",
                (asset_id, fingerprint),
            ).fetchone()
            if existing:
                connection.execute(
                    """UPDATE soc_alerts SET severity = ?, detail = ?, occurrences = occurrences + 1,
                       last_seen_at = ?, updated_at = ? WHERE id = ?""",
                    (severity, detail, timestamp, timestamp, existing["id"]),
                )
            else:
                connection.execute(
                    """INSERT INTO soc_alerts
                       (asset_id, fingerprint, severity, title, detail, first_seen_at, last_seen_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (asset_id, fingerprint, severity, title, detail, timestamp, timestamp, timestamp),
                )


async def check_asset(asset_id: int) -> dict[str, Any] | None:
    asset = get_asset(asset_id)
    if asset is None:
        return None
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_probe_public_domain, asset["domain"]), timeout=PROBE_DEADLINE_SECONDS
        )
    except asyncio.TimeoutError:
        result = {
            "status": "offline", "http_status": None, "response_time_ms": None,
            "tls_valid": False, "tls_days_remaining": None, "https_redirect": False,
            "last_error": f"Monitor check did not finish within {PROBE_DEADLINE_SECONDS} seconds.",
        }
    except TargetBlockedError as exc:
        result = {
            "status": "blocked", "http_status": None, "response_time_ms": None,
            "tls_valid": None, "tls_days_remaining": None, "https_redirect": None,
            "last_error": str(exc),
        }
    except Exception as exc:
        result = {
            "status": "offline", "http_status": None, "response_time_ms": None,
            "tls_valid": False, "tls_days_remaining": None, "https_redirect": False,
            "last_error": str(exc)[:180] or "Monitor check failed.",
        }
    _save_monitor_result(asset_id, result)
    return get_asset(asset_id)


async def monitor_loop() -> None:
    while True:
        try:
            due_assets = list_due_assets()
            if due_assets:
                await asyncio.gather(*(check_asset(asset["id"]) for asset in due_assets), return_exceptions=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("SOC monitoring cycle failed")
        await asyncio.sleep(MONITOR_TICK_SECONDS)