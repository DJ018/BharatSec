"""Persistent store for domain scans.

Scans used to live in process memory, which breaks on serverless platforms where every request
may run in a different instance. Each scan is now one row holding its full result as JSON.
"""
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, List, Optional

import database
from config import DATA_DIR
from models.scan_models import ScanResult, ScanStatus

DB_PATH = Path(os.getenv("SCAN_DATABASE_PATH", str(DATA_DIR / "scans.db")))


@contextmanager
def _db() -> Iterator[Any]:
    with database.transaction(DB_PATH) as connection:
        yield connection


def init_db() -> None:
    with _db() as connection:
        database.schema_lock(connection, "scans")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scans_completed ON scans(status, completed_at DESC);
            """
        )


PUBLIC_PREFIX = "pub_"  # free scans by signed-out visitors; kept out of team scan lists
_NOT_PUBLIC = "substr(scan_id, 1, 4) != 'pub_'"


def save(scan: ScanResult) -> None:
    with _db() as connection:
        connection.execute(
            """INSERT INTO scans (scan_id, domain, status, progress, started_at, completed_at, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id) DO UPDATE SET
                   status = excluded.status, progress = excluded.progress,
                   completed_at = excluded.completed_at, payload = excluded.payload""",
            (scan.scan_id, scan.domain, scan.status.value, scan.progress, scan.started_at,
             scan.completed_at, scan.model_dump_json()),
        )


def get(scan_id: str) -> Optional[ScanResult]:
    with _db() as connection:
        row = connection.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return ScanResult.model_validate_json(row["payload"]) if row else None


def claim_for_run(scan_id: str) -> bool:
    """Atomically move a pending scan to running, so a scan is only ever executed once."""
    with _db() as connection:
        cursor = connection.execute(
            "UPDATE scans SET status = ? WHERE scan_id = ? AND status = ?",
            (ScanStatus.RUNNING.value, scan_id, ScanStatus.PENDING.value),
        )
        return cursor.rowcount == 1


def recent_completed(limit: int = 20) -> List[ScanResult]:
    with _db() as connection:
        rows = connection.execute(
            f"SELECT payload FROM scans WHERE status = ? AND {_NOT_PUBLIC} ORDER BY completed_at DESC LIMIT ?",
            (ScanStatus.COMPLETE.value, limit),
        ).fetchall()
    return [ScanResult.model_validate_json(row["payload"]) for row in rows]


def score_history(domain: str, limit: int = 20) -> List[dict]:
    """Completed team scans of one domain, oldest first, for the score trend."""
    with _db() as connection:
        rows = connection.execute(
            f"SELECT scan_id, completed_at, payload FROM scans WHERE domain = ? AND status = ? AND {_NOT_PUBLIC} "
            "ORDER BY completed_at DESC LIMIT ?",
            (domain, ScanStatus.COMPLETE.value, limit),
        ).fetchall()
    history = []
    for row in reversed(rows):
        scan = ScanResult.model_validate_json(row["payload"])
        history.append({"scan_id": row["scan_id"], "completed_at": row["completed_at"], "score": scan.score.overall})
    return history


def list_summaries(limit: int = 100) -> List[dict]:
    with _db() as connection:
        rows = connection.execute(
            f"SELECT scan_id, domain, status, payload FROM scans WHERE {_NOT_PUBLIC} ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    summaries = []
    for row in rows:
        scan = ScanResult.model_validate_json(row["payload"])
        summaries.append({"scan_id": row["scan_id"], "domain": row["domain"], "status": row["status"],
                          "score": scan.score.overall})
    return summaries
