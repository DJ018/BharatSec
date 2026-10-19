"""SQLite-backed accounts and revocable browser sessions."""
import hashlib
import hmac
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Generator

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field

from config import (
    ALLOW_REGISTRATION,
    AUTH_COOKIE_SECURE,
    AUTH_SESSION_DAYS,
    AUTH_SESSION_SECRET,
    BOOTSTRAP_DISPLAY_NAME,
    BOOTSTRAP_PASSWORD,
    BOOTSTRAP_USERNAME,
    DATA_DIR,
    IS_LOOPBACK_HOST,
    TRUSTED_PROXY_HOPS,
)

AUTH_DB_PATH = DATA_DIR / "auth.db"
SESSION_COOKIE = "bharatsec_session"
SESSION_COOKIE_SECURE = AUTH_COOKIE_SECURE
PASSWORD_ITERATIONS = 310_000
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(AUTH_DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _database() -> Generator[sqlite3.Connection, None, None]:
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
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS auth_rate_limits (
                scope TEXT NOT NULL,
                identifier_hash TEXT NOT NULL,
                window_started REAL NOT NULL,
                attempts INTEGER NOT NULL,
                PRIMARY KEY (scope, identifier_hash)
            );
            """
        )
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            if BOOTSTRAP_USERNAME and BOOTSTRAP_PASSWORD:
                if not USERNAME_PATTERN.fullmatch(BOOTSTRAP_USERNAME):
                    raise RuntimeError("BHARATSEC_BOOTSTRAP_USERNAME must be 3–32 letters, numbers, dots, underscores, or hyphens.")
                connection.execute(
                    "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (
                        BOOTSTRAP_USERNAME.lower(),
                        BOOTSTRAP_DISPLAY_NAME or BOOTSTRAP_USERNAME,
                        _hash_password(BOOTSTRAP_PASSWORD),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            elif not IS_LOOPBACK_HOST:
                raise RuntimeError(
                    "No BharatSec accounts exist. Set BHARATSEC_BOOTSTRAP_USERNAME and "
                    "BHARATSEC_BOOTSTRAP_PASSWORD before first production startup."
                )


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


_DUMMY_PASSWORD_HASH = _hash_password("invalid-account-password")


def _sign_session_token(random_token: str) -> str:
    signature = hmac.new(
        AUTH_SESSION_SECRET.encode("utf-8"),
        random_token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{random_token}.{signature}"


def _valid_session_token(token: str) -> bool:
    try:
        random_token, signature = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = _sign_session_token(random_token).rsplit(".", 1)[1]
    return hmac.compare_digest(signature, expected)


def _user_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "name": row["display_name"],
        "avatar": "👤",
    }


def client_ip(request: Request) -> str:
    """Return the caller's address, honouring X-Forwarded-For only from trusted proxies.

    Each trusted proxy appends the address it received the request from, so the client
    is the Nth entry from the right; entries further left are caller-controlled.
    """
    peer = request.client.host if request.client else "unknown"
    if TRUSTED_PROXY_HOPS == 0:
        return peer
    forwarded = [part.strip() for part in request.headers.get("x-forwarded-for", "").split(",") if part.strip()]
    if len(forwarded) < TRUSTED_PROXY_HOPS:
        return peer
    return forwarded[-TRUSTED_PROXY_HOPS]


def _rate_limit_key(scope: str, identifier: str) -> str:
    return hashlib.sha256(f"{scope}\0{identifier}".encode("utf-8")).hexdigest()


def check_rate_limit(scope: str, identifier: str, *, limit: int, window_seconds: int) -> None:
    now = datetime.now(timezone.utc).timestamp()
    key = _rate_limit_key(scope, identifier)
    with _database() as connection:
        row = connection.execute(
            "SELECT window_started, attempts FROM auth_rate_limits WHERE scope = ? AND identifier_hash = ?",
            (scope, key),
        ).fetchone()
        if row and now - row["window_started"] < window_seconds and row["attempts"] >= limit:
            raise HTTPException(429, "Too many authentication attempts. Please wait and try again.")
        if row is None or now - row["window_started"] >= window_seconds:
            connection.execute(
                """
                INSERT INTO auth_rate_limits (scope, identifier_hash, window_started, attempts)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(scope, identifier_hash)
                DO UPDATE SET window_started = excluded.window_started, attempts = 0
                """,
                (scope, key, now),
            )


def record_rate_limited_attempt(scope: str, identifier: str, *, window_seconds: int) -> None:
    now = datetime.now(timezone.utc).timestamp()
    key = _rate_limit_key(scope, identifier)
    with _database() as connection:
        connection.execute(
            """
            INSERT INTO auth_rate_limits (scope, identifier_hash, window_started, attempts)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(scope, identifier_hash)
            DO UPDATE SET
                window_started = CASE
                    WHEN excluded.window_started - auth_rate_limits.window_started >= ? THEN excluded.window_started
                    ELSE auth_rate_limits.window_started
                END,
                attempts = CASE
                    WHEN excluded.window_started - auth_rate_limits.window_started >= ? THEN 1
                    ELSE auth_rate_limits.attempts + 1
                END
            """,
            (scope, key, now, window_seconds, window_seconds),
        )


def clear_rate_limit(scope: str, identifier: str) -> None:
    with _database() as connection:
        connection.execute(
            "DELETE FROM auth_rate_limits WHERE scope = ? AND identifier_hash = ?",
            (scope, _rate_limit_key(scope, identifier)),
        )


def create_account(username: str, password: str, display_name: str) -> dict[str, Any]:
    if not ALLOW_REGISTRATION:
        raise HTTPException(403, "Public registration is disabled. Contact your BharatSec administrator.")
    normalized = username.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise HTTPException(422, "Username must be 3–32 characters using letters, numbers, dots, underscores, or hyphens.")
    if not 12 <= len(password) <= 256:
        raise HTTPException(422, "Password must be between 12 and 256 characters.")

    try:
        with _database() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (
                    normalized,
                    display_name.strip() or normalized,
                    _hash_password(password),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            row = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "An account with that username already exists.") from exc

    return _user_payload(row)


def create_session(username: str, password: str, remember: bool, response: Response) -> dict[str, Any]:
    normalized = username.strip().lower()
    with _database() as connection:
        row = connection.execute("SELECT * FROM users WHERE username = ?", (normalized,)).fetchone()

    password_valid = _verify_password(
        password,
        row["password_hash"] if row is not None else _DUMMY_PASSWORD_HASH,
    )
    if row is None or not password_valid:
        raise HTTPException(401, "Incorrect username or password.")

    now = datetime.now(timezone.utc)
    session_seconds = AUTH_SESSION_DAYS * 24 * 60 * 60 if remember else 24 * 60 * 60
    expires = now + timedelta(seconds=session_seconds)
    token = _sign_session_token(secrets.token_urlsafe(32))
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with _database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now.isoformat(),))
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token_hash, row["id"], expires.isoformat(), now.isoformat()),
        )

    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=session_seconds if remember else None,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return _user_payload(row)


def get_user(token: str | None) -> dict[str, Any] | None:
    if not token or not _valid_session_token(token):
        return None
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with _database() as connection:
        row = connection.execute(
            """
            SELECT users.* FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (token_hash, now),
        ).fetchone()
    return _user_payload(row) if row else None


def revoke_session(token: str | None) -> None:
    if not token:
        return
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
    with _database() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=12, max_length=256)
    display_name: str = Field("", max_length=80)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)
    password: str = Field(..., min_length=1, max_length=256)
    remember: bool = False


def current_user(request: Request) -> dict[str, Any] | None:
    return get_user(request.cookies.get(SESSION_COOKIE))


init_db()
