"""Accounts, roles and revocable browser sessions (SQLite locally, Postgres in production)."""
import hashlib
import hmac
import logging
import re
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Generator

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field

import database
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


@contextmanager
def _database() -> Generator[Any, None, None]:
    with database.transaction(AUTH_DB_PATH, timeout=10) as connection:
        yield connection


def init_db() -> None:
    with _database() as connection:
        database.schema_lock(connection, "auth")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
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
        # Account-management columns, added in place so existing databases keep their users.
        columns = database.table_columns(connection, "users")
        if "role" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
        if "must_change_password" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        if "last_login_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        if "email" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN email TEXT")
        connection.executescript(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users(email);
            CREATE TABLE IF NOT EXISTS oauth_identities (
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                email TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (provider, subject)
            );
            CREATE INDEX IF NOT EXISTS oauth_identities_user_idx ON oauth_identities(user_id);
            """
        )

        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count and not connection.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
            # Databases created before roles existed: the first account becomes the administrator.
            connection.execute("UPDATE users SET role = 'admin' WHERE id = (SELECT MIN(id) FROM users)")
        if user_count == 0:
            if BOOTSTRAP_USERNAME and BOOTSTRAP_PASSWORD:
                if not USERNAME_PATTERN.fullmatch(BOOTSTRAP_USERNAME):
                    raise RuntimeError("BHARATSEC_BOOTSTRAP_USERNAME must be 3–32 letters, numbers, dots, underscores, or hyphens.")
                connection.execute(
                    "INSERT INTO users (username, display_name, password_hash, created_at, role) VALUES (?, ?, ?, ?, 'admin')",
                    (
                        BOOTSTRAP_USERNAME.lower(),
                        BOOTSTRAP_DISPLAY_NAME or BOOTSTRAP_USERNAME,
                        _hash_password(BOOTSTRAP_PASSWORD),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            elif not IS_LOOPBACK_HOST:
                # First-run setup: the first person to sign up becomes the administrator.
                # Claim it right after deploying (or set BHARATSEC_BOOTSTRAP_* to pre-create the admin).
                logging.getLogger("bharatsec.auth").warning(
                    "No BharatSec accounts exist yet: the first sign-up will become the administrator."
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


_session_secret_cache: str | None = None


def _session_secret() -> str:
    """Configured secret, or one generated once and kept in the database (serverless deployments)."""
    global _session_secret_cache
    if AUTH_SESSION_SECRET:
        return AUTH_SESSION_SECRET
    if _session_secret_cache is None:
        with _database() as connection:
            row = connection.execute("SELECT value FROM app_settings WHERE key = 'session_secret'").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO app_settings (key, value) VALUES ('session_secret', ?) ON CONFLICT(key) DO NOTHING",
                    (secrets.token_urlsafe(48),),
                )
                row = connection.execute("SELECT value FROM app_settings WHERE key = 'session_secret'").fetchone()
        _session_secret_cache = row["value"]
    return _session_secret_cache


def claim_interval(job: str, interval_seconds: float) -> bool:
    """True at most once per interval across all instances; used to pace scheduled jobs."""
    key = f"job:{job}"
    now = datetime.now(timezone.utc).timestamp()
    with _database() as connection:
        database.schema_lock(connection, key)
        row = connection.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        try:
            if row is not None and now - float(row["value"]) < interval_seconds:
                return False
        except ValueError:
            pass
        connection.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(now)),
        )
    return True


def _sign_session_token(random_token: str) -> str:
    signature = hmac.new(
        _session_secret().encode("utf-8"),
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


ROLES = ("admin", "analyst")


def _user_payload(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "name": row["display_name"],
        "avatar": "👤",
        "role": row["role"],
        "email": row["email"],
        "has_password": bool(row["password_hash"]),
        "must_change_password": bool(row["must_change_password"]),
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


def setup_required() -> bool:
    """True on a brand-new install: no accounts exist yet, so the first sign-up creates the admin."""
    with _database() as connection:
        return connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None


def create_account(username: str, password: str, display_name: str) -> dict[str, Any]:
    normalized = username.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise HTTPException(422, "Username must be 3–32 characters using letters, numbers, dots, underscores, or hyphens.")
    if not 12 <= len(password) <= 256:
        raise HTTPException(422, "Password must be between 12 and 256 characters.")

    try:
        with _database() as connection:
            # Serialise sign-ups so two people can't both claim a brand-new install as admin.
            database.schema_lock(connection, "auth-account-create")
            has_users = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
            if has_users and not ALLOW_REGISTRATION:
                raise HTTPException(403, "Public registration is disabled. Contact your BharatSec administrator.")
            # The very first account on a fresh install administers the workspace.
            role = "analyst" if has_users else "admin"
            new_id = connection.execute(
                "INSERT INTO users (username, display_name, password_hash, created_at, role) VALUES (?, ?, ?, ?, ?) RETURNING id",
                (
                    normalized,
                    display_name.strip() or normalized,
                    _hash_password(password),
                    datetime.now(timezone.utc).isoformat(),
                    role,
                ),
            ).fetchone()[0]
            row = connection.execute("SELECT * FROM users WHERE id = ?", (new_id,)).fetchone()
    except database.IntegrityError as exc:
        raise HTTPException(409, "An account with that username already exists.") from exc

    return _user_payload(row)


def create_session(username: str, password: str, remember: bool, response: Response) -> dict[str, Any]:
    normalized = username.strip().lower()
    with _database() as connection:
        row = connection.execute("SELECT * FROM users WHERE username = ?", (normalized,)).fetchone()

    # Accounts created through Google/GitHub/etc. have no password; check a dummy hash so timing matches.
    stored_hash = row["password_hash"] if row is not None and row["password_hash"] else _DUMMY_PASSWORD_HASH
    password_valid = _verify_password(password, stored_hash)
    if row is None or not row["password_hash"] or not password_valid:
        raise HTTPException(401, "Incorrect username or password.")
    return start_session(row, remember, response)


def start_session(row: Any, remember: bool, response: Response) -> dict[str, Any]:
    """Issue a session cookie for an already-authenticated user row."""
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
        connection.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now.isoformat(), row["id"]))

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


# ── Account management ───────────────────────────────────────────────────────

def _token_hash(token: str | None) -> str:
    return hashlib.sha256((token or "").encode("ascii", errors="ignore")).hexdigest()


def _temporary_password() -> str:
    """A one-time password an administrator hands over; the member must replace it at first sign-in."""
    return secrets.token_urlsafe(12)  # 16 URL-safe characters, ~96 bits


def _validate_new_password(password: str) -> None:
    if not 12 <= len(password) <= 256:
        raise HTTPException(422, "Password must be between 12 and 256 characters.")


def change_password(user_id: int, current_password: str, new_password: str, keep_token: str | None) -> dict[str, Any]:
    """Change the signed-in user's password and sign out their other sessions.

    Accounts created through a sign-in provider have no password yet; they set one without a current password.
    """
    _validate_new_password(new_password)
    with _database() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None or (row["password_hash"] and not _verify_password(current_password, row["password_hash"])):
            raise HTTPException(401, "Your current password is incorrect.")
        if _verify_password(new_password, row["password_hash"]):
            raise HTTPException(422, "Choose a password different from your current one.")
        connection.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
            (_hash_password(new_password), user_id),
        )
        connection.execute(
            "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
            (user_id, _token_hash(keep_token)),
        )
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _user_payload(row)


def list_users() -> list[dict[str, Any]]:
    with _database() as connection:
        rows = connection.execute(
            "SELECT id, username, display_name, role, email, must_change_password, created_at, last_login_at"
            " FROM users ORDER BY id"
        ).fetchall()
        linked: dict[int, list[str]] = {}
        for identity in connection.execute("SELECT user_id, provider FROM oauth_identities ORDER BY provider").fetchall():
            linked.setdefault(identity["user_id"], []).append(identity["provider"])
    return [
        {
            "id": row["id"], "username": row["username"], "name": row["display_name"], "role": row["role"],
            "email": row["email"], "providers": linked.get(row["id"], []),
            "must_change_password": bool(row["must_change_password"]),
            "created_at": row["created_at"], "last_login_at": row["last_login_at"],
        }
        for row in rows
    ]


def admin_create_user(username: str, display_name: str, role: str, email: str = "") -> tuple[dict[str, Any], str]:
    """Create a member with a temporary password (returned once) they must change at first sign-in.

    With an email, the member can instead sign in with a Google/GitHub/Facebook/Microsoft account that has
    that verified email; a blank username is generated from the email.
    """
    if role not in ROLES:
        raise HTTPException(422, "Role must be admin or analyst.")
    normalized_email = _normalize_email(email)
    if email.strip() and not normalized_email:
        raise HTTPException(422, "Enter a valid email address.")
    temporary = _temporary_password()
    try:
        with _database() as connection:
            if username.strip():
                normalized = username.strip().lower()
                if not USERNAME_PATTERN.fullmatch(normalized):
                    raise HTTPException(
                        422, "Username must be 3–32 characters using letters, numbers, dots, underscores, or hyphens."
                    )
            elif normalized_email:
                normalized = _available_username(connection, normalized_email.split("@", 1)[0], display_name)
            else:
                raise HTTPException(422, "Enter a username or an email address.")
            if normalized_email and connection.execute(
                "SELECT 1 FROM users WHERE email = ?", (normalized_email,)
            ).fetchone():
                raise HTTPException(409, "Another account already uses that email address.")
            new_id = connection.execute(
                """INSERT INTO users (username, display_name, password_hash, created_at, role, must_change_password, email)
                   VALUES (?, ?, ?, ?, ?, 1, ?) RETURNING id""",
                (normalized, display_name.strip() or normalized, _hash_password(temporary),
                 datetime.now(timezone.utc).isoformat(), role, normalized_email),
            ).fetchone()[0]
            row = connection.execute("SELECT * FROM users WHERE id = ?", (new_id,)).fetchone()
    except database.IntegrityError as exc:
        raise HTTPException(409, "An account with that username already exists.") from exc
    return _user_payload(row), temporary


def _target_user(connection: Any, user_id: int) -> Any:
    row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Team member not found.")
    return row


def _ensure_another_admin(connection: Any, user_id: int) -> None:
    others = connection.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?", (user_id,)).fetchone()[0]
    if others == 0:
        raise HTTPException(409, "BharatSec needs at least one administrator. Make someone else an admin first.")


def set_user_role(actor_id: int, user_id: int, role: str) -> dict[str, Any]:
    if role not in ROLES:
        raise HTTPException(422, "Role must be admin or analyst.")
    with _database() as connection:
        row = _target_user(connection, user_id)
        if row["role"] == "admin" and role != "admin":
            if user_id == actor_id:
                raise HTTPException(409, "You can't remove your own administrator access.")
            _ensure_another_admin(connection, user_id)
        connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        row = _target_user(connection, user_id)
    return _user_payload(row)


def reset_user_password(actor_id: int, user_id: int) -> tuple[dict[str, Any], str]:
    """Issue a new temporary password and sign the member out everywhere."""
    if user_id == actor_id:
        raise HTTPException(409, "Use Change password to update your own password.")
    temporary = _temporary_password()
    with _database() as connection:
        _target_user(connection, user_id)
        connection.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
            (_hash_password(temporary), user_id),
        )
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        row = _target_user(connection, user_id)
    return _user_payload(row), temporary


def delete_user(actor_id: int, user_id: int) -> None:
    if user_id == actor_id:
        raise HTTPException(409, "You can't remove your own account.")
    with _database() as connection:
        row = _target_user(connection, user_id)
        if row["role"] == "admin":
            _ensure_another_admin(connection, user_id)
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))  # sessions cascade


# ── Sign in with Google, GitHub, Facebook, Microsoft ─────────────────────────

EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


def _normalize_email(email: str | None) -> str | None:
    value = (email or "").strip().lower()
    return value if len(value) <= 254 and EMAIL_PATTERN.fullmatch(value) else None


def _username_base(text: str) -> str:
    """Turn a profile name, handle or email local part into a valid username stem."""
    base = re.sub(r"[^a-z0-9_.-]+", ".", text.strip().lower())
    base = re.sub(r"[._-]{2,}", ".", base).strip("._-")
    return base[:28]


def _available_username(connection: Any, *candidates: str | None) -> str:
    """First free username built from the candidates: "priya", then "priya2", "priya3", and so on."""
    stems = [stem for stem in (_username_base(c or "") for c in candidates) if len(stem) >= 3] or ["user"]
    for stem in stems:
        if not connection.execute("SELECT 1 FROM users WHERE username = ?", (stem,)).fetchone():
            return stem
    for number in range(2, 1000):
        candidate = f"{stems[0]}{number}"
        if not connection.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone():
            return candidate
    return f"{stems[0][:20]}.{secrets.token_hex(4)}"


def oauth_sign_in(provider: str, profile: dict[str, Any], link_user_id: int | None = None) -> Any:
    """Find or create the account for a provider identity and return its user row.

    Order: an identity already linked; the signed-in user who asked to link it; an account whose email matches
    the provider's verified email; otherwise a new account (first-run setup or open registration) whose
    username is generated from the profile.
    """
    subject = str(profile["subject"])
    email = _normalize_email(profile.get("email")) if profile.get("email_verified") else None
    now = datetime.now(timezone.utc).isoformat()
    with _database() as connection:
        database.schema_lock(connection, "auth-account-create")
        identity = connection.execute(
            "SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?", (provider, subject)
        ).fetchone()
        if identity is not None:
            if link_user_id is not None and identity["user_id"] != link_user_id:
                raise HTTPException(409, "That account is already connected to a different BharatSec user.")
            user_id = identity["user_id"]
        elif link_user_id is not None:
            if not connection.execute("SELECT 1 FROM users WHERE id = ?", (link_user_id,)).fetchone():
                raise HTTPException(404, "Account not found.")
            if connection.execute(
                "SELECT 1 FROM oauth_identities WHERE provider = ? AND user_id = ?", (provider, link_user_id)
            ).fetchone():
                raise HTTPException(409, "Disconnect your current account for this provider before connecting another.")
            user_id = link_user_id
        else:
            match = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone() if email else None
            if match is not None:
                user_id = match["id"]
            else:
                has_users = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
                if has_users and not ALLOW_REGISTRATION:
                    raise HTTPException(
                        403,
                        "No BharatSec account uses this email. Ask your administrator to add you with this email address.",
                    )
                name = (profile.get("name") or "").strip()[:80]
                username = _available_username(
                    connection, profile.get("username_hint"), email.split("@", 1)[0] if email else None, name,
                )
                user_id = connection.execute(
                    """INSERT INTO users (username, display_name, password_hash, created_at, role, email)
                       VALUES (?, ?, '', ?, ?, ?) RETURNING id""",
                    (username, name or username, now, "analyst" if has_users else "admin", email),
                ).fetchone()[0]
        if identity is None:
            connection.execute(
                "INSERT INTO oauth_identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)",
                (provider, subject, user_id, email, now),
            )
        # A member who was given a temporary password but signs in with a provider never needs it: discard it
        # so it cannot be used later, and don't force a password change.
        connection.execute(
            "UPDATE users SET password_hash = '', must_change_password = 0 WHERE id = ? AND must_change_password = 1",
            (user_id,),
        )
        if email:
            # Keep a verified email on the account so any provider using that email can sign in to it.
            connection.execute(
                "UPDATE users SET email = ? WHERE id = ? AND email IS NULL"
                " AND NOT EXISTS (SELECT 1 FROM users other WHERE other.email = ?)",
                (email, user_id, email),
            )
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_identities(user_id: int) -> list[dict[str, Any]]:
    with _database() as connection:
        rows = connection.execute(
            "SELECT provider, email, created_at FROM oauth_identities WHERE user_id = ? ORDER BY provider", (user_id,)
        ).fetchall()
    return [{"provider": row["provider"], "email": row["email"], "connected_at": row["created_at"]} for row in rows]


def unlink_identity(user_id: int, provider: str) -> None:
    with _database() as connection:
        row = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Account not found.")
        others = connection.execute(
            "SELECT COUNT(*) FROM oauth_identities WHERE user_id = ? AND provider != ?", (user_id, provider)
        ).fetchone()[0]
        if not row["password_hash"] and others == 0:
            raise HTTPException(409, "Set a password first, or you would have no way to sign in.")
        connection.execute("DELETE FROM oauth_identities WHERE user_id = ? AND provider = ?", (user_id, provider))


class PasswordChangeRequest(BaseModel):
    current_password: str = Field("", max_length=256)
    new_password: str = Field(..., min_length=12, max_length=256)


class MemberCreateRequest(BaseModel):
    username: str = Field("", max_length=32)
    display_name: str = Field("", max_length=80)
    email: str = Field("", max_length=254)
    role: str = Field("analyst", pattern="^(admin|analyst)$")


class MemberUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst)$")


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
