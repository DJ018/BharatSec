"""Sign in with Google, GitHub, Facebook and Microsoft (OAuth 2.0 authorization-code flow).

A provider appears on the sign-in page only when its client ID and secret are set:
GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET, GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET,
FACEBOOK_CLIENT_ID / FACEBOOK_CLIENT_SECRET (the Facebook App ID and App Secret),
MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET.
Each provider's app must allow the redirect URL  <site>/api/auth/oauth/<provider>/callback.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

import config  # noqa: F401  (loads backend/.env before the variables below are read)

STATE_COOKIE = "bharatsec_oauth"
STATE_MAX_AGE_SECONDS = 600
HTTP_TIMEOUT = httpx.Timeout(15.0)


@dataclass(frozen=True)
class Provider:
    key: str
    label: str
    authorize_url: str
    token_url: str
    scope: str
    pkce: bool

    @property
    def client_id(self) -> str:
        return os.getenv(f"{self.key.upper()}_CLIENT_ID", "").strip()

    @property
    def client_secret(self) -> str:
        return os.getenv(f"{self.key.upper()}_CLIENT_SECRET", "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


PROVIDERS: dict[str, Provider] = {
    "google": Provider(
        "google", "Google", "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token", "openid email profile", pkce=True,
    ),
    "github": Provider(
        "github", "GitHub", "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token", "read:user user:email", pkce=True,
    ),
    "facebook": Provider(
        "facebook", "Facebook", "https://www.facebook.com/v19.0/dialog/oauth",
        "https://graph.facebook.com/v19.0/oauth/access_token", "public_profile,email", pkce=False,
    ),
    "microsoft": Provider(
        "microsoft", "Microsoft", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token", "openid email profile User.Read", pkce=True,
    ),
}


class OAuthError(Exception):
    """A sign-in attempt that failed for a reason the user can be told about."""


def configured_providers() -> list[dict[str, str]]:
    return [{"key": p.key, "label": p.label} for p in PROVIDERS.values() if p.configured]


def get_provider(key: str) -> Provider:
    provider = PROVIDERS.get(key)
    if provider is None or not provider.configured:
        raise OAuthError("That sign-in option is not available.")
    return provider


# ── Signed, short-lived state cookie (CSRF protection + PKCE verifier) ───────

def _sign(payload: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def pack_state(data: dict[str, Any], secret: str) -> str:
    # Unpadded so the cookie value has no "=" and is never quoted.
    payload = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode("utf-8")).rstrip(b"=")
    return f"{payload.decode('ascii')}.{_sign(payload, secret)}"


def unpack_state(value: str | None, secret: str) -> dict[str, Any]:
    try:
        payload, signature = (value or "").rsplit(".", 1)
        if not hmac.compare_digest(signature, _sign(payload.encode("ascii"), secret)):
            raise ValueError
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii") + b"=" * (-len(payload) % 4)))
    except (ValueError, TypeError, json.JSONDecodeError):
        raise OAuthError("Your sign-in link expired. Please try again.") from None
    if time.time() - float(data.get("ts", 0)) > STATE_MAX_AGE_SECONDS:
        raise OAuthError("Your sign-in link expired. Please try again.")
    return data


def new_state(provider: Provider, return_to: str, link_user_id: int | None) -> dict[str, Any]:
    return {
        "p": provider.key,
        "s": secrets.token_urlsafe(24),
        "v": secrets.token_urlsafe(48) if provider.pkce else "",
        "r": return_to,
        "u": link_user_id,
        "ts": time.time(),
    }


def authorize_url(provider: Provider, state: dict[str, Any], redirect_uri: str) -> str:
    params = {
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": provider.scope,
        "state": state["s"],
    }
    if provider.pkce:
        challenge = base64.urlsafe_b64encode(hashlib.sha256(state["v"].encode("ascii")).digest()).rstrip(b"=")
        params.update(code_challenge=challenge.decode("ascii"), code_challenge_method="S256")
    if provider.key == "google":
        params["prompt"] = "select_account"
    if provider.key == "microsoft":
        params["prompt"] = "select_account"
    return f"{provider.authorize_url}?{urlencode(params)}"


# ── Code exchange and profile lookup ─────────────────────────────────────────

async def fetch_profile(provider: Provider, code: str, state: dict[str, Any], redirect_uri: str) -> dict[str, Any]:
    """Exchange the authorization code and return {subject, email, email_verified, name, username_hint}."""
    form = {
        "client_id": provider.client_id,
        "client_secret": provider.client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    if provider.pkce:
        form["code_verifier"] = state["v"]
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"Accept": "application/json"}) as client:
        token_response = await client.post(provider.token_url, data=form)
        try:
            token = token_response.json()
        except ValueError:
            token = {}
        access_token = token.get("access_token") if isinstance(token, dict) else None
        if token_response.status_code >= 400 or not access_token:
            raise OAuthError(f"{provider.label} did not confirm the sign-in. Please try again.")
        auth = {"Authorization": f"Bearer {access_token}"}
        try:
            return await _PROFILE_READERS[provider.key](client, auth)
        except httpx.HTTPError as exc:
            raise OAuthError(f"Could not read your {provider.label} profile. Please try again.") from exc


async def _get_json(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> Any:
    response = await client.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


async def _google_profile(client: httpx.AsyncClient, auth: dict[str, str]) -> dict[str, Any]:
    info = await _get_json(client, "https://openidconnect.googleapis.com/v1/userinfo", auth)
    email = info.get("email") or ""
    return {
        "subject": info["sub"], "email": email, "email_verified": bool(info.get("email_verified")),
        "name": info.get("name") or "", "username_hint": email.split("@", 1)[0] if email else info.get("given_name"),
    }


async def _github_profile(client: httpx.AsyncClient, auth: dict[str, str]) -> dict[str, Any]:
    headers = {**auth, "X-GitHub-Api-Version": "2022-11-28"}
    user = await _get_json(client, "https://api.github.com/user", headers)
    emails = await _get_json(client, "https://api.github.com/user/emails", headers)
    verified = [e for e in emails if isinstance(e, dict) and e.get("verified")] if isinstance(emails, list) else []
    primary = next((e for e in verified if e.get("primary")), verified[0] if verified else None)
    return {
        "subject": user["id"], "email": primary["email"] if primary else "", "email_verified": primary is not None,
        "name": user.get("name") or user.get("login") or "", "username_hint": user.get("login"),
    }


async def _facebook_profile(client: httpx.AsyncClient, auth: dict[str, str]) -> dict[str, Any]:
    info = await _get_json(client, "https://graph.facebook.com/v19.0/me?fields=id,name,email", auth)
    email = info.get("email") or ""
    # Facebook only returns an email the person has confirmed with Facebook.
    return {
        "subject": info["id"], "email": email, "email_verified": bool(email),
        "name": info.get("name") or "", "username_hint": email.split("@", 1)[0] if email else info.get("name"),
    }


async def _microsoft_profile(client: httpx.AsyncClient, auth: dict[str, str]) -> dict[str, Any]:
    info = await _get_json(client, "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName", auth)
    email = info.get("mail") or info.get("userPrincipalName") or ""
    # Microsoft does not guarantee these addresses are verified, so they are never used to match existing accounts.
    return {
        "subject": info["id"], "email": email, "email_verified": False,
        "name": info.get("displayName") or "", "username_hint": email.split("@", 1)[0] if email else None,
    }


_PROFILE_READERS = {
    "google": _google_profile,
    "github": _github_profile,
    "facebook": _facebook_profile,
    "microsoft": _microsoft_profile,
}
