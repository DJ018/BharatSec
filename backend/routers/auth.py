"""Public account creation, social sign-in and server-backed browser sessions."""
import html
import os
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

import auth as auth_service
import oauth

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.get("/config")
def auth_config():
    setup = auth_service.setup_required()
    # On a brand-new install the first sign-up creates the administrator, even when sign-up is otherwise off.
    return {
        "registration_enabled": auth_service.ALLOW_REGISTRATION or setup,
        "setup_required": setup,
        "providers": oauth.configured_providers(),
    }


@router.post("/register", status_code=201)
def register(request: auth_service.RegisterRequest, response: Response, http_request: Request):
    client_ip = auth_service.client_ip(http_request)
    auth_service.check_rate_limit("register", client_ip, limit=5, window_seconds=3600)
    try:
        user = auth_service.create_account(request.username, request.password, request.display_name)
        auth_service.create_session(request.username, request.password, False, response)
    except HTTPException:
        auth_service.record_rate_limited_attempt("register", client_ip, window_seconds=3600)
        raise
    auth_service.record_rate_limited_attempt("register", client_ip, window_seconds=3600)
    return {"user": user}


@router.post("/login")
def login(request: auth_service.LoginRequest, response: Response, http_request: Request):
    client_ip = auth_service.client_ip(http_request)
    login_key = f"{client_ip}:{request.username.strip().lower()}"
    auth_service.check_rate_limit("login-ip", client_ip, limit=50, window_seconds=900)
    auth_service.check_rate_limit("login-account", login_key, limit=10, window_seconds=900)
    try:
        user = auth_service.create_session(request.username, request.password, request.remember, response, request.code)
    except HTTPException as exc:
        # A correct password that still needs its second factor is not a failed attempt.
        if exc.status_code == 401 and exc.detail != auth_service.TWO_FACTOR_REQUIRED:
            auth_service.record_rate_limited_attempt("login-ip", client_ip, window_seconds=900)
            auth_service.record_rate_limited_attempt("login-account", login_key, window_seconds=900)
        raise
    # The per-IP window is not reset on success, so a valid account cannot be used to
    # wipe the failure count for guesses against other accounts.
    auth_service.clear_rate_limit("login-account", login_key)
    return {"user": user}


@router.get("/me")
def me(request: Request):
    user = auth_service.current_user(request)
    if user is None:
        raise HTTPException(401, "Sign in to continue.")
    return {"user": user}


@router.post("/logout")
def logout(request: Request, response: Response):
    auth_service.revoke_session(request.cookies.get(auth_service.SESSION_COOKIE))
    auth_service.clear_session_cookie(response)
    return {"ok": True}


# ── Account management ───────────────────────────────────────────────────────
# /api/auth/* is outside the global sign-in middleware, so every route here checks the session itself.

def _signed_in(request: Request) -> dict:
    user = auth_service.current_user(request)
    if user is None:
        raise HTTPException(401, "Sign in to continue.")
    return user


def _admin(request: Request) -> dict:
    user = _signed_in(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Only administrators can manage the team.")
    return user


@router.post("/password")
def change_password(body: auth_service.PasswordChangeRequest, request: Request):
    """Change your own password. Other sessions for your account are signed out."""
    user = _signed_in(request)
    key = f"user:{user['id']}"
    auth_service.check_rate_limit("password-change", key, limit=10, window_seconds=900)
    try:
        updated = auth_service.change_password(
            user["id"], body.current_password, body.new_password, request.cookies.get(auth_service.SESSION_COOKIE),
        )
    except HTTPException as exc:
        if exc.status_code == 401:
            auth_service.record_rate_limited_attempt("password-change", key, window_seconds=900)
        raise
    return {"user": updated}


@router.get("/users")
def list_users(request: Request):
    _admin(request)
    return {"users": auth_service.list_users()}


@router.post("/users", status_code=201)
def add_member(body: auth_service.MemberCreateRequest, request: Request):
    """Create a member. The temporary password is returned once and is never stored in plain text."""
    _admin(request)
    user, temporary = auth_service.admin_create_user(body.username, body.display_name, body.role, body.email)
    return {"user": user, "temporary_password": temporary}


@router.patch("/users/{user_id}")
def update_member(user_id: int, body: auth_service.MemberUpdateRequest, request: Request):
    actor = _admin(request)
    return {"user": auth_service.set_user_role(actor["id"], user_id, body.role)}


@router.post("/users/{user_id}/reset-password")
def reset_member_password(user_id: int, request: Request):
    actor = _admin(request)
    user, temporary = auth_service.reset_user_password(actor["id"], user_id)
    return {"user": user, "temporary_password": temporary}


@router.delete("/users/{user_id}", status_code=204)
def remove_member(user_id: int, request: Request):
    actor = _admin(request)
    auth_service.delete_user(actor["id"], user_id)


# ── Sign in with Google, GitHub, Facebook, Microsoft ─────────────────────────

PUBLIC_URL = os.getenv("BHARATSEC_PUBLIC_URL", "").strip().rstrip("/")


def _safe_return(path: str | None, default: str = "/dashboard.html") -> str:
    """Only same-site absolute paths; "//host" and "/\\host" would leave the site."""
    if not path or not path.startswith("/") or path.startswith("//") or path.startswith("/\\"):
        return default
    return path


def _redirect_uri(request: Request, provider: str) -> str:
    if PUBLIC_URL:
        base = PUBLIC_URL
    else:
        scheme = request.url.scheme
        if auth_service.TRUSTED_PROXY_HOPS:
            scheme = request.headers.get("x-forwarded-proto", scheme).split(",")[0].strip() or scheme
        base = f"{scheme}://{request.url.netloc}"
    return f"{base}/api/auth/oauth/{provider}/callback"


def _oauth_failure(message: str, linking: bool) -> RedirectResponse:
    target = (
        f"/account.html?oauth_error={quote(message)}#security" if linking
        else f"/login.html?oauth_error={quote(message)}"
    )
    response = RedirectResponse(target, status_code=303)
    response.delete_cookie(oauth.STATE_COOKIE, path="/api/auth/oauth")
    return response


@router.get("/oauth/{provider}/start")
def oauth_start(provider: str, request: Request, link: bool = False):
    """Send the browser to the provider. With link=1 the provider account is connected to the signed-in user."""
    linking_user = auth_service.current_user(request) if link else None
    if link and linking_user is None:
        return _oauth_failure("Sign in first, then connect your account.", linking=False)
    try:
        provider_config = oauth.get_provider(provider)
    except oauth.OAuthError as exc:
        return _oauth_failure(str(exc), linking=link)
    return_to = "/account.html#security" if link else _safe_return(request.query_params.get("return"))
    state = oauth.new_state(provider_config, return_to, linking_user["id"] if linking_user else None)
    response = RedirectResponse(
        oauth.authorize_url(provider_config, state, _redirect_uri(request, provider)), status_code=303
    )
    # Lax (not Strict) so the cookie comes back on the provider's top-level redirect to our callback.
    response.set_cookie(
        oauth.STATE_COOKIE, oauth.pack_state(state, auth_service._session_secret()),
        max_age=oauth.STATE_MAX_AGE_SECONDS, httponly=True, secure=auth_service.SESSION_COOKIE_SECURE,
        samesite="lax", path="/api/auth/oauth",
    )
    return response


@router.get("/oauth/{provider}/callback")
async def oauth_callback(provider: str, request: Request):
    client_ip = auth_service.client_ip(request)
    auth_service.check_rate_limit("oauth", client_ip, limit=30, window_seconds=900)
    auth_service.record_rate_limited_attempt("oauth", client_ip, window_seconds=900)
    linking = False
    try:
        state = oauth.unpack_state(request.cookies.get(oauth.STATE_COOKIE), auth_service._session_secret())
        linking = state.get("u") is not None
        if state.get("p") != provider or request.query_params.get("state") != state.get("s"):
            raise oauth.OAuthError("Your sign-in link expired. Please try again.")
        if request.query_params.get("error"):
            raise oauth.OAuthError("Sign-in was cancelled.")
        code = request.query_params.get("code")
        if not code:
            raise oauth.OAuthError("The sign-in provider did not return a code. Please try again.")
        provider_config = oauth.get_provider(provider)
        profile = await oauth.fetch_profile(provider_config, code, state, _redirect_uri(request, provider))
        # When linking, the signed state cookie (issued only to the signed-in user at /start) names the account;
        # the Strict session cookie itself is not sent on the provider's cross-site redirect back here.
        row = auth_service.oauth_sign_in(provider, profile, state.get("u"))
    except oauth.OAuthError as exc:
        return _oauth_failure(str(exc), linking)
    except HTTPException as exc:
        return _oauth_failure(str(exc.detail), linking)

    destination = _safe_return(state.get("r"))
    if not linking and row["totp_enabled"]:
        # The provider proved who this is; the authenticator code is still required before a session starts.
        pending = RedirectResponse(f"/login.html?twofactor=1&return={quote(destination, safe='')}", status_code=303)
        pending.delete_cookie(oauth.STATE_COOKIE, path="/api/auth/oauth")
        pending.set_cookie(auth_service.PENDING_2FA_COOKIE, auth_service.pack_pending_two_factor(row["id"], True),
                           max_age=auth_service.PENDING_2FA_SECONDS, httponly=True, secure=auth_service.SESSION_COOKIE_SECURE,
                           samesite="lax", path="/api/auth")
        return pending
    # The session cookie is SameSite=Strict, so it is not sent on a redirect chain that began at the provider.
    # This page finishes the sign-in with a same-site navigation instead.
    target = html.escape(destination, quote=True)
    response = HTMLResponse(
        "<!doctype html><meta charset=\"utf-8\"><title>Signing you in</title>"
        f"<meta http-equiv=\"refresh\" content=\"0;url={target}\">"
        f"<p style=\"font-family:system-ui;padding:2rem\">Signing you in… <a href=\"{target}\">Continue</a></p>"
    )
    response.delete_cookie(oauth.STATE_COOKIE, path="/api/auth/oauth")
    if not linking:
        auth_service.start_session(row, True, response)
    return response


# ── Two-factor sign-in ────────────────────────────────────────────────────────

@router.post("/2fa/setup")
def two_factor_setup(request: Request):
    """Start set-up: a new secret and otpauth:// link for the authenticator app (not active yet)."""
    user = _signed_in(request)
    return auth_service.start_two_factor_setup(user["id"])


@router.post("/2fa/enable")
def two_factor_enable(body: auth_service.TwoFactorCode, request: Request):
    """Confirm with a code from the app; returns one-time recovery codes, shown only now."""
    user = _signed_in(request)
    auth_service.check_rate_limit("2fa", str(user["id"]), limit=10, window_seconds=900)
    try:
        codes = auth_service.confirm_two_factor(user["id"], body.code)
    except HTTPException:
        auth_service.record_rate_limited_attempt("2fa", str(user["id"]), window_seconds=900)
        raise
    return {"enabled": True, "recovery_codes": codes}


@router.post("/2fa/disable")
def two_factor_disable(body: auth_service.TwoFactorCode, request: Request):
    user = _signed_in(request)
    auth_service.check_rate_limit("2fa", str(user["id"]), limit=10, window_seconds=900)
    try:
        auth_service.disable_two_factor(user["id"], body.code)
    except HTTPException:
        auth_service.record_rate_limited_attempt("2fa", str(user["id"]), window_seconds=900)
        raise
    return {"enabled": False}


@router.post("/2fa/complete")
def two_factor_complete(body: auth_service.TwoFactorCode, request: Request, response: Response):
    """Finish a Google/GitHub/Microsoft/Facebook sign-in for an account that has 2FA on."""
    pending = auth_service.unpack_pending_two_factor(request.cookies.get(auth_service.PENDING_2FA_COOKIE))
    if pending is None:
        raise HTTPException(401, "Your sign-in expired. Please sign in again.")
    user_id, remember = pending
    auth_service.check_rate_limit("2fa", str(user_id), limit=10, window_seconds=900)
    if not auth_service.verify_second_factor(user_id, body.code):
        auth_service.record_rate_limited_attempt("2fa", str(user_id), window_seconds=900)
        raise HTTPException(401, "That code is not valid. Check your authenticator app and try again.")
    response.delete_cookie(auth_service.PENDING_2FA_COOKIE, path="/api/auth")
    return {"user": auth_service.start_session(auth_service.user_row(user_id), remember, response)}


@router.get("/identities")
def identities(request: Request):
    user = _signed_in(request)
    return {"identities": auth_service.list_identities(user["id"]), "providers": oauth.configured_providers()}


@router.delete("/identities/{provider}", status_code=204)
def disconnect_identity(provider: str, request: Request):
    user = _signed_in(request)
    auth_service.unlink_identity(user["id"], provider)
