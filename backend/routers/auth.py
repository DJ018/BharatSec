"""Public account creation and server-backed browser sessions."""
from fastapi import APIRouter, HTTPException, Request, Response

import auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.get("/config")
def auth_config():
    setup = auth_service.setup_required()
    # On a brand-new install the first sign-up creates the administrator, even when sign-up is otherwise off.
    return {"registration_enabled": auth_service.ALLOW_REGISTRATION or setup, "setup_required": setup}


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
        user = auth_service.create_session(request.username, request.password, request.remember, response)
    except HTTPException as exc:
        if exc.status_code == 401:
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
    user, temporary = auth_service.admin_create_user(body.username, body.display_name, body.role)
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
