"""Public account creation and server-backed browser sessions."""
from fastapi import APIRouter, HTTPException, Request, Response

import auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.get("/config")
def auth_config():
    return {"registration_enabled": auth_service.ALLOW_REGISTRATION}


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
