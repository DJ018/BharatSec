"""
BharatSec: FastAPI Entry Point
"""
import sys
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

# Ensure backend package root is on path for absolute imports
BACKEND_DIR = Path(__file__).parent.resolve()
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
import os

import auth as auth_service
from config import AUTH_COOKIE_SECURE, BHARATSEC_HOST, CORS_ORIGINS, IS_LOOPBACK_HOST, IS_SERVERLESS
from engines import cloud_engine, scan_store, soc_engine, threat_intel_engine
from routers import auth as auth_router, cloud, scan, ai, soc, threat_intel

PROTECTED_PAGES = {
    "/dashboard", "/dashboard.html",
    "/soc", "/soc.html",
    "/threat-intel", "/threat-intel.html",
    "/risk", "/risk.html",
    "/cloud", "/cloud.html",
    "/account", "/account.html",
}


# Pages use a few inline scripts and handlers, Chart.js from jsDelivr and Google Fonts; nothing else is allowed.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"

CRON_SECRET = os.getenv("CRON_SECRET", "")
CRON_MIN_INTERVAL_SECONDS = 60
CRON_MAX_ASSET_CHECKS = 20


def init_databases() -> None:
    auth_service.init_db()
    soc_engine.init_db()
    threat_intel_engine.init_db()
    cloud_engine.init_db()
    scan_store.init_db()


if IS_SERVERLESS:
    # Serverless platforms may not run the lifespan hook, so tables are created at import.
    init_databases()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not IS_SERVERLESS:
        init_databases()
    # Long-running loops only work on a persistent server; serverless deployments use /api/cron/tick.
    background_tasks = [] if IS_SERVERLESS else [
        asyncio.create_task(soc_engine.monitor_loop(), name="bharatsec-soc-monitor"),
        asyncio.create_task(threat_intel_engine.feed_loop(), name="bharatsec-threat-intel-sync"),
    ]
    try:
        yield
    finally:
        for task in background_tasks:
            task.cancel()
        await asyncio.gather(*background_tasks, return_exceptions=True)

app = FastAPI(
    title="BharatSec",
    description="AI-Powered Cyber Risk Intelligence Platform",
    version="1.0.0",
    # No public API documentation pages: they only matter to developers and reveal every endpoint.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(scan.router)
app.include_router(ai.router)
app.include_router(soc.router)
app.include_router(threat_intel.router)
app.include_router(cloud.router)


@app.middleware("http")
async def enforce_authentication_and_security_headers(request, call_next):
    path = request.url.path
    is_auth_route = path.startswith("/api/auth/")
    is_public_route = (
        path in {"/", "/index.html", "/login", "/login.html", "/api/health", "/api/cron/tick"}
        or path.startswith("/assets/")
        or path.startswith("/favicon")
    )
    is_api_route = path.startswith("/api/")
    is_protected_page = path in PROTECTED_PAGES
    response = None
    if (
        request.method != "OPTIONS"
        and not is_public_route
        and not is_auth_route
        and (is_api_route or is_protected_page)
    ):
        user = auth_service.current_user(request)
        if user is None:
            if is_protected_page:
                response = RedirectResponse(
                    f"/login.html?return={quote(str(request.url), safe='')}",
                    status_code=303,
                )
            else:
                response = JSONResponse({"detail": "Sign in to continue."}, status_code=401)
        else:
            request.state.user = user

    origin = request.headers.get("origin")
    if origin and request.method not in {"GET", "HEAD", "OPTIONS"}:
        request_origin = f"{request.url.scheme}://{request.url.netloc}"
        if origin.rstrip("/") != request_origin.rstrip("/") and origin.rstrip("/") not in CORS_ORIGINS:
            response = JSONResponse({"detail": "Request origin is not allowed."}, status_code=403)

    if response is None:
        response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    if is_api_route or is_protected_page or is_auth_route:
        response.headers["Cache-Control"] = "no-store"
    elif is_public_route:
        # Revalidate pages and assets on every load (cheap 304s via ETag) so a deploy never mixes old and new CSS/JS.
        response.headers.setdefault("Cache-Control", "no-cache")
    if AUTH_COOKIE_SECURE and request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# ── Serve frontend ────────────────────────────────────────────────────────────
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/favicon.ico", include_in_schema=False)
    async def serve_favicon():
        # Pages declare the SVG mark as their icon; some browsers still ask for /favicon.ico.
        return FileResponse(str(FRONTEND_DIR / "assets" / "images" / "brand" / "bharatsec-mark.svg"), media_type="image/svg+xml")

    @app.get("/index.html", include_in_schema=False)
    async def serve_index_html():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/dashboard", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(str(FRONTEND_DIR / "dashboard.html"))

    @app.get("/dashboard.html", include_in_schema=False)
    async def serve_dashboard_html():
        return FileResponse(str(FRONTEND_DIR / "dashboard.html"))

    @app.get("/login", include_in_schema=False)
    async def serve_login():
        return FileResponse(str(FRONTEND_DIR / "login.html"))

    @app.get("/login.html", include_in_schema=False)
    async def serve_login_html():
        return FileResponse(str(FRONTEND_DIR / "login.html"))

    @app.get("/soc", include_in_schema=False)
    @app.get("/soc.html", include_in_schema=False)
    async def serve_soc():
        return FileResponse(str(FRONTEND_DIR / "soc.html"))

    @app.get("/threat-intel", include_in_schema=False)
    @app.get("/threat-intel.html", include_in_schema=False)
    async def serve_threat_intel():
        return FileResponse(str(FRONTEND_DIR / "threat-intel.html"))

    @app.get("/risk", include_in_schema=False)
    @app.get("/risk.html", include_in_schema=False)
    async def serve_risk():
        return FileResponse(str(FRONTEND_DIR / "risk.html"))

    @app.get("/cloud", include_in_schema=False)
    @app.get("/cloud.html", include_in_schema=False)
    async def serve_cloud():
        return FileResponse(str(FRONTEND_DIR / "cloud.html"))

    @app.get("/account", include_in_schema=False)
    @app.get("/account.html", include_in_schema=False)
    async def serve_account():
        return FileResponse(str(FRONTEND_DIR / "account.html"))


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "BharatSec", "version": "1.0.0"}


# ── Scheduled jobs (serverless) ───────────────────────────────────────────────
@app.api_route("/api/cron/tick", methods=["GET", "POST"])
async def cron_tick(request: Request):
    """Run due SOC checks and feed syncs. Safe to call often: work is paced through the database."""
    if CRON_SECRET and request.headers.get("authorization") != f"Bearer {CRON_SECRET}":
        return JSONResponse({"detail": "Not authorized."}, status_code=401)
    if not auth_service.claim_interval("cron-tick", CRON_MIN_INTERVAL_SECONDS):
        return {"status": "skipped", "reason": "A tick ran less than a minute ago."}
    due_assets = soc_engine.list_due_assets()[:CRON_MAX_ASSET_CHECKS]
    if due_assets:
        await asyncio.gather(*(soc_engine.check_asset(asset["id"]) for asset in due_assets), return_exceptions=True)
    feeds_synced = False
    if auth_service.claim_interval("threat-intel-sync", threat_intel_engine.SYNC_INTERVAL_SECONDS):
        await threat_intel_engine.sync_feeds()
        await threat_intel_engine.sync_breach_watches()
        feeds_synced = True
    return {"status": "ok", "assets_checked": len(due_assets), "feeds_synced": feeds_synced}


if __name__ == "__main__":
    import uvicorn
    reload_enabled = IS_LOOPBACK_HOST and os.getenv("BHARATSEC_RELOAD", "true").lower() in {"1", "true", "yes"}
    uvicorn.run(
        "main:app",
        host=BHARATSEC_HOST,
        port=int(os.getenv("PORT", "8000")),
        reload=reload_enabled,
    )
