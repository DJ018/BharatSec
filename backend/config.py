"""
BharatSec — Configuration
"""
import os
from pathlib import Path
from urllib.parse import urlsplit


def _load_env_file():
    """Load key-value pairs from backend/.env or the repo root .env when present."""
    backend_dir = Path(__file__).resolve().parent
    env_files = [backend_dir / ".env", backend_dir.parent / ".env"]

    for env_file in env_files:
        if not env_file.exists():
            continue

        # utf-8-sig drops the byte-order mark Windows Notepad adds, which would corrupt the first key.
        for line in env_file.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]  # KEY="value" and KEY='value' are common in .env files
            os.environ.setdefault(key, value)


_load_env_file()


def _env_number(name: str, default: float, *, minimum: float, maximum: float, cast=float):
    """Read a numeric setting; fall back to the default on a typo instead of failing to boot."""
    raw = os.getenv(name, "").strip()
    try:
        value = cast(raw) if raw else default
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))

# ── Project paths ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
# Serverless platforms (Vercel) run each request in a short-lived instance with a read-only disk.
IS_SERVERLESS = bool(os.getenv("VERCEL"))
HAS_DATABASE_URL = bool((os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "").strip())
try:
    DATA_DIR.mkdir(exist_ok=True)
except OSError:
    pass  # read-only filesystem: data lives in DATABASE_URL instead

# ── API Keys (optional — set in environment variables) ────────────────────────
# Trimmed so a key pasted with stray spaces or quotes still works.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip().strip("\"'")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip().strip("\"'")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
# Tried when the main model is retired or overloaded (Google keeps these aliases pointed at current models).
GEMINI_FALLBACK_MODELS = ("gemini-flash-latest", "gemini-flash-lite-latest")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
# Seconds to wait for the provider (per read while streaming).
COPILOT_TIMEOUT = _env_number("COPILOT_TIMEOUT", 45.0, minimum=5.0, maximum=300.0)
# Longest answer BharatSec AI may write (tokens); ~2,000 tokens ≈ 1,500 words.
AI_MAX_OUTPUT_TOKENS = _env_number("AI_MAX_OUTPUT_TOKENS", 2048, minimum=256, maximum=8192, cast=int)
# Requests per user per minute across all AI endpoints (protects provider quota and cost).
AI_RATE_LIMIT_PER_MINUTE = _env_number("AI_RATE_LIMIT_PER_MINUTE", 20, minimum=1, maximum=1000, cast=int)

# ── Authentication and deployment ────────────────────────────────────────────
BHARATSEC_HOST = os.getenv("BHARATSEC_HOST", "127.0.0.1").strip()
# A serverless deployment is always public, whatever BHARATSEC_HOST says.
_is_loopback_host = BHARATSEC_HOST.lower() in {"127.0.0.1", "localhost", "::1"} and not IS_SERVERLESS
IS_LOOPBACK_HOST = _is_loopback_host
AUTH_SESSION_SECRET = os.getenv("BHARATSEC_SESSION_SECRET", "") or (
    "local-development-only-bharatsec-session-secret"
    if _is_loopback_host else ""
)
if IS_SERVERLESS and not HAS_DATABASE_URL:
    raise RuntimeError("Serverless deployments need DATABASE_URL (Postgres); local files do not persist between requests.")
# Without a configured secret, a public deployment with a database generates one and stores it there.
if not AUTH_SESSION_SECRET and not _is_loopback_host and not HAS_DATABASE_URL:
    raise RuntimeError("Set BHARATSEC_SESSION_SECRET to a random value of at least 32 characters before binding beyond localhost.")
if AUTH_SESSION_SECRET and len(AUTH_SESSION_SECRET) < 32:
    raise RuntimeError("BHARATSEC_SESSION_SECRET must contain at least 32 characters.")
AUTH_COOKIE_SECURE = os.getenv("BHARATSEC_COOKIE_SECURE", str(not _is_loopback_host)).lower() in {"1", "true", "yes"}
if not _is_loopback_host and not AUTH_COOKIE_SECURE:
    raise RuntimeError("Set BHARATSEC_COOKIE_SECURE=true when binding beyond localhost.")
AUTH_SESSION_DAYS = int(os.getenv("BHARATSEC_SESSION_DAYS", "7"))
if not 1 <= AUTH_SESSION_DAYS <= 30:
    raise RuntimeError("BHARATSEC_SESSION_DAYS must be between 1 and 30.")
ALLOW_REGISTRATION = os.getenv(
    "BHARATSEC_ALLOW_REGISTRATION",
    "true" if _is_loopback_host else "false",
).lower() in {"1", "true", "yes"}
BOOTSTRAP_USERNAME = os.getenv("BHARATSEC_BOOTSTRAP_USERNAME", "").strip()
BOOTSTRAP_PASSWORD = os.getenv("BHARATSEC_BOOTSTRAP_PASSWORD", "")
BOOTSTRAP_DISPLAY_NAME = os.getenv("BHARATSEC_BOOTSTRAP_DISPLAY_NAME", "BharatSec Administrator").strip()
if BOOTSTRAP_PASSWORD and len(BOOTSTRAP_PASSWORD) < 12:
    raise RuntimeError("BHARATSEC_BOOTSTRAP_PASSWORD must contain at least 12 characters.")
# Number of reverse proxies in front of the app that append to X-Forwarded-For.
# 0 (default) ignores the header; set it only when every request passes through those proxies.
# On Vercel every request arrives through its edge proxy, so one hop is the default there.
TRUSTED_PROXY_HOPS = int(os.getenv("BHARATSEC_TRUSTED_PROXY_HOPS", "1" if IS_SERVERLESS else "0"))
if not 0 <= TRUSTED_PROXY_HOPS <= 5:
    raise RuntimeError("BHARATSEC_TRUSTED_PROXY_HOPS must be between 0 and 5.")

# Use Gemini if key is present, else rule-based AI
USE_GEMINI = bool(GEMINI_API_KEY)
USE_OPENAI = bool(OPENAI_API_KEY) and not USE_GEMINI

# ── Scanning settings ─────────────────────────────────────────────────────────
SCAN_TIMEOUT = 45        # seconds per check (increased for real-world domains)
MAX_SCAN_WORKERS = 10

# User-Agent string for all outbound HTTP requests (many servers reject empty UA)
USER_AGENT = "BharatSec/1.0 (AI-Powered Cyber Risk Intelligence; +https://bharatsec.in)"

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "dev", "api", "admin", "portal",
    "vpn", "remote", "secure", "login", "app", "test", "staging",
    "beta", "shop", "blog", "support", "help", "docs", "status",
    "dashboard", "cdn", "assets", "static", "img", "files",
    "m", "mobile", "old", "new", "backup", "db", "database",
]

# ── HTTP Headers security checks ──────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS (HTTP Strict Transport Security)",
        "severity": "HIGH",
        "description": "Forces browsers to use HTTPS, preventing protocol downgrade attacks.",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "name": "Content Security Policy",
        "severity": "HIGH",
        "description": "Prevents XSS and data injection attacks by defining approved content sources.",
        "fix": "Implement a CSP policy. Start with: Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by controlling if the page can be embedded in iframes.",
        "fix": "Add header: X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks.",
        "fix": "Add header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "name": "Referrer Policy",
        "severity": "LOW",
        "description": "Controls how much referrer information is sent with requests.",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "name": "Permissions Policy",
        "severity": "LOW",
        "description": "Controls browser features and APIs available to the page.",
        "fix": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
}

# ── Risk scoring weights ──────────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "attack_surface":    0.25,
    "web_security":      0.25,
    "identity_exposure": 0.20,
    "configuration":     0.15,
    "credential_risk":   0.15,
}

SEVERITY_SCORE_MAP = {
    "CRITICAL": 0,
    "HIGH":     30,
    "MEDIUM":   60,
    "LOW":      85,
    "INFO":     95,
}

# ── CORS ──────────────────────────────────────────────────────────────────────
_configured_cors_origins = os.getenv("BHARATSEC_CORS_ORIGINS", "").strip()
CORS_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in _configured_cors_origins.split(",")
    if origin.strip()
] if _configured_cors_origins else (
    ["http://localhost:8000", "http://127.0.0.1:8000"] if _is_loopback_host else []
)
if "*" in CORS_ORIGINS:
    raise RuntimeError("BHARATSEC_CORS_ORIGINS must list explicit origins; wildcard CORS is not supported.")
for origin in CORS_ORIGINS:
    parsed_origin = urlsplit(origin)
    if (
        parsed_origin.scheme not in {"http", "https"}
        or not parsed_origin.netloc
        or parsed_origin.path
        or parsed_origin.query
        or parsed_origin.fragment
        or parsed_origin.username
        or parsed_origin.password
    ):
        raise RuntimeError(f"Invalid CORS origin {origin!r}; use an exact scheme and host without a path.")
