"""Search-engine plumbing: robots.txt, sitemap.xml and IndexNow pings.

Only the public landing page is meant for search results. Signed-in pages already redirect to the
sign-in page; robots.txt keeps crawlers away from them and from the API.
"""
import hashlib
import logging
import os
from pathlib import Path
from typing import List, Tuple

import httpx

logger = logging.getLogger("bharatsec.seo")

# The address every share link, profile and application already uses; other hosts point here via <link rel="canonical">.
SITE_URL = (os.getenv("BHARATSEC_SITE_URL") or "https://bharatsec.vercel.app").strip().rstrip("/")

# IndexNow (Bing, Yandex, Seznam, Naver): the key is public by design and proves we own the host.
INDEXNOW_KEY = "87ec72de68e002f74f3dffc2e747237f"
INDEXNOW_ENDPOINT = "https://api.indexnow.org/indexnow"

# Google Search Console ownership file (URL-prefix property https://bharatsec.vercel.app/). Keep it: removing it unverifies.
GOOGLE_VERIFICATION_FILE = "google8541ef115d903cf0.html"

# (path, change frequency, priority) for pages anyone can open.
PUBLIC_PAGES: List[Tuple[str, str, str]] = [("/", "weekly", "1.0")]

PRIVATE_PATHS = ["/api/", "/dashboard", "/soc", "/threat-intel", "/risk", "/cloud", "/account"]

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def robots_txt() -> str:
    lines = ["User-agent: *", "Allow: /"]
    lines += [f"Disallow: {path}" for path in PRIVATE_PATHS]
    lines += ["", f"Sitemap: {SITE_URL}/sitemap.xml", ""]
    return "\n".join(lines)


def sitemap_xml() -> str:
    urls = "".join(
        f"  <url><loc>{SITE_URL}{path}</loc><changefreq>{freq}</changefreq><priority>{priority}</priority></url>\n"
        for path, freq, priority in PUBLIC_PAGES
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls}</urlset>\n"
    )


def public_pages_fingerprint() -> str:
    """Changes whenever a public page changes, so IndexNow is pinged once per real update."""
    digest = hashlib.sha256()
    for path, _, _ in PUBLIC_PAGES:
        page = FRONTEND_DIR / ("index.html" if path == "/" else path.strip("/") + ".html")
        if page.exists():
            digest.update(page.read_bytes())
    return digest.hexdigest()


async def ping_indexnow() -> dict:
    """Tell IndexNow search engines that the public pages changed."""
    host = SITE_URL.split("://", 1)[-1]
    payload = {
        "host": host,
        "key": INDEXNOW_KEY,
        "keyLocation": f"{SITE_URL}/{INDEXNOW_KEY}.txt",
        "urlList": [f"{SITE_URL}{path}" for path, _, _ in PUBLIC_PAGES],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=8)) as client:
            response = await client.post(INDEXNOW_ENDPOINT, json=payload)
        # 200 and 202 both mean accepted; 4xx means the key or host was rejected.
        ok = response.status_code in (200, 202)
        if not ok:
            logger.warning("IndexNow ping rejected: HTTP %s", response.status_code)
        return {"status": "ok" if ok else "rejected", "http": response.status_code, "urls": len(payload["urlList"])}
    except httpx.HTTPError as exc:
        logger.warning("IndexNow ping failed: %s", type(exc).__name__)
        return {"status": "error", "detail": type(exc).__name__}
