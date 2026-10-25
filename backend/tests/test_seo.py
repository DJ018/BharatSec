"""Search-engine plumbing: robots.txt, sitemap.xml, IndexNow and page meta tags."""
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import auth as auth_service
import main
import seo
from engines import soc_engine, threat_intel_engine, vector_knowledge
from tests.auth_helpers import authenticated_client

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


class CrawlerFilesTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)  # signed out, like a crawler

    def tearDown(self):
        self.client.close()

    def test_robots_allows_the_site_blocks_private_areas_and_names_the_sitemap(self):
        response = self.client.get("/robots.txt")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/plain"))
        body = response.text
        self.assertIn("User-agent: *", body)
        self.assertIn("Disallow: /api/", body)
        self.assertIn("Disallow: /dashboard", body)
        self.assertIn(f"Sitemap: {seo.SITE_URL}/sitemap.xml", body)
        self.assertNotIn("Disallow: /\n", body)

    def test_sitemap_is_valid_xml_listing_the_public_home_page(self):
        response = self.client.get("/sitemap.xml")
        self.assertEqual(response.status_code, 200)
        self.assertIn("xml", response.headers["content-type"])
        root = ET.fromstring(response.text)
        ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        locs = [el.text for el in root.findall("s:url/s:loc", ns)]
        self.assertEqual(locs, [f"{seo.SITE_URL}/"])

    def test_google_search_console_verification_file(self):
        response = self.client.get(f"/{seo.GOOGLE_VERIFICATION_FILE}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, f"google-site-verification: {seo.GOOGLE_VERIFICATION_FILE}")

    def test_indexnow_key_file_proves_ownership(self):
        response = self.client.get(f"/{seo.INDEXNOW_KEY}.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, seo.INDEXNOW_KEY)
        self.assertRegex(seo.INDEXNOW_KEY, r"^[0-9a-f]{32}$")


class IndexNowPingTests(unittest.TestCase):
    def setUp(self):
        self.client = authenticated_client()
        with auth_service._database() as connection:
            connection.execute("DELETE FROM app_settings WHERE key LIKE 'job:%' OR key LIKE 'change:%'")

    def tearDown(self):
        self.client.close()

    def _tick(self, ping):
        with patch.object(main, "IS_SERVERLESS", True), \
             patch.object(soc_engine, "list_due_assets", return_value=[]), \
             patch.object(threat_intel_engine, "sync_feeds", AsyncMock(return_value=[])), \
             patch.object(threat_intel_engine, "sync_breach_watches", AsyncMock()), \
             patch.object(vector_knowledge, "configured", return_value=False), \
             patch.object(seo, "ping_indexnow", ping):
            return self.client.get("/api/cron/tick").json()

    def test_pings_once_per_change_to_the_public_pages(self):
        ping = AsyncMock(return_value={"status": "ok", "http": 202, "urls": 1})
        first = self._tick(ping)
        with auth_service._database() as connection:
            connection.execute("DELETE FROM app_settings WHERE key LIKE 'job:%'")  # let the next tick run
        second = self._tick(ping)
        self.assertEqual(first["indexnow"]["status"], "ok")
        self.assertIsNone(second["indexnow"])
        ping.assert_awaited_once()

        with auth_service._database() as connection:
            connection.execute("DELETE FROM app_settings WHERE key LIKE 'job:%'")
        with patch.object(seo, "public_pages_fingerprint", return_value="new-content"):
            third = self._tick(ping)
        self.assertEqual(third["indexnow"]["status"], "ok")
        self.assertEqual(ping.await_count, 2)

    def test_ping_sends_host_key_and_urls(self):
        sent = {}

        class Response:
            status_code = 202

        class Client:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def post(self, url, json=None):
                sent.update(url=url, json=json)
                return Response()

        import asyncio
        with patch.object(seo.httpx, "AsyncClient", Client):
            result = asyncio.run(seo.ping_indexnow())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(sent["url"], seo.INDEXNOW_ENDPOINT)
        self.assertEqual(sent["json"]["key"], seo.INDEXNOW_KEY)
        self.assertEqual(sent["json"]["host"], seo.SITE_URL.split("://")[1])
        self.assertEqual(sent["json"]["urlList"], [f"{seo.SITE_URL}/"])


class PageMetaTests(unittest.TestCase):
    def test_home_page_has_canonical_social_and_structured_data(self):
        html = (FRONTEND / "index.html").read_text(encoding="utf-8")
        self.assertIn(f'<link rel="canonical" href="{seo.SITE_URL}/" />', html)
        for tag in ('property="og:title"', 'property="og:image"', 'name="twitter:card"', 'application/ld+json'):
            self.assertIn(tag, html)
        title = re.search(r"<title>(.*?)</title>", html).group(1)
        description = re.search(r'<meta name="description" content="(.*?)"', html).group(1)
        self.assertLessEqual(len(title), 65)
        self.assertLessEqual(len(description), 160)
        self.assertNotIn("noindex", html)
        self.assertTrue((FRONTEND / "assets/images/og/bharatsec-og.png").exists())

    def test_private_pages_ask_not_to_be_indexed(self):
        for page in ("login", "account", "dashboard", "soc", "threat-intel", "risk", "cloud"):
            html = (FRONTEND / f"{page}.html").read_text(encoding="utf-8")
            self.assertIn('<meta name="robots" content="noindex, follow" />', html, page)


if __name__ == "__main__":
    unittest.main()
