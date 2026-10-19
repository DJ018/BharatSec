"""Offline tests for async DNS and independent HTTP redirect checks."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from engines import osint_engine


class FakeResolver:
    timeout = None
    lifetime = None
    nameservers = []

    async def resolve(self, name, record_type, **kwargs):
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=reject"]
        if record_type == "TXT":
            return ["v=spf1 -all"]
        if record_type == "A":
            return ["192.0.2.10"]
        if record_type == "CNAME":
            return []
        return [f"test-{record_type.lower()}"]


class FakeAsyncClient:
    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        if url.startswith("http://"):
            return SimpleNamespace(
                status_code=301,
                headers={"location": url.replace("http://", "https://")},
                url=url,
                text="",
            )
        return SimpleNamespace(
            status_code=200,
            headers={"server": "test"},
            url=url,
            text="<html></html>",
        )


class ScanEngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_records_are_resolved_asynchronously(self):
        with patch.object(osint_engine.dns.asyncresolver, "Resolver", FakeResolver):
            results = await osint_engine.get_dns_records("example.com")
        self.assertTrue(results.a_records)
        self.assertTrue(results.has_spf)
        self.assertTrue(results.has_dmarc)

    async def test_http_redirect_is_checked_even_when_https_works(self):
        with patch.object(osint_engine.httpx, "AsyncClient", FakeAsyncClient):
            results = await osint_engine.get_web_info("example.com")
        self.assertEqual(results.status_code, 200)
        self.assertTrue(results.https_redirect)


if __name__ == "__main__":
    unittest.main()
