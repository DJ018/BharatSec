"""Threat Intel API tests use temporary databases and mocked providers."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from engines import soc_engine, threat_intel_engine as intel
from tests.auth_helpers import authenticated_client


class ThreatIntelApiTests(unittest.TestCase):
    def test_large_feed_import_is_persisted_as_one_successful_sync(self):
        payload = {
            "vulnerabilities": [
                {
                    "cveID": f"CVE-2025-{index:04d}",
                    "vulnerabilityName": f"Test vulnerability {index}",
                    "dateAdded": "2025-01-03",
                }
                for index in range(1000)
            ],
        }

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return payload

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, *args, **kwargs):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(intel.httpx, "AsyncClient", return_value=FakeClient()):
                intel.init_db()
                result = asyncio.run(intel._sync_one_feed("cisa_kev"))
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["fetched_count"], 1000)
                self.assertEqual(len(intel.list_indicators(limit=1000)), 1000)

    def test_feed_parsers_normalize_cisa_and_urlhaus_records(self):
        kev = intel._cisa_records({
            "vulnerabilities": [{
                "cveID": "CVE-2025-12345",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Remote code execution",
                "dateAdded": "2025-01-03",
            }],
        })
        urlhaus = intel._urlhaus_records({
            "urls": {
                "1": {
                    "url": "http://malware.example/payload",
                    "threat": "malware_download",
                    "url_status": "online",
                    "tags": ["loader"],
                },
            },
        })
        self.assertEqual((kev[0]["ioc"], kev[0]["type"]), ("CVE-2025-12345", "cve"))
        self.assertEqual((urlhaus[0]["ioc"], urlhaus[0]["type"]), ("http://malware.example/payload", "url"))

    def test_urlhaus_json_recent_lists_are_flattened(self):
        # json_recent maps each URL id to a list of entries.
        records = intel._urlhaus_records({
            "3445437": [{"url": "http://malware.example/a", "url_status": "online", "threat": "malware_download"}],
            "3445438": [
                {"url": "https://malware.example/b", "url_status": "offline", "tags": ["elf"]},
                {"url": "https://malware.example/c", "url_status": "online"},
            ],
        })
        self.assertEqual(
            [record["ioc"] for record in records],
            ["http://malware.example/a", "https://malware.example/b", "https://malware.example/c"],
        )
        self.assertEqual(records[1]["tags"], ["elf"])

    def test_unrecognized_feed_payload_is_reported_as_error(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"query_status": "unexpected", "data": "changed"}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, *args, **kwargs):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(intel.httpx, "AsyncClient", return_value=FakeClient()):
                intel.init_db()
                result = asyncio.run(intel._sync_one_feed("urlhaus"))
        self.assertEqual(result["status"], "error")
        self.assertIn("unrecognized format", result["detail"])

    def test_breach_check_parses_hibp_json(self):
        responses = [
            {"alice": ["Adobe", "Gawker"], "bob": ["Adobe"], "carol": ["LinkedIn"]},
            {"alice": ["Adobe"]},
        ]

        class FakeResponse:
            status_code = 200

            def __init__(self, payload):
                self.payload = payload

            def raise_for_status(self):
                return None

            def json(self):
                return self.payload

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, *args, **kwargs):
                return FakeResponse(responses.pop(0))

        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(intel, "HIBP_API_KEY", "test-key"), \
                 patch.object(intel.httpx, "AsyncClient", side_effect=lambda *a, **k: FakeClient()):
                intel.init_db()
                first = asyncio.run(intel.check_breach_domain("example.com"))
                exposures = {row["breach_name"]: row["affected_accounts"] for row in intel.list_breach_exposures()}
                second = asyncio.run(intel.check_breach_domain("example.com"))
                remaining = {row["breach_name"]: row["affected_accounts"] for row in intel.list_breach_exposures()}

        self.assertEqual((first["breach_count"], first["affected_accounts"]), (3, 3))
        self.assertEqual(exposures, {"Adobe": 2, "Gawker": 1, "LinkedIn": 1})
        self.assertEqual(second["breach_count"], 1)
        self.assertEqual(remaining, {"Adobe": 1})

    def test_indicator_triage_enrichment_and_asset_correlation(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(soc_engine, "DB_PATH", Path(folder) / "soc.db"):
                with authenticated_client() as client:
                    soc_engine.create_asset("example.com", "Example", 300)
                    created = client.post(
                        "/api/threat-intel/indicators",
                        json={
                            "ioc": "https://portal.example.com/login",
                            "title": "Credential phishing page",
                            "threat_type": "phishing",
                            "confidence": 88,
                            "tags": ["credential-theft"],
                        },
                    )
                    self.assertEqual(created.status_code, 201)
                    self.assertEqual(created.json()["ioc_type"], "url")
                    indicator_id = created.json()["id"]

                    with patch.object(intel, "_local_enrichment", return_value={"method": "local", "resolved_ips": ["203.0.113.8"]}):
                        enriched = client.post(f"/api/threat-intel/indicators/{indicator_id}/enrich")
                    self.assertEqual(enriched.status_code, 200)
                    self.assertEqual(enriched.json()["enrichment"]["method"], "local")

                    triaged = client.patch(
                        f"/api/threat-intel/indicators/{indicator_id}",
                        json={"status": "investigating"},
                    )
                    self.assertEqual(triaged.json()["status"], "investigating")
                    results = client.get("/api/threat-intel/indicators?query=portal&status=investigating")
                    self.assertEqual(len(results.json()), 1)

                    matches = client.get("/api/threat-intel/correlations").json()
                    self.assertEqual(len(matches), 1)
                    self.assertEqual(matches[0]["matches"][0]["asset_domain"], "example.com")
                    self.assertEqual(client.get("/api/threat-intel/overview").json()["environment_matches"], 1)

    def test_feed_sync_route_uses_provider_results(self):
        results = [{"key": "cisa_kev", "status": "ok", "fetched_count": 1, "detail": "Imported one."}]
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(intel, "sync_feeds", new=AsyncMock(return_value=results)):
                with authenticated_client() as client:
                    response = client.post("/api/threat-intel/feeds/sync")
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), results)

    def test_breach_watch_requires_provider_key(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(intel, "HIBP_API_KEY", ""):
                with authenticated_client() as client:
                    response = client.post(
                        "/api/threat-intel/breach-watches",
                        json={"domain": "example.com", "authorized": True},
                    )
                    self.assertEqual(response.status_code, 503)
                    self.assertIn("HIBP_API_KEY", response.json()["detail"])

    def test_indicator_validation_rejects_malformed_iocs(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"):
                with authenticated_client() as client:
                    malformed_hash = client.post(
                        "/api/threat-intel/indicators",
                        json={"ioc": "not-a-hash", "ioc_type": "sha256"},
                    )
                    malformed_url = client.post(
                        "/api/threat-intel/indicators",
                        json={"ioc": "javascript:alert(1)", "ioc_type": "url"},
                    )
                    self.assertEqual(malformed_hash.status_code, 422)
                    self.assertEqual(malformed_url.status_code, 422)


if __name__ == "__main__":
    unittest.main()