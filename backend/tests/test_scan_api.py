"""API tests for scan authorization and request handling."""
import unittest
from unittest.mock import AsyncMock, patch

from tests.auth_helpers import authenticated_client
from models.scan_models import DNSResults, SSLInfo, WHOISInfo, WebInfo
from routers import scan


class ScanApiTests(unittest.TestCase):
    def setUp(self):
        self.client = authenticated_client()

    def tearDown(self):
        self.client.close()

    def test_scan_requires_explicit_authorization(self):
        with patch.object(scan, "run_scan", new=AsyncMock()) as run_scan:
            response = self.client.post(
                "/api/scan/start",
                json={"domain": "example.com"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "You must confirm authorization to scan this target.")
        run_scan.assert_not_awaited()

    def test_scan_starts_when_authorization_is_explicit(self):
        with patch.object(scan, "run_scan", new=AsyncMock()) as run_scan:
            response = self.client.post(
                "/api/scan/start",
                json={"domain": "example.com", "authorized": True},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "started")
        run_scan.assert_awaited_once()

    def test_authorized_scan_completes_and_results_are_available(self):
        with patch.object(scan, "get_dns_records", new=AsyncMock(return_value=DNSResults())), \
             patch.object(scan, "get_whois", new=AsyncMock(return_value=WHOISInfo())), \
             patch.object(scan, "get_web_info", new=AsyncMock(return_value=WebInfo())), \
             patch.object(scan, "get_ssl_info", return_value=SSLInfo(valid=True, days_remaining=90)), \
             patch.object(scan, "enumerate_subdomains", new=AsyncMock(return_value=[])):
            start_response = self.client.post(
                "/api/scan/start",
                json={"domain": "example.com", "authorized": True},
            )

        self.assertEqual(start_response.status_code, 200)
        scan_id = start_response.json()["scan_id"]
        status_response = self.client.get(f"/api/scan/{scan_id}/status")
        results_response = self.client.get(f"/api/scan/{scan_id}/results")

        self.assertEqual(status_response.json()["status"], "complete")
        self.assertEqual(status_response.json()["progress"], 100)
        self.assertEqual(results_response.status_code, 200)
        self.assertEqual(results_response.json()["domain"], "example.com")
        recent_response = self.client.get("/api/scan/recent")
        self.assertEqual(recent_response.status_code, 200)
        self.assertIn(scan_id, [item["scan_id"] for item in recent_response.json()])


if __name__ == "__main__":
    unittest.main()