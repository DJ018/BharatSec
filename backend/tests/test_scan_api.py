"""API tests for scan authorization and the create → run → status flow."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tests.auth_helpers import authenticated_client
from models.scan_models import DNSResults, SSLInfo, WHOISInfo, WebInfo
from engines import scan_store
from routers import scan


class ScanApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_patch = patch.object(scan_store, "DB_PATH", Path(self.temp_dir.name) / "scans.db")
        self.store_patch.start()
        scan_store.init_db()
        self.client = authenticated_client()

    def tearDown(self):
        self.client.close()
        self.store_patch.stop()
        self.temp_dir.cleanup()

    def test_scan_requires_explicit_authorization(self):
        with patch.object(scan, "run_scan", new=AsyncMock()) as run_scan:
            response = self.client.post(
                "/api/scan/start",
                json={"domain": "example.com"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "You must confirm authorization to scan this target.")
        run_scan.assert_not_awaited()

    def test_scan_is_created_then_run_exactly_once(self):
        with patch.object(scan, "run_scan", new=AsyncMock()) as run_scan:
            response = self.client.post(
                "/api/scan/start",
                json={"domain": "example.com", "authorized": True},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "started")
            run_scan.assert_not_awaited()  # creating a scan never runs it
            scan_id = response.json()["scan_id"]
            self.assertEqual(self.client.get(f"/api/scan/{scan_id}/status").json()["status"], "pending")
            self.client.post(f"/api/scan/{scan_id}/run")
            self.client.post(f"/api/scan/{scan_id}/run")  # duplicate run requests are ignored
        run_scan.assert_awaited_once()
        self.assertEqual(self.client.post("/api/scan/scan_missing/run").status_code, 404)

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
            run_response = self.client.post(f"/api/scan/{scan_id}/run")
        self.assertEqual(run_response.json()["status"], "complete")
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