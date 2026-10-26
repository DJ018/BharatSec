"""Public status page: live component checks and the daily self-scan of BharatSec's own website."""
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import auth as auth_service
import main
from engines import scan_store, soc_engine, status_monitor, threat_intel_engine
from models.scan_models import ScanStatus
from routers import scan as scan_router


async def _finish(scan_id, domain):
    scan = scan_store.get(scan_id)
    scan.status = ScanStatus.COMPLETE
    scan.progress = 100
    scan.completed_at = "2026-10-27T03:00:00+00:00"
    scan.score.overall = 82
    scan.ssl.grade = "A"
    scan.web.headers.present = ["Strict-Transport-Security", "Content-Security-Policy"]
    scan_store.save(scan)


class StatusTests(unittest.TestCase):
    def setUp(self):
        main.init_databases()
        with scan_store._db() as connection:
            connection.execute("DELETE FROM scans WHERE substr(scan_id, 1, 9) = 'pub_self_'")
        with auth_service._database() as connection:
            connection.execute("DELETE FROM app_settings WHERE key LIKE 'job:%'")
        status_monitor._cache.update(at=0.0, payload=None)
        self.client = TestClient(main.app)  # signed out: the status page is public
        self.patches = [
            patch.object(scan_router, "_reject_non_public_target", AsyncMock()),
            patch.object(scan_router, "run_scan", _finish),
            patch.object(soc_engine, "list_due_assets", return_value=[]),
            patch.object(threat_intel_engine, "sync_feeds", AsyncMock(return_value=[])),
            patch.object(threat_intel_engine, "sync_breach_watches", AsyncMock()),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.client.close()
        status_monitor._cache.update(at=0.0, payload=None)

    def test_status_is_public_and_lists_every_component(self):
        response = self.client.get("/api/public/status")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn(body["status"], {"operational", "degraded", "down"})
        names = [item["name"] for item in body["components"]]
        self.assertEqual(names[:2], ["Website and API", "Database"])
        self.assertIn("Domain scanner", names)
        self.assertIsNone(body["self_scan"]["latest"])
        self.assertEqual(body["self_scan"]["domain"], status_monitor.SELF_DOMAIN)

    def test_status_page_is_served_signed_out(self):
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="st-components"', response.text)

    def test_daily_tick_scans_bharatsec_itself_once(self):
        with patch.object(main, "IS_SERVERLESS", True), \
             patch.object(main.vector_knowledge, "configured", return_value=False), \
             patch.object(main.seo, "ping_indexnow", AsyncMock(return_value={"status": 202})):
            first = self.client.get("/api/cron/tick").json()
            with auth_service._database() as connection:  # let the next tick run, but not the self-scan
                connection.execute("DELETE FROM app_settings WHERE key = 'job:cron-tick'")
            second = self.client.get("/api/cron/tick").json()
        self.assertEqual(first["self_scan"]["status"], "complete")
        self.assertTrue(first["self_scan"]["scan_id"].startswith("pub_self_"))
        self.assertIsNone(second["self_scan"])

        status_monitor._cache.update(at=0.0, payload=None)
        latest = self.client.get("/api/public/status").json()["self_scan"]["latest"]
        self.assertEqual((latest["score"], latest["ssl_grade"], latest["headers_present"]), (82, "A", 2))
        report = self.client.get(f"/api/public/scan/{latest['scan_id']}/report")
        self.assertEqual(report.status_code, 200)  # the full report is public

    def test_local_ticks_do_not_scan(self):
        self.assertIsNone(self.client.get("/api/cron/tick").json()["self_scan"])


if __name__ == "__main__":
    unittest.main()
