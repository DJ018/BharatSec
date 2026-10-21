"""Scheduled-job endpoint used on serverless deployments in place of background loops."""
import unittest
from unittest.mock import AsyncMock, patch

import auth as auth_service
import main
from engines import soc_engine, threat_intel_engine
from tests.auth_helpers import authenticated_client


class CronTickTests(unittest.TestCase):
    def setUp(self):
        self.client = authenticated_client()
        with auth_service._database() as connection:
            connection.execute("DELETE FROM app_settings WHERE key LIKE 'job:%'")

    def tearDown(self):
        self.client.close()

    def test_tick_checks_due_assets_and_syncs_feeds_once_per_interval(self):
        check = AsyncMock()
        sync = AsyncMock(return_value=[])
        breaches = AsyncMock()
        with patch.object(soc_engine, "list_due_assets", return_value=[{"id": 7}]), \
             patch.object(soc_engine, "check_asset", check), \
             patch.object(threat_intel_engine, "sync_feeds", sync), \
             patch.object(threat_intel_engine, "sync_breach_watches", breaches):
            first = self.client.get("/api/cron/tick")
            second = self.client.get("/api/cron/tick")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), {"status": "ok", "assets_checked": 1, "feeds_synced": True})
        self.assertEqual(second.json()["status"], "skipped")
        check.assert_awaited_once_with(7)
        sync.assert_awaited_once()
        breaches.assert_awaited_once()

    def test_tick_requires_cron_secret_when_configured(self):
        with patch.object(main, "CRON_SECRET", "s3cret"):
            self.assertEqual(self.client.get("/api/cron/tick").status_code, 401)
            with patch.object(soc_engine, "list_due_assets", return_value=[]), \
                 patch.object(threat_intel_engine, "sync_feeds", AsyncMock(return_value=[])), \
                 patch.object(threat_intel_engine, "sync_breach_watches", AsyncMock()):
                response = self.client.get("/api/cron/tick", headers={"Authorization": "Bearer s3cret"})
        self.assertEqual(response.status_code, 200)

    def test_claim_interval_allows_one_claim_per_window(self):
        self.assertTrue(auth_service.claim_interval("unit-test", 3600))
        self.assertFalse(auth_service.claim_interval("unit-test", 3600))
        self.assertTrue(auth_service.claim_interval("unit-test", 0))


if __name__ == "__main__":
    unittest.main()
