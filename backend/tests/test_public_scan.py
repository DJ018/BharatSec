"""Free scans for signed-out visitors: no account needed, rate limited, isolated from team scans."""
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import auth as auth_service
import main
from engines import scan_store
from models.scan_models import ScanStatus
from routers import scan as scan_router
from tests.auth_helpers import authenticated_client


async def _finish(scan_id, domain):
    scan = scan_store.get(scan_id)
    scan.status = ScanStatus.COMPLETE
    scan.progress = 100
    scan.completed_at = "2026-10-26T00:00:00+00:00"
    scan_store.save(scan)


class PublicScanTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)  # signed out
        with auth_service._database() as connection:
            connection.execute("DELETE FROM auth_rate_limits WHERE scope LIKE 'public-scan%'")
        self.patches = [
            patch.object(scan_router, "_reject_non_public_target", AsyncMock()),
            patch.object(scan_router, "run_scan", _finish),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.client.close()

    def _start(self, domain="example.com", authorized=True):
        return self.client.post("/api/public/scan/start", json={"domain": domain, "authorized": authorized})

    def test_signed_out_visitor_can_run_a_scan_and_read_the_report(self):
        started = self._start()
        self.assertEqual(started.status_code, 200, started.text)
        scan_id = started.json()["scan_id"]
        self.assertTrue(scan_id.startswith("pub_"))
        self.assertEqual(self.client.post(f"/api/public/scan/{scan_id}/run").json()["status"], "complete")
        self.assertEqual(self.client.get(f"/api/public/scan/{scan_id}/status").json()["progress"], 100)
        report = self.client.get(f"/api/public/scan/{scan_id}/report")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json()["domain"], "example.com")

    def test_authorization_must_be_confirmed(self):
        self.assertEqual(self._start(authorized=False).status_code, 400)

    def test_free_scans_are_limited_per_visitor(self):
        for _ in range(scan_router.PUBLIC_SCANS_PER_VISITOR):
            self.assertEqual(self._start().status_code, 200)
        limited = self._start()
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Sign in", limited.json()["detail"])

    def test_invalid_domain_does_not_use_up_the_allowance(self):
        for _ in range(scan_router.PUBLIC_SCANS_PER_VISITOR + 1):
            self.assertEqual(self._start("not a domain").status_code, 422)
        self.assertEqual(self._start().status_code, 200)

    def test_public_endpoints_never_serve_team_scans(self):
        team = authenticated_client()
        try:
            scan_id = team.post("/api/scan/start", json={"domain": "example.org", "authorized": True}).json()["scan_id"]
        finally:
            team.close()
        for path in (f"/api/public/scan/{scan_id}/status", f"/api/public/scan/{scan_id}/report"):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_free_scans_stay_out_of_team_scan_lists(self):
        scan_id = self._start("free-visitor.example").json()["scan_id"]
        self.client.post(f"/api/public/scan/{scan_id}/run")
        team = authenticated_client()
        try:
            recent = team.get("/api/scan/recent").json()
            listed = team.get("/api/scan/").json()
        finally:
            team.close()
        self.assertNotIn(scan_id, [scan["scan_id"] for scan in recent])
        self.assertNotIn(scan_id, [scan["scan_id"] for scan in listed])

    def test_report_page_and_sample_are_served(self):
        page = self.client.get("/report")
        self.assertEqual(page.status_code, 200)
        self.assertIn('content="noindex, follow"', page.text)
        sample = self.client.get("/assets/data/sample-report.json")
        self.assertEqual(sample.status_code, 200)
        self.assertEqual(sample.json()["status"], "complete")


class ScoreHistoryTests(unittest.TestCase):
    def _saved(self, scan_id, domain, score, completed_at):
        from models.scan_models import ScanResult
        scan = ScanResult(scan_id=scan_id, domain=domain, status=ScanStatus.COMPLETE, progress=100,
                          started_at=completed_at, completed_at=completed_at)
        scan.score.overall = score
        scan_store.save(scan)

    def test_history_is_oldest_first_and_excludes_free_scans(self):
        domain = "history-check.example"
        self._saved("scan_hist_1", domain, 62, "2026-10-01T10:00:00+00:00")
        self._saved("scan_hist_2", domain, 81, "2026-10-20T10:00:00+00:00")
        self._saved("pub_hist_3", domain, 10, "2026-10-25T10:00:00+00:00")
        self._saved("scan_other", "other.example", 50, "2026-10-21T10:00:00+00:00")
        client = authenticated_client()
        try:
            history = client.get("/api/scan/history", params={"domain": domain}).json()
            bad = client.get("/api/scan/history", params={"domain": "not a domain"})
        finally:
            client.close()
        self.assertEqual([(h["scan_id"], h["score"]) for h in history], [("scan_hist_1", 62), ("scan_hist_2", 81)])
        self.assertEqual(bad.status_code, 422)

    def test_history_requires_sign_in(self):
        client = TestClient(main.app)
        try:
            self.assertEqual(client.get("/api/scan/history", params={"domain": "example.com"}).status_code, 401)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
