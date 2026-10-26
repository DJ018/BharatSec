"""Team-wide CERT-In and DPDP compliance checklist."""
import unittest

from fastapi.testclient import TestClient

import main
from engines import compliance_engine
from tests.auth_helpers import authenticated_client


class ComplianceTests(unittest.TestCase):
    def setUp(self):
        self.client = authenticated_client()
        compliance_engine.init_db()
        with compliance_engine._connect() as connection:
            connection.execute("DELETE FROM compliance_status")

    def tearDown(self):
        self.client.close()

    def test_checklist_lists_every_item_with_framework_progress(self):
        body = self.client.get("/api/compliance").json()
        self.assertEqual(body["total"], len(compliance_engine.ITEMS))
        self.assertEqual(body["done"], 0)
        self.assertEqual({fw["id"] for fw in body["frameworks"]}, {"cert-in", "dpdp", "basics"})
        self.assertTrue(any(item["id"] == "certin-6h" for item in body["items"]))
        for item in body["items"]:
            self.assertNotIn(chr(0x2014), item["title"] + item["why"] + item["how"])  # house style

    def test_ticking_an_item_updates_progress_and_records_who(self):
        updated = self.client.put("/api/compliance/certin-poc", json={"done": True, "note": "Owner: Devesh"})
        self.assertEqual(updated.status_code, 200)
        self.assertTrue(updated.json()["done"])
        self.assertEqual(updated.json()["note"], "Owner: Devesh")
        self.assertTrue(updated.json()["updated_by"])
        body = self.client.get("/api/compliance").json()
        self.assertEqual(body["done"], 1)
        cert_in = next(fw for fw in body["frameworks"] if fw["id"] == "cert-in")
        self.assertEqual(cert_in["done"], 1)

    def test_toggling_keeps_an_existing_note(self):
        self.client.put("/api/compliance/dpdp-notice", json={"done": True, "note": "Published on /privacy"})
        untoggled = self.client.put("/api/compliance/dpdp-notice", json={"done": False}).json()
        self.assertFalse(untoggled["done"])
        self.assertEqual(untoggled["note"], "Published on /privacy")

    def test_unknown_item_is_rejected(self):
        self.assertEqual(self.client.put("/api/compliance/not-a-thing", json={"done": True}).status_code, 404)

    def test_requires_sign_in(self):
        anonymous = TestClient(main.app)
        try:
            self.assertEqual(anonymous.get("/api/compliance").status_code, 401)
            page = anonymous.get("/compliance", follow_redirects=False)
            self.assertEqual(page.status_code, 303)
        finally:
            anonymous.close()


if __name__ == "__main__":
    unittest.main()
