"""Free single-purpose tools: SSL, email authentication and security headers checks."""
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

import auth as auth_service
import main
from models.scan_models import DNSResults, HeadersResult, SSLInfo, WebInfo
from routers import tools


class FreeToolTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)  # signed out
        with auth_service._database() as connection:
            connection.execute("DELETE FROM auth_rate_limits WHERE scope = 'public-tools'")
        self.guard = patch.object(tools, "_reject_non_public_target", AsyncMock())
        self.guard.start()

    def tearDown(self):
        self.guard.stop()
        self.client.close()

    def test_ssl_check_reports_expiry_and_advice(self):
        info = SSLInfo(valid=True, issuer="Let's Encrypt", days_remaining=12, grade="B", protocol="TLSv1.2", expires="2026-11-08")
        with patch.object(tools, "get_ssl_info", return_value=info):
            body = self.client.get("/api/public/tools/ssl", params={"domain": "https://www.Example.com/path"}).json()
        self.assertEqual(body["domain"], "example.com")
        self.assertEqual(body["ssl"]["days_remaining"], 12)
        self.assertTrue(any("expires in 12 days" in line for line in body["advice"]))
        self.assertTrue(any("TLS 1.2 and 1.3" in line for line in body["advice"]))

    def test_email_check_reads_spf_dkim_and_dmarc_policy(self):
        records = DNSResults(txt_records=['"v=spf1 include:_spf.google.com ~all"'], mx_records=["1 aspmx.l.google.com."], has_spf=True, has_dkim=False)
        with patch.object(tools, "get_dns_records", AsyncMock(return_value=records)), \
             patch.object(tools, "_dmarc_record", AsyncMock(return_value="v=DMARC1; p=none; rua=mailto:d@example.com")):
            body = self.client.get("/api/public/tools/email", params={"domain": "example.com"}).json()
        self.assertTrue(body["spf"]["present"])
        self.assertEqual(body["spf"]["record"], "v=spf1 include:_spf.google.com ~all")
        self.assertFalse(body["dkim"]["present"])
        self.assertEqual(body["dmarc"]["policy"], "none")
        self.assertTrue(any("p=quarantine" in line for line in body["advice"]))
        self.assertTrue(any("DKIM" in line for line in body["advice"]))

    def test_headers_check_lists_present_and_missing(self):
        web = WebInfo(status_code=200, https_redirect=True,
                      headers=HeadersResult(present=["Strict-Transport-Security", "X-Content-Type-Options"]))
        with patch.object(tools, "get_web_info", AsyncMock(return_value=web)):
            body = self.client.get("/api/public/tools/headers", params={"domain": "example.com"}).json()
        self.assertTrue(body["https_redirect"])
        self.assertIn("Content-Security-Policy", body["missing"])
        self.assertNotIn("Strict-Transport-Security", body["missing"])
        self.assertEqual(len(body["headers"]), 6)

    def test_invalid_domains_are_rejected(self):
        for bad in ("not a domain", "127.0.0.1", ""):
            self.assertEqual(self.client.get("/api/public/tools/ssl", params={"domain": bad}).status_code, 422, bad)

    def test_private_targets_are_refused(self):
        self.guard.stop()
        with patch.object(tools, "_reject_non_public_target", AsyncMock(side_effect=HTTPException(422, "private"))):
            response = self.client.get("/api/public/tools/headers", params={"domain": "internal.example"})
        self.guard.start()
        self.assertEqual(response.status_code, 422)

    def test_checks_are_rate_limited_per_visitor(self):
        web = WebInfo()
        with patch.object(tools, "get_web_info", AsyncMock(return_value=web)), patch.object(tools, "CHECKS_PER_HOUR", 2):
            codes = [self.client.get("/api/public/tools/headers", params={"domain": "example.com"}).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])


if __name__ == "__main__":
    unittest.main()
