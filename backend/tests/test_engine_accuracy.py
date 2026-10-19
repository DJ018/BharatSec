"""Regression tests for scan accuracy, SOC attribution, cloud severity, and threat correlation."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engines import cloud_engine, risk_engine, soc_engine, threat_intel_engine as intel
from engines.security_engine import _grade
from models.scan_models import DNSResults, ScanResult, SSLInfo, SubdomainResult, WebInfo, WHOISInfo
from tests.auth_helpers import authenticated_client


def _scan(domain="example.com", **overrides) -> ScanResult:
    scan = ScanResult(scan_id="scan_test", domain=domain)
    scan.ssl = SSLInfo(valid=True, days_remaining=200, protocol="TLSv1.3", expires="2027-01-01")
    scan.web = WebInfo(status_code=200, https_redirect=True)
    scan.dns = DNSResults(has_spf=True, has_dmarc=True, has_dkim=True, mx_records=["10 mx.example.com."])
    for key, value in overrides.items():
        setattr(scan, key, value)
    return scan


def _alive(*names):
    return [SubdomainResult(subdomain=name, ip="203.0.113.5", status_code=200, alive=True) for name in names]


class RiskEngineTests(unittest.TestCase):
    def test_sensitive_subdomains_match_exact_labels_only(self):
        scan = _scan("oldnavy.com", subdomains=_alive("www.oldnavy.com", "shop.oldnavy.com", "admin.oldnavy.com"))
        titles = [f.title for f in risk_engine.generate_findings(scan) if f.id.startswith("sensitive_sub")]
        self.assertEqual(titles, ["Sensitive Subdomain Exposed: admin.oldnavy.com"])

    def test_sensitive_subdomain_after_generic_ones_is_still_reported(self):
        names = [f"{label}.example.com" for label in ("www", "api", "app", "cdn", "blog", "shop", "staging")]
        findings = risk_engine.generate_findings(_scan(subdomains=_alive(*names)))
        self.assertTrue(any(f.title.endswith("staging.example.com") for f in findings))
        self.assertEqual(sum(f.id.startswith("sub_exposure") for f in findings), 1)

    def test_info_findings_never_improve_the_score(self):
        quiet = _scan()
        quiet.findings = risk_engine.generate_findings(quiet)
        busy = _scan(subdomains=_alive(*[f"{label}.example.com" for label in ("www", "api", "app", "cdn", "blog", "shop")]))
        busy.findings = risk_engine.generate_findings(busy)
        self.assertEqual(risk_engine.calculate_score(quiet).attack_surface, 100)
        self.assertEqual(risk_engine.calculate_score(busy).attack_surface, 100)

    def test_expired_domain_is_critical(self):
        scan = _scan(whois=WHOISInfo(expiration_date="2026-01-01", days_until_expiry=-30))
        expired = [f for f in risk_engine.generate_findings(scan) if f.id.startswith("domain_expired")]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].severity.value, "CRITICAL")

    def test_missing_dkim_is_low_confidence(self):
        scan = _scan(dns=DNSResults(has_spf=True, has_dmarc=True, has_dkim=False, mx_records=["10 mx.example.com."]))
        dkim = [f for f in risk_engine.generate_findings(scan) if f.id.startswith("no_dkim")]
        self.assertEqual(dkim[0].severity.value, "LOW")

    def test_tls_grades(self):
        self.assertEqual(_grade(SSLInfo(valid=True, protocol="TLSv1.3", days_remaining=200)), "A")
        self.assertEqual(_grade(SSLInfo(valid=True, protocol="TLSv1.2", days_remaining=20)), "B")
        accepts_legacy = SSLInfo(valid=True, protocol="TLSv1.3", days_remaining=200,
                                 vulnerabilities=["Server still accepts TLS 1.0 (deprecated TLS 1.0/1.1)"])
        self.assertEqual(_grade(accepts_legacy), "C")
        self.assertEqual(_grade(SSLInfo(valid=False, protocol="TLSv1", days_remaining=200)), "D")
        self.assertEqual(_grade(SSLInfo(valid=False, protocol="TLSv1.2", days_remaining=-3, expires="2026-01-01")), "F")
        self.assertEqual(_grade(SSLInfo(valid=False)), "N/A")

    def test_legacy_tls_vulnerability_produces_finding(self):
        scan = _scan(ssl=SSLInfo(valid=True, protocol="TLSv1.3", days_remaining=200, expires="2027-01-01",
                                 vulnerabilities=["Server still accepts TLS 1.0 (deprecated TLS 1.0/1.1)"]))
        self.assertTrue(any(f.id.startswith("tls_old") for f in risk_engine.generate_findings(scan)))


class WildcardDnsTests(unittest.IsolatedAsyncioTestCase):
    async def test_catch_all_subdomains_are_filtered(self):
        from engines import osint_engine
        from models.scan_models import DNSResults

        class Answer:
            address = "203.0.113.10"

        class WildcardResolver:
            timeout = lifetime = None
            nameservers = []

            async def resolve(self, name, rtype, **kwargs):
                return [Answer()]  # every name resolves

        async def fake_probe(client, host):
            # The real site answers differently from the catch-all 404 page.
            return (200, 53051) if host.startswith("www.") else (404, 107)

        dns_result = DNSResults()
        with patch.object(osint_engine.dns.asyncresolver, "Resolver", WildcardResolver), \
             patch.object(osint_engine, "_probe_http", side_effect=fake_probe):
            found = await osint_engine.enumerate_subdomains("example.com", dns_result)
        self.assertTrue(dns_result.wildcard_dns)
        self.assertEqual([s.subdomain for s in found], ["www.example.com"])

    def test_wildcard_finding_and_no_mail_domain_advice(self):
        scan = _scan(dns=DNSResults(has_spf=False, has_dmarc=False, wildcard_dns=True, mx_records=[]))
        findings = {f.id.rsplit("_", 1)[0]: f for f in risk_engine.generate_findings(scan)}
        self.assertEqual(findings["wildcard_dns"].severity.value, "INFO")
        self.assertIn("v=spf1 -all", findings["no_spf"].fix)
        self.assertIn("p=reject", findings["no_dmarc"].fix)

    def test_response_matching_tolerates_small_size_changes(self):
        from engines.osint_engine import _same_response
        self.assertTrue(_same_response((404, 107), (404, 110)))
        self.assertFalse(_same_response((200, 53051), (404, 107)))
        self.assertFalse(_same_response((200, 5000), (200, 9000)))


class CloudSeverityTests(unittest.TestCase):
    def test_port_specs_covering_ssh_or_rdp(self):
        for spec in ("*", "22", "3389", "0-65535", "20-30", "80,3389"):
            with self.subTest(spec=spec):
                self.assertTrue(cloud_engine._port_spec_covers_admin(spec))
        for spec in ("443", "80,443", "1000-2000", "", "not-a-port"):
            with self.subTest(spec=spec):
                self.assertFalse(cloud_engine._port_spec_covers_admin(spec))


class SocAttributionTests(unittest.TestCase):
    def test_incident_author_comes_from_session_not_request(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(soc_engine, "DB_PATH", Path(folder) / "soc.db"):
                soc_engine.init_db()
                with authenticated_client() as client:
                    me = client.get("/api/auth/me").json()["user"]
                    created = client.post(
                        "/api/soc/incidents",
                        json={"title": "Phishing report", "author": "Somebody Else"},
                    )
                    self.assertEqual(created.status_code, 201)
                    incident_id = created.json()["id"]
                    client.post(f"/api/soc/incidents/{incident_id}/events",
                                json={"message": "Checked mail logs", "author": "Somebody Else"})
                    events = client.get(f"/api/soc/incidents/{incident_id}").json()["events"]
        authors = {event["author"] for event in events}
        self.assertEqual(authors, {me["name"]})

    def test_reopening_alert_with_active_duplicate_returns_conflict(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(soc_engine, "DB_PATH", Path(folder) / "soc.db"):
                soc_engine.init_db()
                asset = soc_engine.create_asset("example.com", "Example", 300)
                offline = {"status": "offline", "http_status": None, "response_time_ms": None, "tls_valid": False,
                           "tls_days_remaining": None, "https_redirect": False, "last_error": "down"}
                online = {**offline, "status": "online", "http_status": 200, "tls_valid": True, "last_error": ""}
                soc_engine._save_monitor_result(asset["id"], offline)   # alert 1 opens
                soc_engine._save_monitor_result(asset["id"], online)    # alert 1 resolves
                soc_engine._save_monitor_result(asset["id"], offline)   # alert 2 opens
                first = soc_engine.list_alerts("resolved")[0]["id"]
                with authenticated_client() as client:
                    response = client.patch(f"/api/soc/alerts/{first}", json={"state": "open"})
        self.assertEqual(response.status_code, 409)


class ThreatCorrelationTests(unittest.TestCase):
    def test_correlations_cover_all_indicators_case_insensitively(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(intel, "DB_PATH", Path(folder) / "intel.db"), \
                 patch.object(soc_engine, "DB_PATH", Path(folder) / "soc.db"):
                intel.init_db()
                soc_engine.init_db()
                soc_engine.create_asset("example.com", "Example", 300)
                records = [
                    {"ioc": f"http://noise{index}.invalid-example.net/x", "type": "url", "title": "noise",
                     "threat_type": "malware", "confidence": 80, "tags": []}
                    for index in range(1500)
                ]
                records.append({"ioc": "http://Portal.EXAMPLE.com/payload", "type": "url", "title": "match",
                                "threat_type": "malware", "confidence": 90, "tags": []})
                intel._import_records("abuse.ch URLhaus", records)
                correlations = intel.list_correlations()
                overview = intel.get_overview()
        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0]["matches"][0]["asset_domain"], "example.com")
        self.assertEqual(overview["environment_matches"], 1)


if __name__ == "__main__":
    unittest.main()
