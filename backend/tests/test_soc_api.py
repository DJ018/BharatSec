"""SOC tests use a temporary database and mocked monitor probes."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engines import soc_engine
from tests.auth_helpers import authenticated_client


class SocApiTests(unittest.TestCase):
    def test_alert_to_incident_response_workflow(self):
        offline_probe = {
            "status": "offline",
            "http_status": None,
            "response_time_ms": None,
            "tls_valid": False,
            "tls_days_remaining": None,
            "https_redirect": False,
            "last_error": "Synthetic monitor failure",
        }

        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "soc-test.db"
            with patch.object(soc_engine, "DB_PATH", database):
                with authenticated_client() as client:
                    rejected = client.post("/api/soc/assets", json={"domain": "example.com"})
                    self.assertEqual(rejected.status_code, 400)

                    created = client.post(
                        "/api/soc/assets",
                        json={"domain": "https://Example.com/", "authorized": True},
                    )
                    self.assertEqual(created.status_code, 201)
                    asset = created.json()
                    self.assertEqual(asset["domain"], "example.com")

                    with patch.object(soc_engine, "_probe_public_domain", return_value=offline_probe):
                        checked = client.post(f"/api/soc/assets/{asset['id']}/check")
                        client.post(f"/api/soc/assets/{asset['id']}/check")
                    self.assertEqual(checked.json()["status"], "offline")

                    alerts = client.get("/api/soc/alerts").json()
                    self.assertEqual(len(alerts), 1)
                    self.assertEqual(alerts[0]["occurrences"], 2)
                    alert_id = alerts[0]["id"]

                    acknowledged = client.patch(
                        f"/api/soc/alerts/{alert_id}",
                        json={"state": "acknowledged"},
                    )
                    self.assertEqual(acknowledged.json()["state"], "acknowledged")

                    incident_response = client.post(
                        f"/api/soc/alerts/{alert_id}/incident",
                        json={"title": "Website availability event", "severity": "HIGH", "author": "SOC Analyst"},
                    )
                    self.assertEqual(incident_response.status_code, 201)
                    incident_id = incident_response.json()["id"]

                    updated = client.patch(
                        f"/api/soc/incidents/{incident_id}",
                        json={"status": "investigating", "owner": "On-call", "author": "SOC Analyst"},
                    )
                    self.assertEqual(updated.json()["status"], "investigating")
                    self.assertEqual(updated.json()["owner"], "On-call")

                    note = client.post(
                        f"/api/soc/incidents/{incident_id}/events",
                        json={"message": "Origin health check started.", "author": "SOC Analyst"},
                    )
                    self.assertEqual(note.status_code, 201)
                    detail = client.get(f"/api/soc/incidents/{incident_id}").json()
                    self.assertEqual(len(detail["events"]), 5)
                    self.assertEqual(detail["events"][-1]["message"], "Origin health check started.")

    def test_private_and_invalid_targets_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(soc_engine, "DB_PATH", Path(folder) / "soc-test.db"):
                with authenticated_client() as client:
                    private_ip = client.post(
                        "/api/soc/assets",
                        json={"domain": "127.0.0.1", "authorized": True},
                    )
                    local_domain = client.post(
                        "/api/soc/assets",
                        json={"domain": "service.local", "authorized": True},
                    )
                    malformed_port = client.post(
                        "/api/soc/assets",
                        json={"domain": "example.com:not-a-port", "authorized": True},
                    )
                    self.assertEqual(private_ip.status_code, 422)
                    self.assertEqual(local_domain.status_code, 422)
                    self.assertEqual(malformed_port.status_code, 422)

    def test_https_only_asset_does_not_raise_redirect_alert(self):
        https_only_probe = {
            "status": "online",
            "http_status": 200,
            "http_responded": False,
            "response_time_ms": 120,
            "tls_valid": True,
            "tls_days_remaining": 90,
            "https_redirect": False,
            "last_error": "",
        }
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(soc_engine, "DB_PATH", Path(folder) / "soc-test.db"):
                with authenticated_client() as client:
                    created = client.post(
                        "/api/soc/assets",
                        json={"domain": "example.com", "authorized": True},
                    )
                    asset_id = created.json()["id"]
                    with patch.object(soc_engine, "_probe_public_domain", return_value=https_only_probe):
                        checked = client.post(f"/api/soc/assets/{asset_id}/check")
                    self.assertEqual(checked.json()["status"], "online")
                    self.assertEqual(client.get("/api/soc/alerts").json(), [])


if __name__ == "__main__":
    unittest.main()