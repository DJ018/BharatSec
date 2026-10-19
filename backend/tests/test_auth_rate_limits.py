"""Login throttling keyed on the real client address."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

import auth as auth_service
from main import app


def _request(peer: str, forwarded: str | None = None):
    headers = {"x-forwarded-for": forwarded} if forwarded is not None else {}
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)


class ClientIpTests(unittest.TestCase):
    def test_forwarded_header_is_ignored_without_trusted_proxies(self):
        with patch.object(auth_service, "TRUSTED_PROXY_HOPS", 0):
            self.assertEqual(auth_service.client_ip(_request("10.0.0.1", "198.51.100.7")), "10.0.0.1")

    def test_client_is_taken_from_the_trusted_proxy_entry(self):
        with patch.object(auth_service, "TRUSTED_PROXY_HOPS", 1):
            # The left entry is attacker-supplied; the proxy appended the real address.
            request = _request("10.0.0.1", "203.0.113.99, 198.51.100.7")
            self.assertEqual(auth_service.client_ip(request), "198.51.100.7")
        with patch.object(auth_service, "TRUSTED_PROXY_HOPS", 2):
            request = _request("10.0.0.1", "203.0.113.99, 198.51.100.7, 172.70.1.1")
            self.assertEqual(auth_service.client_ip(request), "198.51.100.7")

    def test_short_forwarded_header_falls_back_to_peer(self):
        with patch.object(auth_service, "TRUSTED_PROXY_HOPS", 2):
            self.assertEqual(auth_service.client_ip(_request("10.0.0.1", "198.51.100.7")), "10.0.0.1")
            self.assertEqual(auth_service.client_ip(_request("10.0.0.1")), "10.0.0.1")


class LoginThrottleTests(unittest.TestCase):
    password = "Correct-Horse-Battery-42"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.patches = [
            patch.object(auth_service, "AUTH_DB_PATH", Path(self.temp_dir.name) / "auth.db"),
            patch.object(auth_service, "TRUSTED_PROXY_HOPS", 1),
        ]
        for item in self.patches:
            item.start()
        auth_service.init_db()
        self.client = TestClient(app)
        for username in ("victim-user", "attacker-user"):
            response = self.client.post(
                "/api/auth/register", json={"username": username, "password": self.password}
            )
            self.assertEqual(response.status_code, 201)

    def tearDown(self):
        self.client.close()
        for item in reversed(self.patches):
            item.stop()
        self.temp_dir.cleanup()

    def _login(self, username: str, password: str, ip: str):
        return self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"x-forwarded-for": ip},
        )

    def test_one_clients_failures_do_not_lock_out_other_clients(self):
        for _ in range(10):
            self.assertEqual(self._login("victim-user", "wrong-password-123", "203.0.113.10").status_code, 401)
        self.assertEqual(self._login("victim-user", "wrong-password-123", "203.0.113.10").status_code, 429)
        self.assertEqual(self._login("victim-user", self.password, "198.51.100.20").status_code, 200)

    def test_successful_login_does_not_reset_ip_failure_window(self):
        attacker_ip = "203.0.113.50"
        for _ in range(3):
            self._login("victim-user", "wrong-password-123", attacker_ip)
        self.assertEqual(self._login("attacker-user", self.password, attacker_ip).status_code, 200)
        with auth_service._database() as connection:
            row = connection.execute(
                "SELECT attempts FROM auth_rate_limits WHERE scope = 'login-ip' AND identifier_hash = ?",
                (auth_service._rate_limit_key("login-ip", attacker_ip),),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["attempts"], 3)


if __name__ == "__main__":
    unittest.main()
