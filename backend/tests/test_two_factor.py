"""Two-factor sign-in: authenticator codes (RFC 6238), recovery codes and provider sign-ins."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

import auth as auth_service
import oauth
from main import app

PASSWORD = "Owner-Password-0001"


class TotpMathTests(unittest.TestCase):
    def test_matches_rfc_6238_vectors(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of "12345678901234567890"
        self.assertEqual(auth_service.totp_code(secret, 59 // 30), "287082")
        self.assertEqual(auth_service.totp_code(secret, 1111111109 // 30), "081804")


class TwoFactorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.step = 1_000_000
        self.patches = [
            patch.object(auth_service, "AUTH_DB_PATH", Path(self.temp_dir.name) / "auth.db"),
            patch.object(auth_service, "_current_step", lambda now=None: self.step),
            patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "google-id", "GOOGLE_CLIENT_SECRET": "google-secret"}),
        ]
        for item in self.patches:
            item.start()
        auth_service.init_db()
        self.owner = TestClient(app, follow_redirects=False)
        response = self.owner.post("/api/auth/register", json={"username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertFalse(response.json()["user"]["two_factor"])
        self.clients = [self.owner]

    def tearDown(self):
        for client in self.clients:
            client.close()
        for item in reversed(self.patches):
            item.stop()
        self.temp_dir.cleanup()

    def _client(self):
        client = TestClient(app, follow_redirects=False)
        self.clients.append(client)
        return client

    def _code(self):
        """A fresh code: move the clock on a step, since a used step is never accepted twice."""
        self.step += 1
        return auth_service.totp_code(self.secret, self.step)

    def _turn_on(self):
        setup = self.owner.post("/api/auth/2fa/setup")
        self.assertEqual(setup.status_code, 200, setup.text)
        self.secret = setup.json()["secret"]
        self.assertIn("otpauth://totp/BharatSec%3Aowner?secret=", setup.json()["otpauth_uri"])
        enabled = self.owner.post("/api/auth/2fa/enable", json={"code": self._code()})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        return enabled.json()["recovery_codes"]

    def _login(self, code=None):
        payload = {"username": "owner", "password": PASSWORD}
        if code:
            payload["code"] = code
        return self._client().post("/api/auth/login", json=payload)

    def test_wrong_code_does_not_turn_it_on(self):
        self.owner.post("/api/auth/2fa/setup")
        response = self.owner.post("/api/auth/2fa/enable", json={"code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._login().status_code, 200)  # still password-only

    def test_password_alone_is_not_enough_once_on(self):
        codes = self._turn_on()
        self.assertEqual(len(codes), 8)
        self.assertEqual(len(set(codes)), 8)

        asked = self._login()
        self.assertEqual(asked.status_code, 401)
        self.assertEqual(asked.json()["detail"], auth_service.TWO_FACTOR_REQUIRED)
        self.assertNotIn(auth_service.SESSION_COOKIE, asked.cookies)

        self.assertEqual(self._login("123456").status_code, 401)
        signed_in = self._login(self._code())
        self.assertEqual(signed_in.status_code, 200, signed_in.text)
        self.assertTrue(signed_in.json()["user"]["two_factor"])

    def test_a_code_cannot_be_replayed(self):
        self._turn_on()
        code = self._code()
        self.assertEqual(self._login(code).status_code, 200)
        self.assertEqual(self._login(code).status_code, 401)

    def test_recovery_code_works_once(self):
        codes = self._turn_on()
        self.assertEqual(self._login(codes[0].upper()).status_code, 200)
        self.assertEqual(self._login(codes[0]).status_code, 401)
        self.assertEqual(self._login(codes[1]).status_code, 200)

    def test_turning_off_needs_a_valid_code(self):
        self._turn_on()
        self.assertEqual(self.owner.post("/api/auth/2fa/disable", json={"code": "000000"}).status_code, 400)
        self.assertEqual(self.owner.post("/api/auth/2fa/disable", json={"code": self._code()}).status_code, 200)
        self.assertEqual(self._login().status_code, 200)

    def test_setup_needs_a_signed_in_user(self):
        self.assertEqual(self._client().post("/api/auth/2fa/setup").status_code, 401)

    def test_provider_sign_in_still_asks_for_the_code(self):
        self._turn_on()
        link = self.owner.get("/api/auth/oauth/google/start", params={"link": "1"})
        state = parse_qs(urlsplit(link.headers["location"]).query)["state"][0]
        profile = {"subject": "g-1", "email": "", "email_verified": False, "name": "Owner", "username_hint": None}
        with patch.object(oauth, "fetch_profile", AsyncMock(return_value=profile)):
            linked = self.owner.get("/api/auth/oauth/google/callback", params={"code": "abc", "state": state})
        self.assertEqual(linked.status_code, 200)  # linking a signed-in account needs no second code
        self.assertIn("url=/account.html#security", linked.text)

        visitor = self._client()
        start = visitor.get("/api/auth/oauth/google/start", params={"return": "/dashboard.html"})
        state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
        with patch.object(oauth, "fetch_profile", AsyncMock(return_value=profile)):
            callback = visitor.get("/api/auth/oauth/google/callback", params={"code": "abc", "state": state})
        self.assertEqual(callback.status_code, 303)
        self.assertTrue(callback.headers["location"].startswith("/login.html?twofactor=1"))
        self.assertEqual(visitor.get("/api/auth/me").status_code, 401)  # no session yet

        self.assertEqual(visitor.post("/api/auth/2fa/complete", json={"code": "000000"}).status_code, 401)
        done = visitor.post("/api/auth/2fa/complete", json={"code": self._code()})
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(visitor.get("/api/auth/me").json()["user"]["username"], "owner")

    def test_complete_without_a_pending_sign_in_is_refused(self):
        self._turn_on()
        self.assertEqual(self._client().post("/api/auth/2fa/complete", json={"code": self._code()}).status_code, 401)
        self.assertIsNone(auth_service.unpack_pending_two_factor("1.1.9999999999.forged"))


if __name__ == "__main__":
    unittest.main()
