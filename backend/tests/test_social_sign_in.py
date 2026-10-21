"""Sign in with Google, GitHub, Facebook and Microsoft, with usernames generated from the profile."""
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

PROVIDER_ENV = {
    "GOOGLE_CLIENT_ID": "google-id", "GOOGLE_CLIENT_SECRET": "google-secret",
    "GITHUB_CLIENT_ID": "github-id", "GITHUB_CLIENT_SECRET": "github-secret",
}


def _profile(subject, email="", verified=True, name="", hint=None):
    return {"subject": subject, "email": email, "email_verified": verified, "name": name, "username_hint": hint}


class SocialSignInTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.patches = [
            patch.object(auth_service, "AUTH_DB_PATH", Path(self.temp_dir.name) / "auth.db"),
            patch.object(auth_service, "ALLOW_REGISTRATION", False),
            patch.dict(os.environ, PROVIDER_ENV),
        ]
        for item in self.patches:
            item.start()
        auth_service.init_db()
        self.clients = []

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

    def _sign_in(self, client, provider, profile, link=False, return_to=None):
        params = {"link": "1"} if link else ({"return": return_to} if return_to else {})
        start = client.get(f"/api/auth/oauth/{provider}/start", params=params)
        self.assertEqual(start.status_code, 303, start.text)
        query = parse_qs(urlsplit(start.headers["location"]).query)
        with patch.object(oauth, "fetch_profile", AsyncMock(return_value=profile)) as fetch:
            callback = client.get(
                f"/api/auth/oauth/{provider}/callback", params={"code": "abc", "state": query["state"][0]}
            )
        return start, callback, fetch

    def test_config_lists_only_configured_providers(self):
        providers = self._client().get("/api/auth/config").json()["providers"]
        self.assertEqual([p["key"] for p in providers], ["google", "github"])

    def test_first_google_sign_in_claims_admin_with_generated_username(self):
        client = self._client()
        start, callback, fetch = self._sign_in(
            client, "google", _profile("g-1", "Priya.Sharma@Example.com", name="Priya Sharma"), return_to="/soc.html"
        )
        location = urlsplit(start.headers["location"])
        self.assertEqual(location.netloc, "accounts.google.com")
        query = parse_qs(location.query)
        self.assertEqual(query["redirect_uri"][0], "http://testserver/api/auth/oauth/google/callback")
        self.assertEqual(query["code_challenge_method"][0], "S256")
        self.assertEqual(fetch.await_args.args[1], "abc")

        self.assertEqual(callback.status_code, 200)
        self.assertIn('url=/soc.html"', callback.text)  # finishes with a same-site navigation
        user = client.get("/api/auth/me").json()["user"]
        self.assertEqual(user["username"], "priya.sharma")
        self.assertEqual(user["name"], "Priya Sharma")
        self.assertEqual(user["role"], "admin")
        self.assertEqual(user["email"], "priya.sharma@example.com")
        self.assertFalse(user["has_password"])
        self.assertFalse(client.get("/api/auth/config").json()["setup_required"])

    def test_returning_user_signs_in_to_the_same_account(self):
        first = self._client()
        self._sign_in(first, "github", _profile(42, "dev@example.com", name="Dev", hint="dev-octo"))
        second = self._client()
        self._sign_in(second, "github", _profile(42, "dev@example.com", name="Dev", hint="dev-octo"))
        self.assertEqual(first.get("/api/auth/me").json()["user"]["id"], second.get("/api/auth/me").json()["user"]["id"])
        self.assertEqual(second.get("/api/auth/me").json()["user"]["username"], "dev-octo")

    def test_usernames_are_made_unique(self):
        self._sign_in(self._client(), "google", _profile("a", "sam@one.example", name="Sam"))
        with patch.object(auth_service, "ALLOW_REGISTRATION", True):
            client = self._client()
            self._sign_in(client, "google", _profile("b", "sam@two.example", name="Sam"))
        user = client.get("/api/auth/me").json()["user"]
        self.assertEqual(user["username"], "sam2")
        self.assertEqual(user["role"], "analyst")

    def test_unknown_person_is_refused_when_registration_is_closed(self):
        self._sign_in(self._client(), "google", _profile("owner", "owner@example.com"))
        stranger = self._client()
        _, callback, _ = self._sign_in(stranger, "google", _profile("x", "stranger@example.com"))
        self.assertEqual(callback.status_code, 303)
        self.assertIn("/login.html?oauth_error=", callback.headers["location"])
        self.assertEqual(stranger.get("/api/auth/me").status_code, 401)

    def test_member_added_by_email_signs_in_with_matching_verified_email(self):
        owner = self._client()
        self._sign_in(owner, "google", _profile("owner", "owner@example.com"))
        added = owner.post("/api/auth/users", json={"email": "Asha.K@Example.com", "display_name": "Asha K"})
        self.assertEqual(added.status_code, 201, added.text)
        self.assertEqual(added.json()["user"]["username"], "asha.k")

        member = self._client()
        self._sign_in(member, "github", _profile(7, "asha.k@example.com", hint="ashak"))
        user = member.get("/api/auth/me").json()["user"]
        self.assertEqual(user["id"], added.json()["user"]["id"])
        # The unused temporary password is discarded instead of forcing a password change.
        self.assertFalse(user["must_change_password"])
        self.assertFalse(user["has_password"])
        temporary_login = self._client().post(
            "/api/auth/login", json={"username": "asha.k", "password": added.json()["temporary_password"]}
        )
        self.assertEqual(temporary_login.status_code, 401)

        # An unverified email never matches an existing account.
        other = self._client()
        _, callback, _ = self._sign_in(other, "google", _profile("y", "asha.k@example.com", verified=False))
        self.assertIn("oauth_error=", callback.headers["location"])

    def test_signed_in_user_connects_and_disconnects_a_provider(self):
        owner = self._client()
        self._sign_in(owner, "google", _profile("owner", "owner@example.com"))
        _, callback, _ = self._sign_in(owner, "github", _profile(99, "other@example.com", hint="octo"), link=True)
        self.assertEqual(callback.status_code, 200)
        self.assertIn("url=/account.html#security", callback.text)
        identities = owner.get("/api/auth/identities").json()["identities"]
        self.assertEqual(sorted(i["provider"] for i in identities), ["github", "google"])

        self.assertEqual(owner.delete("/api/auth/identities/github").status_code, 204)
        # The last sign-in method cannot be removed while the account has no password.
        self.assertEqual(owner.delete("/api/auth/identities/google").status_code, 409)
        set_password = owner.post("/api/auth/password", json={"new_password": "Owner-Password-2026"})
        self.assertEqual(set_password.status_code, 200, set_password.text)
        self.assertTrue(set_password.json()["user"]["has_password"])
        self.assertEqual(owner.delete("/api/auth/identities/google").status_code, 204)

    def test_tampered_or_missing_state_is_rejected(self):
        client = self._client()
        client.get("/api/auth/oauth/google/start")
        with patch.object(oauth, "fetch_profile", AsyncMock()) as fetch:
            response = client.get("/api/auth/oauth/google/callback", params={"code": "abc", "state": "forged"})
        self.assertIn("oauth_error=", response.headers["location"])
        fetch.assert_not_awaited()

    def test_social_only_account_cannot_sign_in_with_an_empty_password(self):
        self._sign_in(self._client(), "google", _profile("owner", "owner@example.com"))
        response = self._client().post("/api/auth/login", json={"username": "owner", "password": "x"})
        self.assertEqual(response.status_code, 401)

    def test_unconfigured_provider_and_offsite_return_are_refused(self):
        client = self._client()
        response = client.get("/api/auth/oauth/facebook/start")
        self.assertIn("/login.html?oauth_error=", response.headers["location"])
        _, callback, _ = self._sign_in(client, "google", _profile("owner", "owner@example.com"), return_to="//evil.example")
        self.assertIn('url=/dashboard.html"', callback.text)


if __name__ == "__main__":
    unittest.main()
