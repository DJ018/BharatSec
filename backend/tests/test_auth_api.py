"""Server-enforced account and session behavior."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import auth as auth_service
from main import app


class AuthApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_patch = patch.object(auth_service, "AUTH_DB_PATH", Path(self.temp_dir.name) / "auth.db")
        self.database_patch.start()
        auth_service.init_db()
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self):
        self.client.close()
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def test_api_and_workspace_pages_require_server_session(self):
        self.assertEqual(self.client.get("/api/scan/recent").status_code, 401)
        protected = self.client.get("/dashboard")
        self.assertEqual(protected.status_code, 303)
        self.assertIn("/login.html?return=", protected.headers["location"])
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_registration_hashes_password_and_creates_httponly_session(self):
        password = "Correct-Horse-Battery-42"
        response = self.client.post(
            "/api/auth/register",
            json={"username": "bharat-user", "password": password, "display_name": "Bharat User"},
        )
        self.assertEqual(response.status_code, 201)
        cookie = response.headers["set-cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=strict", cookie)
        self.assertNotIn("Max-Age", cookie)
        self.assertNotIn("Secure", cookie)

        with auth_service._database() as connection:
            row = connection.execute("SELECT password_hash FROM users WHERE username = ?", ("bharat-user",)).fetchone()
        self.assertNotEqual(row["password_hash"], password)
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))
        self.assertEqual(self.client.get("/api/auth/me").json()["user"]["name"], "Bharat User")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_login_errors_are_generic_and_logout_revokes_session(self):
        self.client.post(
            "/api/auth/register",
            json={"username": "bharat-user", "password": "Correct-Horse-Battery-42"},
        )
        self.client.post("/api/auth/logout")

        wrong_password = self.client.post(
            "/api/auth/login",
            json={"username": "bharat-user", "password": "Incorrect-Horse-Battery-42"},
        )
        unknown_user = self.client.post(
            "/api/auth/login",
            json={"username": "missing-user", "password": "Incorrect-Horse-Battery-42"},
        )
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(wrong_password.json(), unknown_user.json())

        login = self.client.post(
            "/api/auth/login",
            json={"username": "bharat-user", "password": "Correct-Horse-Battery-42", "remember": True},
        )
        self.assertEqual(login.status_code, 200)
        self.assertIn("Max-Age=604800", login.headers["set-cookie"])
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.assertEqual(self.client.get("/api/scan/recent").status_code, 401)

    def test_registration_validates_passwords_and_duplicate_usernames(self):
        short_password = self.client.post(
            "/api/auth/register",
            json={"username": "valid-user", "password": "short"},
        )
        self.assertEqual(short_password.status_code, 422)

        account = {"username": "valid-user", "password": "Correct-Horse-Battery-42"}
        self.assertEqual(self.client.post("/api/auth/register", json=account).status_code, 201)
        duplicate = self.client.post("/api/auth/register", json=account)
        self.assertEqual(duplicate.status_code, 409)

    def test_cross_origin_mutation_is_rejected(self):
        response = self.client.post(
            "/api/auth/register",
            headers={"Origin": "https://attacker.invalid"},
            json={"username": "other-user", "password": "Correct-Horse-Battery-42"},
        )
        self.assertEqual(response.status_code, 403)

    def test_registration_can_be_disabled_for_deployment(self):
        with patch.object(auth_service, "ALLOW_REGISTRATION", False):
            response = self.client.post(
                "/api/auth/register",
                json={"username": "blocked-user", "password": "Correct-Horse-Battery-42"},
            )
        self.assertEqual(response.status_code, 403)

    def test_bootstrap_account_can_sign_in_without_public_registration(self):
        with patch.object(auth_service, "BOOTSTRAP_USERNAME", "initial-admin"), \
             patch.object(auth_service, "BOOTSTRAP_PASSWORD", "Bootstrap-Password-42"), \
             patch.object(auth_service, "BOOTSTRAP_DISPLAY_NAME", "Initial Administrator"), \
             patch.object(auth_service, "ALLOW_REGISTRATION", False):
            auth_service.init_db()
            response = self.client.post(
                "/api/auth/login",
                json={"username": "initial-admin", "password": "Bootstrap-Password-42"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"]["name"], "Initial Administrator")
        self.assertTrue(self.client.get("/dashboard").is_success)


if __name__ == "__main__":
    unittest.main()
