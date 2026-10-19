"""Roles, password changes and team management."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import auth as auth_service
from main import app

ADMIN_PASSWORD = "Admin-Password-0001"


class AccountManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(auth_service, "AUTH_DB_PATH", Path(self.temp_dir.name) / "auth.db")
        self.db_patch.start()
        auth_service.init_db()
        self.admin = TestClient(app)
        response = self.admin.post("/api/auth/register", json={"username": "owner", "password": ADMIN_PASSWORD})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["user"]["role"], "admin")  # first account administers the workspace

    def tearDown(self):
        self.admin.close()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _client(self, username, password):
        client = TestClient(app)
        response = client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        return client, response.json()["user"]

    def _add_member(self, username, role="analyst"):
        response = self.admin.post("/api/auth/users", json={"username": username, "display_name": username.title(), "role": role})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_admin_adds_member_who_must_change_temporary_password(self):
        created = self._add_member("priya")
        temporary = created["temporary_password"]
        self.assertGreaterEqual(len(temporary), 12)
        self.assertTrue(created["user"]["must_change_password"])

        member, user = self._client("priya", temporary)
        self.assertTrue(user["must_change_password"])
        self.assertEqual(user["role"], "analyst")
        changed = member.post("/api/auth/password", json={"current_password": temporary, "new_password": "Priya-Own-Password-1"})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertFalse(changed.json()["user"]["must_change_password"])
        member.close()
        self._client("priya", "Priya-Own-Password-1")[0].close()

    def test_analysts_cannot_manage_the_team(self):
        created = self._add_member("ravi")
        analyst, _ = self._client("ravi", created["temporary_password"])
        self.assertEqual(analyst.get("/api/auth/users").status_code, 403)
        self.assertEqual(analyst.post("/api/auth/users", json={"username": "sneaky", "role": "admin"}).status_code, 403)
        self.assertEqual(analyst.patch(f"/api/auth/users/{created['user']['id']}", json={"role": "admin"}).status_code, 403)
        analyst.close()
        self.assertEqual(TestClient(app).get("/api/auth/users").status_code, 401)

    def test_last_admin_cannot_be_removed_or_demoted(self):
        me = self.admin.get("/api/auth/me").json()["user"]
        self.assertEqual(self.admin.patch(f"/api/auth/users/{me['id']}", json={"role": "analyst"}).status_code, 409)
        self.assertEqual(self.admin.delete(f"/api/auth/users/{me['id']}").status_code, 409)

        second = self._add_member("deputy", role="admin")
        deputy, _ = self._client("deputy", second["temporary_password"])
        # With two admins, one may demote the other — but never the final remaining admin.
        self.assertEqual(deputy.patch(f"/api/auth/users/{me['id']}", json={"role": "analyst"}).status_code, 200)
        self.assertEqual(self.admin.get("/api/auth/users").status_code, 403)  # owner is now an analyst
        self.assertEqual(deputy.delete(f"/api/auth/users/{second['user']['id']}").status_code, 409)
        deputy.close()

    def test_password_change_requires_current_password_and_signs_out_other_sessions(self):
        other_device, _ = self._client("owner", ADMIN_PASSWORD)
        wrong = self.admin.post("/api/auth/password", json={"current_password": "not-it", "new_password": "Brand-New-Password-9"})
        self.assertEqual(wrong.status_code, 401)
        same = self.admin.post("/api/auth/password", json={"current_password": ADMIN_PASSWORD, "new_password": ADMIN_PASSWORD})
        self.assertEqual(same.status_code, 422)
        ok = self.admin.post("/api/auth/password", json={"current_password": ADMIN_PASSWORD, "new_password": "Brand-New-Password-9"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.admin.get("/api/auth/me").status_code, 200)       # this session stays signed in
        self.assertEqual(other_device.get("/api/auth/me").status_code, 401)     # other sessions are revoked
        other_device.close()

    def test_reset_password_revokes_member_sessions(self):
        created = self._add_member("asha")
        member, _ = self._client("asha", created["temporary_password"])
        reset = self.admin.post(f"/api/auth/users/{created['user']['id']}/reset-password")
        self.assertEqual(reset.status_code, 200)
        self.assertNotEqual(reset.json()["temporary_password"], created["temporary_password"])
        self.assertEqual(member.get("/api/auth/me").status_code, 401)
        member.close()
        self._client("asha", reset.json()["temporary_password"])[0].close()

    def test_removed_member_loses_access_and_duplicates_are_rejected(self):
        created = self._add_member("temp")
        member, _ = self._client("temp", created["temporary_password"])
        self.assertEqual(self.admin.post("/api/auth/users", json={"username": "TEMP"}).status_code, 409)
        self.assertEqual(self.admin.delete(f"/api/auth/users/{created['user']['id']}").status_code, 204)
        self.assertEqual(member.get("/api/auth/me").status_code, 401)
        self.assertEqual([u["username"] for u in self.admin.get("/api/auth/users").json()["users"]], ["owner"])
        member.close()

    def test_account_page_requires_sign_in(self):
        anonymous = TestClient(app, follow_redirects=False)
        response = anonymous.get("/account")
        self.assertEqual(response.status_code, 303)
        self.assertIn("/login.html", response.headers["location"])
        self.assertEqual(self.admin.get("/account").status_code, 200)
        anonymous.close()

    def test_legacy_database_promotes_first_user_to_admin(self):
        import sqlite3
        legacy = Path(self.temp_dir.name) / "legacy.db"
        connection = sqlite3.connect(legacy)
        connection.executescript(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
            " display_name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);"
            "INSERT INTO users (username, display_name, password_hash, created_at) VALUES ('first','First','x','t'),('second','Second','x','t');"
        )
        connection.commit()
        connection.close()
        with patch.object(auth_service, "AUTH_DB_PATH", legacy):
            auth_service.init_db()
            roles = {u["username"]: u["role"] for u in auth_service.list_users()}
        self.assertEqual(roles, {"first": "admin", "second": "analyst"})


if __name__ == "__main__":
    unittest.main()
