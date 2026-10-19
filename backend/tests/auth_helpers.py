"""Helpers for authenticated API tests."""
import secrets
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import auth as auth_service
from main import app

_TEST_DATABASE_DIR = tempfile.TemporaryDirectory(prefix="bharatsec-auth-tests-")
_TEST_DATABASE_PATH = Path(_TEST_DATABASE_DIR.name) / "auth.db"
_TEST_USERNAME = f"test-{secrets.token_hex(8)}"
_TEST_PASSWORD = f"Test-{secrets.token_urlsafe(18)}"
_ACCOUNT_CREATED = False


def authenticated_client() -> TestClient:
    global _ACCOUNT_CREATED
    auth_service.AUTH_DB_PATH = _TEST_DATABASE_PATH
    auth_service.init_db()
    client = TestClient(app)
    if not _ACCOUNT_CREATED:
        response = client.post(
            "/api/auth/register",
            json={
                "username": _TEST_USERNAME,
                "password": _TEST_PASSWORD,
                "display_name": "Test User",
            },
        )
        if response.status_code != 201:
            client.close()
            raise RuntimeError(f"Could not create test account: {response.status_code} {response.text}")
        _ACCOUNT_CREATED = True
    else:
        response = client.post(
            "/api/auth/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        if response.status_code != 200:
            client.close()
            raise RuntimeError(f"Could not sign in test account: {response.status_code} {response.text}")
    if response.status_code not in {200, 201}:
        client.close()
        raise RuntimeError(f"Could not authenticate test account: {response.status_code} {response.text}")
    return client
