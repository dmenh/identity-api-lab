"""Isolated default database; TEST_DATABASE_URL opts into a disposable external DB."""
import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_temporary = tempfile.TemporaryDirectory(prefix="identity-lab-tests-")
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite:///" + (Path(_temporary.name) / "test.db").as_posix())
os.environ["ADMIN_PASSWORD"] = "Lab-Test-2026!"
os.environ["AUTH_LOGIN_RATE_LIMIT"] = "1000"
os.environ["OAUTH_TOKEN_RATE_LIMIT"] = "1000"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from main import app  # noqa: E402


@pytest.fixture
def client():
    with TestClient(app) as session:
        yield session


@pytest.fixture
def admin(client):
    response = client.post("/auth/login", json={"username": "admin", "password": "Lab-Test-2026!"})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrfToken"]
    return client
