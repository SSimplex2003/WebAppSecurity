import os
import sys
import tempfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

# Must be set before the app is imported: settings are read at import time.
TEST_DB_FILE = Path(tempfile.mkdtemp(prefix="vault-tests-")) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_FILE.as_posix()}"
os.environ["REDIS_URL"] = ""
os.environ["COOKIE_SECURE"] = "true"
os.environ["ENABLE_HSTS"] = "false"
os.environ["SESSION_IDLE_SECONDS"] = "900"
os.environ["SESSION_ABSOLUTE_SECONDS"] = "43200"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import ratelimit  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    ratelimit.reset_all()
    yield


@pytest.fixture()
def make_client():
    clients = []

    def factory() -> TestClient:
        client = TestClient(app, base_url="https://testserver")
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture()
def client(make_client):
    return make_client()


@pytest.fixture()
def db_file() -> Path:
    return TEST_DB_FILE
