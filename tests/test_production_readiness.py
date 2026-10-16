"""Regression tests for the production-readiness fixes (October 2026)."""
import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from starlette.testclient import TestClient

import app.main as main
from app.database import init_db
from app.main import app
from app.timeutil import isoformat_utc, utcnow


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    asyncio.run(init_db())
    yield


def login(client: TestClient, monkeypatch, subject: str) -> str:
    """Sign in through the OAuth callback; returns the CSRF token."""
    async def fake_userinfo(code, code_verifier):
        return {"sub": subject, "email": f"{subject}@example.com", "name": subject}

    monkeypatch.setattr(main, "get_unity_userinfo", fake_userinfo)
    client.cookies.set("oauth_state", "state")
    client.cookies.set("oauth_verifier", "v" * 43)
    response = client.get("/oauth/openid/callback", params={"state": "state", "code": "code"})
    assert response.status_code == 303
    client.get("/")
    return client.cookies.get("csrf_token")


class TestUtcTimestamps:
    def test_utcnow_is_naive_utc(self):
        before = datetime.now(UTC).replace(tzinfo=None)
        now = utcnow()
        assert now.tzinfo is None
        assert before <= now <= datetime.now(UTC).replace(tzinfo=None)

    def test_isoformat_utc_adds_offset(self):
        assert isoformat_utc(None) is None
        assert isoformat_utc(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05+00:00"
        aware = datetime(2026, 1, 2, 5, 4, 5, tzinfo=UTC) + timedelta(hours=0)
        assert isoformat_utc(aware.astimezone()) == "2026-01-02T05:04:05+00:00"

    def test_api_and_dashboard_timestamps_carry_offsets(self, monkeypatch):
        with TestClient(app, follow_redirects=False) as client:
            csrf = login(client, monkeypatch, "tz-user")
            created = client.post("/tokens", json={"name": "tz", "expires_in_days": 5},
                                  headers={"X-CSRF-Token": csrf})
            assert created.status_code == 200, created.text
            body = created.json()
            assert body["created_at"].endswith("+00:00")
            assert body["expires_at"].endswith("+00:00")
            listed = client.get("/tokens").json()
            assert all(t["created_at"].endswith("+00:00") for t in listed)
            page = client.get("/dashboard").text
            assert 'data-utc="' in page
            assert f'data-expires="{body["expires_at"]}"' in page
