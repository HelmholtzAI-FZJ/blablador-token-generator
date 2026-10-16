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


class captured_logs:
    """Collect records of an app logger (they do not propagate to root)."""

    def __init__(self, name: str = "token_generator.audit"):
        import logging
        self.logger = logging.getLogger(name)
        self.records = []
        self.handler = logging.Handler()
        self.handler.emit = self.records.append

    def __enter__(self):
        self.logger.addHandler(self.handler)
        return self.records

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)


HTML = {"Accept": "text/html,application/xhtml+xml"}


def cleared(response, name: str) -> bool:
    return any(header.startswith(f"{name}=") and "Max-Age=0" in header
               for header in response.headers.get_list("set-cookie"))


class TestBrowserErrors:
    def test_login_is_404_without_oauth(self, monkeypatch):
        monkeypatch.setattr(main.config.oauth, "client_id", "")
        client = TestClient(app, follow_redirects=False)
        response = client.get("/login", headers=HTML)
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("text/html")
        assert "oauth_state" not in response.cookies
        assert client.get("/oauth/openid/callback", params={"code": "c"}).status_code == 404

    def test_provider_error_renders_page_and_clears_flow_cookies(self):
        client = TestClient(app, follow_redirects=False)
        client.cookies.set("oauth_state", "state")
        client.cookies.set("oauth_verifier", "v" * 43)
        with captured_logs() as records:
            response = client.get("/oauth/openid/callback",
                                  params={"error": "access_denied"}, headers=HTML)
            hostile = client.get("/oauth/openid/callback", params={"error": "x\nforged=1"})
        assert response.status_code == 400
        assert response.headers["content-type"].startswith("text/html")
        assert "cancelled" in response.text
        assert cleared(response, "oauth_state") and cleared(response, "oauth_verifier")
        assert hostile.status_code == 400
        messages = [record.getMessage() for record in records]
        assert "action=oauth_authorization_failed error=access_denied" in messages
        assert "action=oauth_authorization_failed error=unrecognized" in messages

    def test_expired_state_and_missing_code(self):
        client = TestClient(app, follow_redirects=False)
        assert client.get("/oauth/openid/callback", params={"state": "s", "code": "c"}).status_code == 400
        client.cookies.set("oauth_state", "s")
        client.cookies.set("oauth_verifier", "v" * 43)
        response = client.get("/oauth/openid/callback", params={"state": "s"})
        assert response.status_code == 400
        assert "authorization code" in response.text

    def test_disabled_account_gets_403_page(self, monkeypatch):
        from fastapi import HTTPException

        async def fake_userinfo(code, code_verifier):
            return {"sub": "disabled-sub", "email": "d@example.com"}

        async def disabled(userinfo, db):
            raise HTTPException(status_code=403, detail="Account has been disabled. Contact an administrator.")

        monkeypatch.setattr(main, "get_unity_userinfo", fake_userinfo)
        monkeypatch.setattr(main, "get_or_create_user", disabled)
        client = TestClient(app, follow_redirects=False)
        client.cookies.set("oauth_state", "s")
        client.cookies.set("oauth_verifier", "v" * 43)
        response = client.get("/oauth/openid/callback", params={"state": "s", "code": "c"}, headers=HTML)
        assert response.status_code == 403
        assert "Contact an administrator" in response.text
        assert "__Host-access_token" not in response.text and "access_token" not in response.cookies

    def test_provider_outage_is_503_page(self, monkeypatch):
        from fastapi import HTTPException

        async def outage(code, code_verifier):
            raise HTTPException(status_code=503, detail="Authentication provider temporarily unavailable")

        monkeypatch.setattr(main, "get_unity_userinfo", outage)
        client = TestClient(app, follow_redirects=False)
        client.cookies.set("oauth_state", "s")
        client.cookies.set("oauth_verifier", "v" * 43)
        response = client.get("/oauth/openid/callback", params={"state": "s", "code": "c"})
        assert response.status_code == 503
        assert "temporarily unavailable" in response.text

    def test_unknown_page_is_html_for_browsers_json_for_apis(self):
        client = TestClient(app)
        page = client.get("/no-such-page", headers=HTML)
        assert page.status_code == 404
        assert page.headers["content-type"].startswith("text/html")
        assert "Not Found" in page.text
        api = client.get("/api/v1/no-such-endpoint", headers=HTML)
        assert api.status_code == 404 and api.json() == {"detail": "Not Found"}
        assert client.get("/no-such-page").json() == {"detail": "Not Found"}

    def test_error_pages_keep_security_headers(self):
        response = TestClient(app).get("/no-such-page", headers=HTML)
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"


class TestReadiness:
    def test_ready_with_database_and_storage(self):
        response = TestClient(app).get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "rate_limit_storage": "ok"}

    def test_rate_limit_storage_outage_degrades_but_stays_ready(self, monkeypatch):
        monkeypatch.setattr(main.limiter._storage, "check", lambda: False)
        with captured_logs() as records:
            response = TestClient(app).get("/readyz")
        assert response.status_code == 200
        assert response.json()["rate_limit_storage"] == "degraded"
        assert any("readiness_degraded dependency=rate_limit_storage" in r.getMessage() for r in records)

    def test_database_outage_fails_readiness(self, monkeypatch):
        def broken_session():
            raise RuntimeError("synthetic database outage")

        monkeypatch.setattr(main.database_module, "async_session_maker", broken_session)
        response = TestClient(app).get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}


class TestValidationApiContract:
    def test_missing_token_is_401_not_csrf_403(self):
        response = TestClient(app).post("/api/v1/auth/validate")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_scheme_is_case_insensitive(self, monkeypatch):
        with TestClient(app, follow_redirects=False) as client:
            csrf = login(client, monkeypatch, "scheme-user")
            token = client.post("/tokens", json={"name": "scheme"},
                                headers={"X-CSRF-Token": csrf}).json()["token"]
        api = TestClient(app)
        for scheme in ("Bearer", "bearer", "BEARER"):
            response = api.post("/api/v1/auth/validate", headers={"Authorization": f"{scheme} {token}"})
            assert response.status_code == 200, scheme
            assert response.json()["valid"] is True
        assert api.post("/api/v1/auth/validate", headers={"Authorization": f"Basic {token}"}).status_code == 401

    def test_unknown_token_401_has_challenge(self):
        response = TestClient(app).post("/api/v1/auth/validate",
                                        headers={"Authorization": "Bearer blablador-" + "0" * 64})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_cookie_endpoints_still_require_csrf(self):
        client = TestClient(app)
        client.cookies.set("csrf_token", "abc")
        assert client.post("/tokens", json={"name": "x"},
                           headers={"Authorization": "Bearer x"}).status_code == 403
