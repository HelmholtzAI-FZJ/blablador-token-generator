"""Regression tests for the production-readiness fixes (October 2026)."""
import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from starlette.testclient import TestClient

import app.main as main
from app.database import build_engine, init_db
from app.main import app
from app.timeutil import isoformat_utc, utcnow
from tests.conftest import drop_schema


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    asyncio.run(init_db())
    yield

    async def drop():
        # Leave a shared (PostgreSQL) test database empty for later modules.
        engine = build_engine(os.environ["DATABASE_URL"])
        async with engine.begin() as conn:
            await drop_schema(conn)
        await engine.dispose()

    asyncio.run(drop())


@pytest.fixture
def client():
    # One event loop for the whole test: asyncpg connections are bound to
    # the loop that opened them, and the lifespan gives a fresh engine.
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


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

    def test_api_and_dashboard_timestamps_carry_offsets(self, client, monkeypatch):
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
    def test_login_is_404_without_oauth(self, client, monkeypatch):
        monkeypatch.setattr(main.config.oauth, "client_id", "")
        response = client.get("/login", headers=HTML)
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("text/html")
        assert "oauth_state" not in response.cookies
        assert client.get("/oauth/openid/callback", params={"code": "c"}).status_code == 404

    def test_provider_error_renders_page_and_clears_flow_cookies(self, client):
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

    def test_expired_state_and_missing_code(self, client):
        assert client.get("/oauth/openid/callback", params={"state": "s", "code": "c"}).status_code == 400
        client.cookies.set("oauth_state", "s")
        client.cookies.set("oauth_verifier", "v" * 43)
        response = client.get("/oauth/openid/callback", params={"state": "s"})
        assert response.status_code == 400
        assert "authorization code" in response.text

    def test_disabled_account_gets_403_page(self, client, monkeypatch):
        from fastapi import HTTPException

        async def fake_userinfo(code, code_verifier):
            return {"sub": "disabled-sub", "email": "d@example.com"}

        async def disabled(userinfo, db):
            raise HTTPException(status_code=403, detail="Account has been disabled. Contact an administrator.")

        monkeypatch.setattr(main, "get_unity_userinfo", fake_userinfo)
        monkeypatch.setattr(main, "get_or_create_user", disabled)
        client.cookies.set("oauth_state", "s")
        client.cookies.set("oauth_verifier", "v" * 43)
        response = client.get("/oauth/openid/callback", params={"state": "s", "code": "c"}, headers=HTML)
        assert response.status_code == 403
        assert "Contact an administrator" in response.text
        assert "__Host-access_token" not in response.text and "access_token" not in response.cookies

    def test_provider_outage_is_503_page(self, client, monkeypatch):
        from fastapi import HTTPException

        async def outage(code, code_verifier):
            raise HTTPException(status_code=503, detail="Authentication provider temporarily unavailable")

        monkeypatch.setattr(main, "get_unity_userinfo", outage)
        client.cookies.set("oauth_state", "s")
        client.cookies.set("oauth_verifier", "v" * 43)
        response = client.get("/oauth/openid/callback", params={"state": "s", "code": "c"})
        assert response.status_code == 503
        assert "temporarily unavailable" in response.text

    def test_unknown_page_is_html_for_browsers_json_for_apis(self, client):
        page = client.get("/no-such-page", headers=HTML)
        assert page.status_code == 404
        assert page.headers["content-type"].startswith("text/html")
        assert "Not Found" in page.text
        api = client.get("/api/v1/no-such-endpoint", headers=HTML)
        assert api.status_code == 404 and api.json() == {"detail": "Not Found"}
        assert client.get("/no-such-page").json() == {"detail": "Not Found"}

    def test_error_pages_keep_security_headers(self, client):
        response = client.get("/no-such-page", headers=HTML)
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"


class TestReadiness:
    def test_ready_with_database_and_storage(self, client):
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "rate_limit_storage": "ok"}

    def test_rate_limit_storage_outage_degrades_but_stays_ready(self, client, monkeypatch):
        def refuse_writes(*args, **kwargs):
            # What a full (maxmemory, noeviction) Redis does; it still answers pings.
            raise RuntimeError("OOM command not allowed")

        monkeypatch.setattr(main.limiter._storage, "incr", refuse_writes)
        with captured_logs() as records:
            response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["rate_limit_storage"] == "degraded"
        assert any("readiness_degraded dependency=rate_limit_storage" in r.getMessage() for r in records)

    def test_database_outage_fails_readiness(self, client, monkeypatch):
        def broken_session():
            raise RuntimeError("synthetic database outage")

        monkeypatch.setattr(main.database_module, "async_session_maker", broken_session)
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}


class TestValidationApiContract:
    def test_missing_token_is_401_not_csrf_403(self, client):
        response = client.post("/api/v1/auth/validate")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_scheme_is_case_insensitive(self, client, monkeypatch):
        csrf = login(client, monkeypatch, "scheme-user")
        token = client.post("/tokens", json={"name": "scheme"},
                            headers={"X-CSRF-Token": csrf}).json()["token"]
        client.cookies.clear()
        for scheme in ("Bearer", "bearer", "BEARER"):
            response = client.post("/api/v1/auth/validate", headers={"Authorization": f"{scheme} {token}"})
            assert response.status_code == 200, scheme
            assert response.json()["valid"] is True
        assert client.post("/api/v1/auth/validate", headers={"Authorization": f"Basic {token}"}).status_code == 401

    def test_unknown_token_401_has_challenge(self, client):
        response = client.post("/api/v1/auth/validate",
                                        headers={"Authorization": "Bearer blablador-" + "0" * 64})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_cookie_endpoints_still_require_csrf(self, client):
        client.cookies.set("csrf_token", "abc")
        assert client.post("/tokens", json={"name": "x"},
                           headers={"Authorization": "Bearer x"}).status_code == 403


class TestAccessLog:
    def test_logs_route_template_status_and_duration(self, client):
        with captured_logs("token_generator.access") as records:
            client.get("/tokens/abc/permanent")
            client.get("/tokens")
        messages = [record.getMessage() for record in records]
        assert any(m.startswith("method=GET route=/tokens status=401 duration_ms=") for m in messages)
        assert all("abc" not in m for m in messages)

    def test_never_logs_query_strings_or_unmatched_paths(self, client):
        secret_code = "synthetic-authorization-code"
        with captured_logs("token_generator.access") as records:
            client.get("/oauth/openid/callback", params={"code": secret_code, "state": "s"})
            client.get("/probe-for-something-secret")
        messages = [record.getMessage() for record in records]
        assert any("route=/oauth/openid/callback status=400" in m for m in messages)
        assert any("route=unmatched status=404" in m for m in messages)
        assert not any(secret_code in m or "something-secret" in m for m in messages)

    def test_probes_are_not_logged(self, client):
        with captured_logs("token_generator.access") as records:
            client.get("/healthz")
            client.get("/readyz")
        assert records == []

    def test_admission_rejections_are_logged(self, client, monkeypatch):
        from limits import parse
        admission = client.app.middleware_stack
        while not hasattr(admission, "budget"):
            admission = admission.app
        monkeypatch.setattr(admission, "budget", parse("1/minute"))
        monkeypatch.setattr(admission, "storage_retry_at", float("inf"))
        with captured_logs("token_generator.access") as records:
            client.get("/")
            client.get("/")
        statuses = [record.getMessage().split("status=")[1].split()[0] for record in records]
        assert statuses[-1] == "429"


def make_admin(client: TestClient, subject: str) -> None:
    """Promote an OAuth account created by login() (bootstrap rules only
    apply to new accounts, so tests set the role directly). Runs on the
    client's event loop, which owns the pooled connections."""
    from sqlalchemy import update
    from app import database
    from app.models import User

    async def promote():
        async with database.async_session_maker() as db:
            await db.execute(update(User).where(User.unity_id == subject).values(is_admin=True))
            await db.commit()

    client.portal.call(promote)


class TestAdminPages:
    def test_token_page_paginates(self, client, monkeypatch):
        login(client, monkeypatch, "page-admin")
        make_admin(client, "page-admin")
        csrf = login(client, monkeypatch, "page-admin")
        for index in range(3):
            assert client.post("/tokens", json={"name": f"paged-{index}"},
                               headers={"X-CSRF-Token": csrf}).status_code == 200
        first = client.get("/admin/tokens")
        assert first.status_code == 200
        assert 'name="current-user-id"' in first.text
        beyond = client.get("/admin/tokens", params={"page": 100000})
        assert beyond.status_code == 200
        assert "No tokens on this page." in beyond.text
        assert 'href="/admin/tokens?page=99999"' in beyond.text

    def test_admin_can_change_roles_through_the_api(self, client, monkeypatch):
        login(client, monkeypatch, "role-target")
        login(client, monkeypatch, "role-admin")
        make_admin(client, "role-admin")
        csrf = login(client, monkeypatch, "role-admin")
        users = client.get("/api/admin/users", params={"page_size": 100}).json()
        target = next(user for user in users if user["unity_id"] == "role-target")
        promoted = client.patch(f"/api/admin/users/{target['id']}", json={"is_admin": True},
                                headers={"X-CSRF-Token": csrf})
        assert promoted.status_code == 200 and promoted.json()["is_admin"] is True
        demoted = client.patch(f"/api/admin/users/{target['id']}", json={"is_admin": False},
                               headers={"X-CSRF-Token": csrf})
        assert demoted.status_code == 200 and demoted.json()["is_admin"] is False


def test_versions_agree():
    import tomllib
    from pathlib import Path

    import yaml

    from app import __version__

    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    chart = yaml.safe_load((root / "helm/blablador-token-generator/Chart.yaml").read_text())
    assert __version__ == project == chart["appVersion"]


def test_configuration_reference_documents_every_setting():
    from pathlib import Path

    from app.config import Config

    text = (Path(__file__).resolve().parents[1] / "docs/configuration.md").read_text()
    missing = []
    for section, field in Config.model_fields.items():
        heading = f"## `{section}`"
        assert heading in text, f"docs/configuration.md lacks a {heading} section"
        body = text.split(heading, 1)[1].split("\n## ", 1)[0]
        missing += [f"{section}.{name}" for name in field.annotation.model_fields if f"`{name}`" not in body]
    assert missing == [], f"undocumented settings: {missing}"


class TestExpiredSessions:
    def expired_session(self) -> str:
        import jwt

        from app.auth import config as auth_config

        payload = {"sub": "someone", "jti": "expired-session", "sep": 0,
                   "exp": datetime.now(UTC) - timedelta(minutes=1)}
        return jwt.encode(payload, auth_config.app.secret_key, algorithm="HS256")

    def test_pages_send_expired_sessions_back_to_sign_in(self, client):
        client.cookies.set("access_token", self.expired_session())
        response = client.get("/dashboard", headers=HTML)
        assert response.status_code == 303
        assert response.headers["location"] == "/"

    def test_api_calls_with_expired_sessions_get_401(self, client):
        client.cookies.set("access_token", self.expired_session())
        response = client.get("/tokens")
        assert response.status_code == 401
        assert response.json() == {"detail": "Authentication required"}
