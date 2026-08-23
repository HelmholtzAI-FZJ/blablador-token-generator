"""Tests for security features: JWT secret validation, CSRF protection,
security headers, rate limiting, and OAuth state verification.
"""
import asyncio
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from app.config import Config, AppConfig
from app.api.validate import validate_token
from app.models import Token
from app.auth import hash_token, generate_token
from app.database import init_db
from app.main import app
from starlette.testclient import TestClient


def make_request() -> Request:
    """Create a minimal Request object for rate-limiter tests."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/validate",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 0),
    }
    return Request(scope)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Initialize database for all tests in this module."""
    asyncio.run(init_db())
    yield


class TestJwtSecretValidation:
    """Critical fix 1: Enforce strong JWT secret at startup."""

    def test_weak_secret_rejected(self):
        """Known weak/default secret values must be rejected."""
        for weak in ["change-me", "change-me-in-production",
                      "your-secret-key", "secret", ""]:
            with pytest.raises(ValueError, match="weak"):
                c = Config(app=AppConfig(secret_key=weak))
                c.validate_security()

    def test_short_secret_rejected(self):
        """Secrets shorter than 32 characters must be rejected."""
        with pytest.raises(ValueError, match="32 characters"):
            c = Config(app=AppConfig(secret_key="a" * 31))
            c.validate_security()

    def test_strong_secret_accepted(self):
        """A 64-character random secret should be accepted."""
        c = Config(app=AppConfig(secret_key="a" * 64))
        c.validate_security()  # Should not raise


class TestCsrfProtection:
    """Critical fix 2: Add CSRF protection via double-submit cookie."""

    def test_csrf_cookie_set_on_get(self):
        """GET requests should set a csrf_token cookie."""
        client = TestClient(app)
        r = client.get("/")
        assert "csrf_token" in r.cookies

    def test_post_without_csrf_rejected(self):
        """POST without CSRF token should be rejected (403)."""
        client = TestClient(app)
        r = client.post("/tokens", json={"name": "test"})
        assert r.status_code == 403

    def test_post_with_matching_csrf_header_passes(self):
        """POST with matching X-CSRF-Token header should pass CSRF check."""
        client = TestClient(app)
        r = client.get("/")
        csrf = r.cookies.get("csrf_token", "")
        # Should pass CSRF (may fail auth, but not with 403)
        r = client.post("/tokens", json={"name": "test"},
                        headers={"X-CSRF-Token": csrf})
        assert r.status_code != 403

    def test_post_with_mismatched_csrf_rejected(self):
        """POST with mismatched X-CSRF-Token header should be rejected."""
        client = TestClient(app)
        client.cookies.set("csrf_token", "correct-token")
        r = client.post("/tokens", json={"name": "test"},
                        headers={"X-CSRF-Token": "wrong-token"})
        assert r.status_code == 403


class TestSecurityHeaders:
    """Medium fix 1: Add security headers middleware."""

    def test_security_headers_present(self):
        """All security headers should be present on responses."""
        client = TestClient(app)
        r = client.get("/")
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"
        assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert "strict-transport-security" in r.headers


class TestTimingSafeComparison:
    """Security: use secrets.compare_digest for timing-safe comparison."""

    def test_oauth_state_uses_constant_time_comparison(self):
        """OAuth state check must use secrets.compare_digest to prevent timing attacks."""
        import inspect
        from app.main import openid_callback
        source = inspect.getsource(openid_callback)
        assert "compare_digest" in source

    def test_csrf_uses_constant_time_comparison(self):
        """CSRF validation must use secrets.compare_digest to prevent timing attacks."""
        import inspect
        from app.main import login_local
        source = inspect.getsource(login_local)
        assert "compare_digest" in source


class TestCommitErrorHandling:
    """Security: commit failures must not leave broken transaction state."""

    def test_revoke_nonexistent_token_no_crash(self):
        """Revoking a non-existent token should not crash the server."""
        import asyncio
        import httpx
        from httpx import ASGITransport
        # Use httpx + ASGI transport for correct async handling
        async def run():
            async with httpx.AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://testserver",
                headers={"x-csrf-token": "fake-csrf-for-test"}
            ) as client:
                r = await client.post("/tokens/nonexistent-id/revoke")
                # Auth guard returns 401 when no valid token; never 500 (crash)
                assert r.status_code in (401, 404, 403)
        asyncio.run(run())

    def test_delete_nonexistent_token_no_crash(self):
        """Deleting a non-existent token should not crash the server."""
        import asyncio
        import httpx
        from httpx import ASGITransport
        async def run():
            async with httpx.AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://testserver",
                headers={"x-csrf-token": "fake-csrf-for-test"}
            ) as client:
                r = await client.delete("/tokens/nonexistent-id/permanent")
                # Auth guard returns 401/403 when no valid token; never 500 (crash)
                assert r.status_code in (401, 403, 404)
        asyncio.run(run())


class TestXssMitigation:
    """Security: user-controlled data must not cause XSS in admin panel."""

    def test_admin_page_xss_sanitized(self):
        """admin.html template must escape user.name via escapeHtml."""
        # Check the escapeHtml function exists in the template
        with open("app/templates/admin.html") as f:
            content = f.read()
        assert "escapeHtml(user.email)" in content
        assert "escapeHtml(user.name)" in content


class TestRateLimitLogin:
    """Security: /login endpoint must be rate-limited."""

    def test_login_rate_limited(self):
        """The /login endpoint should have a rate limit decorator."""
        import inspect
        from app.main import login as login_fn
        source = inspect.getsource(login_fn)
        assert "@limiter.limit" in source

    def test_login_local_form_rate_limited(self):
        """The GET /login/local endpoint must be rate-limited."""
        import inspect
        from app.main import login_local_form
        source = inspect.getsource(login_local_form)
        assert "@limiter.limit" in source


class TestLastAdminProtection:
    """Security: the last remaining admin cannot be demoted or deleted."""

    async def test_detects_last_admin(self, test_db, test_admin):
        from app.api.admin import is_last_admin
        assert await is_last_admin(test_db, test_admin.id)

    async def test_not_last_admin_when_multiple(self, test_db, test_admin):
        from app.models import User
        from app.api.admin import is_last_admin
        second_admin = User(
            unity_id="admin-789",
            email="second-admin@example.com",
            name="Second Admin",
            is_admin=True,
        )
        test_db.add(second_admin)
        await test_db.commit()
        assert not await is_last_admin(test_db, test_admin.id)

    async def test_is_last_admin_false_for_non_admin(self, test_db, test_user):
        from app.api.admin import is_last_admin
        assert not await is_last_admin(test_db, test_user.id)
