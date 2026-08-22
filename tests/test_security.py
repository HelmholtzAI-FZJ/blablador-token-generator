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
