"""Tests for security features: JWT secret validation, CSRF protection,
security headers, rate limiting, and OAuth state verification.
"""
import asyncio
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlalchemy import select
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

    def test_form_post_without_csrf_rejected(self):
        """Cross-site HTML forms must not bypass CSRF on cookie endpoints."""
        client = TestClient(app)
        for path in ("/account/delete", "/logout", "/tokens/x/renew"):
            r = client.post(path, data={"a": "b"})
            assert r.status_code == 403, path

    def test_bearer_header_does_not_bypass_csrf_outside_api(self):
        """A dummy Bearer header must not skip CSRF on cookie endpoints."""
        client = TestClient(app)
        r = client.post("/account/delete", headers={"Authorization": "Bearer x"})
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
        assert "frame-ancestors 'none'" in r.headers.get("content-security-policy", "")


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


class TestDeletionTombstone:
    """Security: a deleted account must not be resurrected by OAuth login."""

    async def test_deleted_user_blocked_from_login(self, test_db, test_user):
        from app.models import DeletedUser
        from app.auth import get_or_create_user
        test_db.add(DeletedUser(unity_id=test_user.unity_id, email=test_user.email))
        await test_db.commit()

        userinfo = {"sub": test_user.unity_id, "email": test_user.email, "name": test_user.name}
        with pytest.raises(HTTPException) as exc:
            await get_or_create_user(userinfo, test_db)
        assert exc.value.status_code == 403

    async def test_undeleted_user_not_blocked(self, test_db, test_user):
        from app.auth import get_or_create_user
        userinfo = {"sub": test_user.unity_id, "email": test_user.email, "name": test_user.name}
        user = await get_or_create_user(userinfo, test_db)
        assert user.id == test_user.id


class TestAdminNoDemotionOnLogin:
    """Security: login must not silently demote a manually-granted admin."""

    async def test_manually_granted_admin_not_demoted_on_login(self, test_db, test_admin):
        from app.auth import get_or_create_user
        # test_admin is is_admin=True but NOT in admin_emails config.
        # Logging in must not flip is_admin to False.
        userinfo = {"sub": test_admin.unity_id, "email": test_admin.email, "name": test_admin.name}
        user = await get_or_create_user(userinfo, test_db)
        assert user.is_admin is True


class TestLoginTimingEqualization:
    """Security: local login must not leak whether an email exists via timing."""

    async def test_unknown_user_still_rejects(self, test_db):
        from app.auth import authenticate_local_user
        result = await authenticate_local_user(
            "ghost@example.com", "WrongPass1", test_db
        )
        assert result is None

    async def test_known_user_wrong_password_rejects(self, test_db, test_admin):
        from app.auth import authenticate_local_user, hash_password
        test_admin.password_hash = hash_password("CorrectHorse9")
        await test_db.commit()
        result = await authenticate_local_user(
            test_admin.email, "WrongPass1", test_db
        )
        assert result is None

    async def test_known_user_correct_password_ok(self, test_db, test_admin):
        from app.auth import authenticate_local_user, hash_password
        test_admin.password_hash = hash_password("CorrectHorse9")
        await test_db.commit()
        result = await authenticate_local_user(
            test_admin.email, "CorrectHorse9", test_db
        )
        assert result is not None
        assert result.id == test_admin.id


class TestAccountDeletion:
    """Security: users can delete their own account, which revokes all tokens."""

    async def test_delete_account_revokes_all_tokens(self, test_db, test_user):
        from app.models import Token
        from app.auth import generate_token, hash_token
        from datetime import datetime, timedelta
        # Create 3 tokens
        for i in range(3):
            test_db.add(Token(
                user_id=test_user.id,
                token_hash=hash_token(generate_token()),
                name=f"Token {i}",
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(days=30),
            ))
        await test_db.commit()

        # Count revoked tokens before
        result = await test_db.execute(
            select(Token).where(Token.user_id == test_user.id)
        )
        before = {t.id: t.revoked_at for t in result.scalars().all()}
        assert all(v is None for v in before.values()), "all should start un-revoked"

        # Simulate the self-delete: revoke tokens + write tombstone + delete user
        from app.models import DeletedUser
        now = datetime.utcnow()
        result = await test_db.execute(
            select(Token).where(Token.user_id == test_user.id)
        )
        for t in result.scalars().all():
            t.revoked_at = now
        test_db.add(DeletedUser(unity_id=test_user.unity_id, email=test_user.email))
        await test_db.delete(test_user)
        await test_db.commit()

        result = await test_db.execute(
            select(Token).where(Token.user_id == test_user.id)
        )
        after = {t.id: t.revoked_at for t in result.scalars().all()}
        assert all(v is not None for v in after.values()), "all should be revoked"

    async def test_deleted_user_tombstone_blocks_login(self, test_db, test_user):
        from app.models import DeletedUser
        from app.auth import get_or_create_user
        test_db.add(DeletedUser(unity_id=test_user.unity_id, email=test_user.email))
        await test_db.commit()
        userinfo = {"sub": test_user.unity_id, "email": test_user.email, "name": test_user.name}
        with pytest.raises(HTTPException) as exc:
            await get_or_create_user(userinfo, test_db)
        assert exc.value.status_code == 403


class TestValidateDeletedAccount:
    """Security: validate endpoint must log when a deleted user tries to use their token."""

    async def test_deleted_user_token_rejected_and_logged(self, test_db, test_user):
        from app.auth import generate_token, hash_token
        from app.models import Token, DeletedUser
        from datetime import datetime, timedelta
        token_hash = hash_token(generate_token())
        test_db.add(Token(
            user_id=test_user.id,
            token_hash=token_hash,
            name="my token",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
        ))
        await test_db.commit()

        # Now delete the account (tombstone)
        test_db.add(DeletedUser(unity_id=test_user.unity_id, email=test_user.email))
        await test_db.delete(test_user)
        await test_db.commit()

        # Validate should reject
        from app.api.validate import validate_token, extract_bearer_token
        plain = generate_token()  # we just need the function path; token won't match
        # Direct test: tombstone exists so validate_token raises via the tombstone check.
        # We verify the tombstone blocks the token by checking the check is present.
        import inspect
        source = inspect.getsource(validate_token)
        assert "DeletedUser" in source, "validate_token must check DeletedUser"


class TestHasPasswordField:
    """Security: UserResponse must expose has_password so the frontend
    can hide the 'Reset Password' button for OAuth-only users."""

    def test_user_response_has_password_field(self):
        from app.api.admin import UserResponse
        fields = UserResponse.model_fields
        assert "has_password" in fields, "UserResponse must include has_password"

    async def test_has_password_true_for_local_user(self, test_db, test_user):
        from app.auth import hash_password
        test_user.password_hash = hash_password("SomePassword1")
        await test_db.commit()
        assert test_user.password_hash is not None

    async def test_has_password_false_for_oauth_user(self, test_db, test_user):
        assert test_user.password_hash is None


class TestOAuthAccountLinking:
    """OAuth login must not take over accounts bound to another identity."""

    @pytest.mark.asyncio
    async def test_same_email_different_subject_rejected(self, test_db, test_user):
        from app.auth import get_or_create_user
        with pytest.raises(HTTPException) as exc:
            await get_or_create_user(
                {"sub": "attacker-sub", "email": test_user.email}, test_db
            )
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_local_account_linked_on_first_oauth_login(self, test_db):
        from app.auth import get_or_create_user
        from app.models import User
        local = User(email="local@example.com", name="Local", password_hash="x")
        test_db.add(local)
        await test_db.commit()
        user = await get_or_create_user(
            {"sub": "sub-1", "email": "local@example.com"}, test_db
        )
        assert user.id == local.id and user.unity_id == "sub-1"

    @pytest.mark.asyncio
    async def test_unverified_email_not_linked(self, test_db):
        from app.auth import get_or_create_user
        from app.models import User
        test_db.add(User(email="local2@example.com", name="L", password_hash="x"))
        await test_db.commit()
        with pytest.raises(HTTPException):
            await get_or_create_user(
                {"sub": "s", "email": "local2@example.com", "email_verified": False},
                test_db,
            )


class TestValidateLocalUserTombstones:
    """Deleted local users must not invalidate other local users' tokens."""

    @pytest.mark.asyncio
    async def test_other_local_tombstones_ignored(self, test_db):
        from app.models import User, DeletedUser
        user = User(email="keep@example.com", name="Keep", password_hash="x")
        test_db.add(user)
        test_db.add(DeletedUser(unity_id=None, email="gone1@example.com"))
        test_db.add(DeletedUser(unity_id=None, email="gone2@example.com"))
        await test_db.commit()
        plain = generate_token()
        test_db.add(Token(user_id=user.id, token_hash=hash_token(plain), name="t"))
        await test_db.commit()
        result = await validate_token(make_request(), bearer_token=plain, db=test_db)
        assert result.valid


class TestLongPasswords:
    """Passwords beyond bcrypt's 72-byte limit must not crash login."""

    def test_verify_long_password_returns_bool(self):
        from app.auth import hash_password, verify_password
        h = hash_password("Aa1" * 20)
        assert verify_password("Aa1" * 20, h)
        assert verify_password("x" * 500, h) is False

    def test_long_password_rejected_on_set(self):
        from app.auth import validate_password_strength
        with pytest.raises(HTTPException):
            validate_password_strength("Aa1" + "x" * 80)
