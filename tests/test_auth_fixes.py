import asyncio
import threading
from datetime import datetime, timedelta

import httpx
import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import Request

import app.auth as auth
from app.database import build_engine
from app.models import Base, RevokedJWT, User
from app.tombstones import record_deletion
from app.timeutil import utcnow


def cookie_request(token: str) -> Request:
    return Request({
        "type": "http", "method": "GET", "path": "/dashboard", "query_string": b"",
        "headers": [(b"cookie", f"{auth.SESSION_COOKIE}={token}".encode())],
        "client": ("127.0.0.90", 10000),
    })


@pytest.mark.asyncio
async def test_configured_admin_stays_demoted_on_login(test_db, monkeypatch):
    monkeypatch.setattr(auth.config.admin, "admin_subjects", ["configured-admin"])
    profile = {"sub": "configured-admin", "email": "admin@example.com"}
    user = await auth.get_or_create_user(profile, test_db)
    assert user.is_admin
    user.is_admin = False
    await auth.invalidate_sessions(user, test_db)
    await test_db.commit()
    assert not (await auth.get_or_create_user(profile, test_db)).is_admin


@pytest.mark.asyncio
async def test_adding_existing_subject_to_config_does_not_promote_old_session(test_db, monkeypatch):
    monkeypatch.setattr(auth.config.admin, "admin_subjects", [])
    monkeypatch.setattr(auth.config.admin, "admin_emails", [])
    profile = {"sub": "existing-subject", "email": "existing@example.com"}
    user = await auth.get_or_create_user(profile, test_db)
    old_session = auth.create_session_token(user)
    monkeypatch.setattr(auth.config.admin, "admin_subjects", [profile["sub"]])
    await auth.get_or_create_user(profile, test_db)
    current = await auth.get_current_user(cookie_request(old_session), test_db)
    assert not current.is_admin
    with pytest.raises(HTTPException) as failure:
        await auth.get_current_admin(current)
    assert failure.value.status_code == 403


@pytest.mark.asyncio
async def test_verified_email_only_bootstraps_admin_for_new_user(test_db, monkeypatch):
    monkeypatch.setattr(auth.config.admin, "admin_emails", ["boss@example.com"])
    unverified = await auth.get_or_create_user({"sub": "unverified", "email": "boss@example.com"}, test_db)
    verified = await auth.get_or_create_user(
        {"sub": "verified", "email": "boss@example.com", "email_verified": True}, test_db
    )
    assert not unverified.is_admin
    assert verified.is_admin
    again = await auth.get_or_create_user(
        {"sub": "unverified", "email": "boss@example.com", "email_verified": True}, test_db
    )
    assert not again.is_admin


@pytest.mark.asyncio
async def test_revocation_failure_is_visible_and_sanitized(test_db, test_user, monkeypatch):
    token = auth.create_session_token(test_user)
    payload = auth.decode_access_token(token)
    logs = []
    monkeypatch.setattr(auth._audit, "error", lambda *args: logs.append(args))
    original_commit = test_db.commit

    async def failed_commit() -> None:
        raise RuntimeError(f"sensitive-token={token}")

    monkeypatch.setattr(test_db, "commit", failed_commit)
    with pytest.raises(HTTPException) as failure:
        await auth.revoke_jwt(payload, test_db)
    assert failure.value.status_code == 503
    assert token not in str(logs) + str(failure.value.detail)
    monkeypatch.setattr(test_db, "commit", original_commit)
    assert (await test_db.execute(select(RevokedJWT).where(RevokedJWT.jti == payload["jti"]))).first() is None
    assert await auth.get_current_user(cookie_request(token), test_db)


@pytest.mark.asyncio
async def test_successful_revocation_is_idempotent_and_rejects_replay(test_db, test_user):
    token = auth.create_session_token(test_user)
    payload = auth.decode_access_token(token)
    await auth.revoke_jwt(payload, test_db)
    await auth.revoke_jwt(payload, test_db)
    with pytest.raises(HTTPException):
        await auth.get_current_user(cookie_request(token), test_db)


@pytest.mark.asyncio
async def test_stale_security_updates_increment_epoch_and_reject_intermediate_session(tmp_path):
    engine = build_engine(f"sqlite+aiosqlite:///{tmp_path}/epoch.db")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as seed:
            user = User(email="epoch@example.com", name="Epoch")
            seed.add(user)
            await seed.commit()
            user_id = user.id
        async with sessions() as first, sessions() as second:
            first_user = (await first.execute(select(User).where(User.id == user_id))).scalar_one()
            second_user = (await second.execute(select(User).where(User.id == user_id))).scalar_one()
            assert first_user.session_epoch == second_user.session_epoch == 0
            await auth.invalidate_sessions(first_user, first)
            await first.commit()
            intermediate_session = auth.create_session_token(first_user)
            assert second_user.session_epoch == 0
            await auth.invalidate_sessions(second_user, second)
            await second.commit()
            assert second_user.session_epoch == 2
        async with sessions() as verify:
            with pytest.raises(HTTPException):
                await auth.get_current_user(cookie_request(intermediate_session), verify)
    finally:
        await engine.dispose()


@pytest.mark.parametrize("claim", ["jti", "sep", "sub", "exp"])
def test_session_requires_security_claims(claim):
    payload = {"sub": "user", "jti": "test-session", "sep": 0, "exp": utcnow() + timedelta(hours=1)}
    payload.pop(claim)
    token = jwt.encode(payload, auth.config.app.secret_key, algorithm="HS256")
    with pytest.raises(HTTPException) as failure:
        auth.decode_access_token(token)
    assert failure.value.status_code == 401


@pytest.mark.parametrize("epoch", [True, "0", -1, 0.0])
def test_session_epoch_has_strict_integer_type(epoch):
    token = auth.create_access_token({"sub": "user", "sep": epoch})
    with pytest.raises(HTTPException):
        auth.decode_access_token(token)


def test_admin_session_has_shorter_configured_lifetime(test_user, test_admin):
    regular = auth.decode_access_token(auth.create_session_token(test_user))
    admin = auth.decode_access_token(auth.create_session_token(test_admin))
    difference = regular["exp"] - admin["exp"]
    expected = (auth.config.app.jwt_expiration_hours - auth.config.app.admin_jwt_expiration_hours) * 3600
    assert abs(difference - expected) <= 1


@pytest.mark.asyncio
async def test_local_password_work_does_not_block_async_loop(test_db, monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def slow_verify(_password: str, _hash: str) -> bool:
        started.set()
        assert release.wait(5)
        return False

    monkeypatch.setattr(auth, "verify_password", slow_verify)
    task = asyncio.create_task(auth.authenticate_local_user("absent@example.com", "unknown", test_db))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        await asyncio.wait_for(asyncio.sleep(0.01), 0.5)
        assert not task.done()
    finally:
        release.set()
        assert await task is None


@pytest.mark.asyncio
async def test_password_capacity_remains_occupied_after_request_cancellation(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(auth.config.local, "max_concurrent_password_operations", 1)

    def slow_verify(_password: str, _hash: str) -> bool:
        started.set()
        assert release.wait(5)
        return False

    monkeypatch.setattr(auth, "verify_password", slow_verify)
    task = asyncio.create_task(auth.verify_password_async("synthetic", "hash"))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(HTTPException) as failure:
            await auth.verify_password_async("synthetic", "hash")
        assert failure.value.status_code == 503
    finally:
        release.set()
        for _ in range(100):
            if not auth._password_operations.get(asyncio.get_running_loop(), 0):
                break
            await asyncio.sleep(0.01)
    assert not auth._password_operations.get(asyncio.get_running_loop(), 0)


def test_long_passphrases_allowed_but_common_passwords_rejected(monkeypatch):
    auth.validate_password_strength("a long private passphrase")
    with pytest.raises(HTTPException):
        auth.validate_password_strength("Password1")
    monkeypatch.setattr(auth.config.local, "blocked_passwords", ["passwordpassword"])
    with pytest.raises(HTTPException):
        auth.validate_password_strength("PASSWORDPASSWORD")


def mock_provider(monkeypatch, handler):
    client_class = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(auth.httpx, "AsyncClient", lambda **kwargs: client_class(transport=transport, **kwargs))


@pytest.mark.asyncio
async def test_oauth_streams_code_verifier_and_bounded_typed_profile(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "POST":
            assert b"code_verifier=synthetic-verifier" in request.content
            return httpx.Response(200, json={"access_token": "synthetic-provider-token", "token_type": "Bearer"})
        assert request.headers["authorization"] == "Bearer synthetic-provider-token"
        return httpx.Response(200, json={"sub": "provider-subject", "email": "profile@example.com", "email_verified": True})

    mock_provider(monkeypatch, handler)
    profile = await auth.get_unity_userinfo("synthetic-code", "synthetic-verifier")
    assert profile["sub"] == "provider-subject" and profile["email_verified"] is True
    assert len(requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    [], {"access_token": []}, {"access_token": "synthetic", "token_type": "MAC"},
])
async def test_oauth_rejects_malformed_token_responses(monkeypatch, response):
    mock_provider(monkeypatch, lambda request: httpx.Response(200, json=response))
    with pytest.raises(HTTPException) as failure:
        await auth.get_unity_userinfo("synthetic-code", "synthetic-verifier")
    assert failure.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", [
    {"sub": ["bad"], "email": "profile@example.com"},
    {"sub": "x" * 256, "email": "profile@example.com"},
    {"sub": "valid", "email": "profile@example.com", "email_verified": "true"},
    {"sub": "valid", "email": "profile@example.com", "name": {"untrusted": "object"}},
])
async def test_oauth_rejects_invalid_profile_types_and_bounds(monkeypatch, profile):
    def handler(request):
        return httpx.Response(200, json={"access_token": "synthetic"} if request.method == "POST" else profile)

    mock_provider(monkeypatch, handler)
    with pytest.raises(HTTPException) as failure:
        await auth.get_unity_userinfo("synthetic-code", "synthetic-verifier")
    assert failure.value.status_code == 503


@pytest.mark.asyncio
async def test_oauth_caps_response_size_without_content_length(monkeypatch):
    class OversizedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 1000
            yield b"y" * 1000

    monkeypatch.setattr(auth.config.oauth, "max_response_bytes", 1024)
    mock_provider(monkeypatch, lambda request: httpx.Response(200, stream=OversizedStream()))
    with pytest.raises(HTTPException) as failure:
        await auth.get_unity_userinfo("synthetic-code", "synthetic-verifier")
    assert failure.value.status_code == 503


@pytest.mark.asyncio
async def test_oauth_timeout_is_bounded_and_does_not_log_credentials(monkeypatch):
    logs = []
    monkeypatch.setattr(auth._audit, "error", lambda *args: logs.append(args))
    monkeypatch.setattr(auth.config.oauth, "request_timeout_seconds", 0.02)

    async def handler(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={"access_token": "sensitive-provider-token"})

    mock_provider(monkeypatch, handler)
    with pytest.raises(HTTPException) as failure:
        await auth.get_unity_userinfo("sensitive-authorization-code", "sensitive-verifier")
    assert failure.value.status_code == 503
    assert "sensitive" not in str(logs) + str(failure.value.detail)


@pytest.mark.asyncio
async def test_oauth_provider_exception_details_are_never_logged(monkeypatch):
    logs = []
    monkeypatch.setattr(auth._audit, "error", lambda *args: logs.append(args))

    def handler(request):
        raise httpx.ReadError("sensitive-provider-token secret-client-password", request=request)

    mock_provider(monkeypatch, handler)
    with pytest.raises(HTTPException) as failure:
        await auth.get_unity_userinfo("sensitive-code", "sensitive-verifier")
    assert failure.value.status_code == 503
    assert "sensitive" not in str(logs) + str(failure.value.detail)


@pytest.mark.asyncio
async def test_direct_oauth_profile_validation_rejects_coercion(test_db):
    with pytest.raises(HTTPException) as failure:
        await auth.get_or_create_user({"sub": {"unexpected": "object"}, "email": "user@example.com"}, test_db)
    assert failure.value.status_code == 503
    assert not (await test_db.execute(select(User))).scalars().all()


@pytest.mark.asyncio
async def test_session_rejects_tombstoned_user_even_if_row_exists(test_db, test_user):
    token = auth.create_session_token(test_user)
    record_deletion(test_db, test_user)
    await test_db.commit()
    with pytest.raises(HTTPException) as failure:
        await auth.get_current_user(cookie_request(token), test_db)
    assert failure.value.status_code == 403


@pytest.mark.asyncio
async def test_oauth_checks_deletion_again_before_issuing_session(test_db, monkeypatch):
    checks = iter([False, True])
    logs = []

    async def deleted(_db, _subject):
        return next(checks)

    monkeypatch.setattr(auth, "is_subject_deleted", deleted)
    monkeypatch.setattr(auth._audit, "warning", lambda *args: logs.append(args))
    with pytest.raises(HTTPException) as failure:
        await auth.get_or_create_user({"sub": "racing-sub", "email": "racing@example.com"}, test_db)
    assert failure.value.status_code == 403
    users = (await test_db.execute(select(User))).scalars().all()
    assert len(users) == 1
    assert "cleanup_required=True" in str(logs) and users[0].id in str(logs)


def test_invalid_unicode_password_returns_validation_error():
    with pytest.raises(HTTPException) as failure:
        auth.validate_password_strength("long enough password\ud800")
    assert failure.value.status_code == 400
