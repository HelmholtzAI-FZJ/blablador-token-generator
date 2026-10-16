import asyncio
import os
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy import func, inspect, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import Request

from app.api.admin import (
    CreateUserRequest, RestoreOAuthRequest, UpdateUserRequest, create_user,
    delete_revoked_tokens, delete_user, is_last_admin, restore_oauth_identity,
    revoke_user_credentials, list_users, router as admin_router, update_user,
)
from app.api.tokens import (
    CreateTokenRequest, RenewTokenRequest, create_token, revoke_all_tokens, rotate_token,
)
from app.api.validate import validate_token
from app.auth import (
    create_session_token, generate_token, get_current_admin, get_current_user, hash_token,
)
from app.config import get_config
from app.cookies import SESSION_COOKIE
from app.database import (
    build_engine, get_db, lock_user_for_update, postgres_connect_args,
    verify_production_database_role,
)
from app.models import Base, Token, User
from app.tombstones import is_subject_deleted, record_deletion
from app.timeutil import utcnow
from tests.conftest import drop_schema


def request(path: str = "/", method: str = "POST", session: str | None = None) -> Request:
    headers = [] if session is None else [(b"cookie", f"{SESSION_COOKIE}={session}".encode())]
    return Request({"type": "http", "method": method, "path": path, "headers": headers,
                    "query_string": b"", "client": ("127.0.0.9", 0)})


@pytest.fixture
async def mutation_sessions(tmp_path):
    url = os.environ.get("TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/mutations.db")
    engine = build_engine(url, hide_parameters=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await drop_schema(conn)
    await engine.dispose()


async def seed_users(sessions, count: int = 1, admin: bool = False) -> list[str]:
    async with sessions() as db:
        users = [User(email=f"fix-{i}@example.invalid", name=f"User {i}", is_admin=admin)
                 for i in range(count)]
        db.add_all(users)
        await db.commit()
        return [user.id for user in users]


@pytest.mark.asyncio
async def test_concurrent_creates_respect_quota(mutation_sessions, monkeypatch):
    (user_id,) = await seed_users(mutation_sessions)
    monkeypatch.setattr(get_config().tokens, "max_tokens_per_user", 1)
    ready = asyncio.Event()
    arrived = 0

    async def create_one(index):
        nonlocal arrived
        async with mutation_sessions() as db:
            user = await db.get(User, user_id)
            arrived += 1
            if arrived == 4:
                ready.set()
            await ready.wait()
            try:
                await create_token.__wrapped__(request("/tokens"),
                    CreateTokenRequest(name=f"Token {index}"), user, db)
                return 200
            except HTTPException as exc:
                return exc.status_code

    results = await asyncio.wait_for(asyncio.gather(*(create_one(i) for i in range(4))), 15)
    assert results.count(200) == 1
    assert results.count(400) == 3
    async with mutation_sessions() as db:
        assert (await db.execute(select(func.count()).select_from(Token))).scalar_one() == 1


@pytest.mark.asyncio
async def test_concurrent_demotions_preserve_one_admin(mutation_sessions):
    ids = await seed_users(mutation_sessions, count=2, admin=True)
    ready = asyncio.Event()
    arrived = 0

    async def demote(user_id):
        nonlocal arrived
        async with mutation_sessions() as db:
            admin = await db.get(User, user_id)
            arrived += 1
            if arrived == 2:
                ready.set()
            await ready.wait()
            try:
                await update_user.__wrapped__(request("/api/admin/users/" + user_id, "PATCH"),
                    user_id, UpdateUserRequest(is_admin=False), admin, db)
                return 200
            except HTTPException as exc:
                return exc.status_code

    results = await asyncio.wait_for(asyncio.gather(*(demote(uid) for uid in ids)), 15)
    assert sorted(results) == [200, 400]
    async with mutation_sessions() as db:
        assert (await db.execute(select(func.count()).select_from(User)
                                .where(User.is_admin.is_(True)))).scalar_one() == 1


@pytest.mark.asyncio
async def test_last_admin_self_delete_rejected(test_db, test_admin):
    from app.main import delete_my_account
    admin_id = test_admin.id
    with pytest.raises(HTTPException) as exc:
        await delete_my_account.__wrapped__(request("/account/delete"), test_admin, test_db)
    assert exc.value.status_code == 400
    assert await test_db.get(User, admin_id) is not None


@pytest.mark.asyncio
async def test_tombstoned_admin_cannot_allow_last_usable_admin_removal(test_db, test_admin):
    from app.main import delete_my_account
    admin_id = test_admin.id
    disabled = User(unity_id="disabled-admin-subject", email="disabled@example.invalid",
                    name="Disabled administrator", is_admin=True)
    test_db.add(disabled)
    record_deletion(test_db, disabled)
    await test_db.commit()
    with pytest.raises(HTTPException) as demotion:
        await update_user.__wrapped__(request(), admin_id, UpdateUserRequest(is_admin=False),
                                      test_admin, test_db)
    assert demotion.value.status_code == 400
    with pytest.raises(HTTPException) as deletion:
        await delete_my_account.__wrapped__(request("/account/delete"), test_admin, test_db)
    assert deletion.value.status_code == 400
    assert (await test_db.get(User, admin_id)).is_admin


@pytest.mark.asyncio
async def test_disabled_admin_row_can_be_cleaned_up(test_db, test_admin):
    disabled = User(unity_id="disabled-cleanup-subject", email="cleanup@example.invalid",
                    name="Disabled administrator", is_admin=True)
    test_db.add(disabled)
    record_deletion(test_db, disabled)
    await test_db.commit()
    disabled_id = disabled.id
    await delete_user.__wrapped__(request(), disabled_id, test_admin, test_db)
    assert await test_db.get(User, disabled_id) is None
    assert await is_last_admin(test_db, test_admin.id)


@pytest.mark.asyncio
async def test_admin_availability_check_is_bounded_and_fails_closed(test_db, test_admin):
    for index in range(101):
        disabled = User(unity_id=f"disabled-many-{index}", email=f"disabled-{index}@example.invalid",
                        name="Disabled administrator", is_admin=True)
        test_db.add(disabled)
        record_deletion(test_db, disabled)
    await test_db.commit()
    await lock_user_for_update(test_db, test_admin.id, admin_membership=True)
    with pytest.raises(HTTPException) as failure:
        await is_last_admin(test_db, test_admin.id)
    assert failure.value.status_code == 503


@pytest.mark.asyncio
async def test_user_pagination_is_bounded_stable_and_preserves_default_page(test_db, test_admin):
    timestamp = datetime(2026, 1, 1)
    test_admin.created_at = timestamp
    users = [User(id=f"00000000-0000-0000-0000-{index:012d}",
                  email=f"page-{index}@example.invalid", name=f"User {index}",
                  created_at=timestamp) for index in range(100)]
    test_db.add_all(users)
    await test_db.commit()
    expected_ids = sorted([test_admin.id] + [user.id for user in users], reverse=True)
    first = await list_users.__wrapped__(request(method="GET"), page_size=100,
                                         admin=test_admin, db=test_db)
    second = await list_users.__wrapped__(request(method="GET"), page=2, page_size=100,
                                          admin=test_admin, db=test_db)
    assert len(first) == 100
    assert len(second) == 1
    assert [user.id for user in first + second] == expected_ids
    default = await list_users.__wrapped__(request(method="GET"), admin=test_admin, db=test_db)
    assert [user.id for user in default] == expected_ids[:20]


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [{"page": 10 ** 40}, {"page": 0}, {"page_size": 101}])
async def test_user_pagination_rejects_invalid_http_bounds(test_db, test_admin, params):
    mini = FastAPI()
    mini.include_router(admin_router)

    async def admin_override():
        return test_admin

    async def database_override():
        yield test_db

    mini.dependency_overrides[get_current_admin] = admin_override
    mini.dependency_overrides[get_db] = database_override
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mini), base_url="http://isolated") as client:
        response = await client.get("/api/admin/users", params=params)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_local_create_does_not_restore_oauth_subject(test_db, test_admin):
    gone = User(unity_id="banned-unverified-subject", email="owner@example.invalid", name="Gone")
    test_db.add(gone)
    await test_db.commit()
    record_deletion(test_db, gone)
    await test_db.delete(gone)
    await test_db.commit()
    await create_user.__wrapped__(request("/api/admin/users"), CreateUserRequest(
        email="owner@example.invalid", name="Real owner", password="Separate safe password 9"),
        test_admin, test_db)
    assert await is_subject_deleted(test_db, "banned-unverified-subject")
    response = await restore_oauth_identity.__wrapped__(request("/api/admin/users/restore-oauth"),
        RestoreOAuthRequest(subject="banned-unverified-subject"), test_admin, test_db)
    assert response["deletions_lifted"] == 1
    assert not await is_subject_deleted(test_db, "banned-unverified-subject")


@pytest.mark.parametrize("model", [CreateTokenRequest, RenewTokenRequest])
def test_extreme_offset_is_validation_error(model):
    values = {"expires_at": "9999-12-31T23:59:59-01:00"}
    if model is CreateTokenRequest:
        values["name"] = "Boundary"
    with pytest.raises(ValidationError):
        model(**values)


def test_expiration_normalized_and_ambiguous_input_rejected():
    body = CreateTokenRequest(name="TZ", expires_at="2027-01-01T12:00:00+02:00")
    assert body.expires_at == datetime(2027, 1, 1, 10)
    with pytest.raises(ValidationError):
        RenewTokenRequest(expires_at="2027-01-01T12:00:00Z", expires_in_days=2)


@pytest.mark.parametrize("email", [
    "user\nforged-event@example.invalid", "user\r@example.invalid",
    "user\t@example.invalid", "user name@example.invalid", "user\x1b@example.invalid",
    "user\x7f@example.invalid", "user\u202e@example.invalid", "@example.invalid",
    "user@", "user@@example.invalid",
])
def test_local_account_email_rejects_log_controls_and_invalid_structure(email):
    with pytest.raises(ValidationError):
        CreateUserRequest(email=email, name="User", password="Separate safe password 9")


def test_local_account_email_normalizes_case_before_persistence():
    body = CreateUserRequest(email="USER@EXAMPLE.INVALID", name="User",
                             password="Separate safe password 9")
    assert body.email == "user@example.invalid"


@pytest.mark.asyncio
async def test_past_expiration_rejected(test_db, test_user):
    with pytest.raises(HTTPException) as exc:
        await create_token.__wrapped__(request("/tokens"), CreateTokenRequest(
            name="Expired", expires_at=utcnow() - timedelta(days=1)), test_user, test_db)
    assert exc.value.status_code == 400
    assert (await test_db.execute(select(func.count()).select_from(Token))).scalar_one() == 0


class CommitFailureSession(AsyncSession):
    async def commit(self):
        raise RuntimeError("Synthetic telemetry write failure")


@pytest.mark.asyncio
async def test_validation_survives_best_effort_telemetry_failure(mutation_sessions):
    (user_id,) = await seed_users(mutation_sessions)
    plain = generate_token()
    async with mutation_sessions() as db:
        db.add(Token(user_id=user_id, token_hash=hash_token(plain), name="Telemetry",
                     expires_at=utcnow() + timedelta(days=1)))
        await db.commit()
    sessions = async_sessionmaker(mutation_sessions.kw["bind"], class_=CommitFailureSession,
                                 expire_on_commit=False)
    async with sessions() as db:
        response = await validate_token.__wrapped__(request("/api/v1/auth/validate"), plain, db)
    assert response.valid
    assert response.user_id == user_id
    assert response.expires_at is not None


class CountingSession(AsyncSession):
    commits = 0

    async def commit(self):
        type(self).commits += 1
        await super().commit()


@pytest.mark.asyncio
async def test_recent_validation_does_not_write_again(mutation_sessions):
    (user_id,) = await seed_users(mutation_sessions)
    plain = generate_token()
    async with mutation_sessions() as db:
        token = Token(user_id=user_id, token_hash=hash_token(plain), name="Coalesced")
        db.add(token)
        await db.commit()
        token_id = token.id
    CountingSession.commits = 0
    sessions = async_sessionmaker(mutation_sessions.kw["bind"], class_=CountingSession,
                                 expire_on_commit=False)
    async with sessions() as db:
        assert (await validate_token.__wrapped__(request(), plain, db)).valid
    async with sessions() as db:
        first_used = (await db.get(Token, token_id)).last_used_at
        assert (await validate_token.__wrapped__(request(), plain, db)).valid
    async with sessions() as db:
        assert (await db.get(Token, token_id)).last_used_at == first_used
    assert CountingSession.commits == 1


@pytest.mark.asyncio
async def test_rotation_invalidates_old_token_and_keeps_new_token(test_db, test_user, test_token):
    old_plain = test_token["plain_token"]
    token_id = test_token["token"].id
    response = await rotate_token.__wrapped__(request(), token_id,
        RenewTokenRequest(expires_in_days=3), test_user, test_db)
    assert response.token != old_plain
    with pytest.raises(HTTPException) as exc:
        await validate_token.__wrapped__(request(), old_plain, test_db)
    assert exc.value.status_code == 401
    assert (await validate_token.__wrapped__(request(), response.token, test_db)).valid


@pytest.mark.asyncio
async def test_rotation_enforces_owner(test_db, test_admin, test_token):
    with pytest.raises(HTTPException) as exc:
        await rotate_token.__wrapped__(request(), test_token["token"].id, None, test_admin, test_db)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_admin_incident_revokes_tokens_and_sessions(test_db, test_user, test_admin, test_token):
    session = create_session_token(test_user)
    user_id = test_user.id
    response = await revoke_user_credentials.__wrapped__(request(), user_id, test_admin, test_db)
    assert response["tokens_revoked"] == 1
    with pytest.raises(HTTPException):
        await validate_token.__wrapped__(request(), test_token["plain_token"], test_db)
    with pytest.raises(HTTPException):
        await get_current_user(request(session=session), test_db)


@pytest.mark.asyncio
async def test_self_revoke_all_preserves_other_user_tokens(test_db, test_user, test_admin, test_token):
    other_plain = generate_token()
    test_db.add(Token(user_id=test_admin.id, token_hash=hash_token(other_plain), name="Other"))
    await test_db.commit()
    session = create_session_token(test_user)
    response = await revoke_all_tokens.__wrapped__(request(), test_user, test_db)
    assert response["tokens_revoked"] == 1
    with pytest.raises(HTTPException):
        await get_current_user(request(session=session), test_db)
    assert (await validate_token.__wrapped__(request(), other_plain, test_db)).valid


@pytest.mark.asyncio
async def test_pre_authenticated_session_cannot_mint_after_revoke(test_db, test_user):
    old_session = create_session_token(test_user)
    authenticated = await get_current_user(request(session=old_session), test_db)
    await revoke_all_tokens.__wrapped__(request(), test_user, test_db)
    with pytest.raises(HTTPException) as exc:
        await create_token.__wrapped__(request("/tokens", session=old_session),
            CreateTokenRequest(name="Late credential"), authenticated, test_db)
    assert exc.value.status_code in (302, 401)
    assert (await test_db.execute(select(func.count()).select_from(Token))).scalar_one() == 0


@pytest.mark.asyncio
async def test_pre_authenticated_admin_cannot_mutate_after_revoke(test_db, test_admin):
    old_session = create_session_token(test_admin)
    authenticated = await get_current_user(request(session=old_session), test_db)
    await revoke_user_credentials.__wrapped__(request(), test_admin.id, test_admin, test_db)
    with pytest.raises(HTTPException) as exc:
        await create_user.__wrapped__(request("/api/admin/users", session=old_session),
            CreateUserRequest(email="late@example.invalid", name="Late account",
                              password="Separate safe password 9"), authenticated, test_db)
    assert exc.value.status_code in (302, 401)
    assert (await test_db.execute(select(func.count()).select_from(User))).scalar_one() == 1


@pytest.mark.asyncio
async def test_bulk_purge_keeps_active_tokens(test_db, test_admin):
    revoked = Token(user_id=test_admin.id, token_hash=hash_token(generate_token()), name="Gone",
                    revoked_at=utcnow())
    active = Token(user_id=test_admin.id, token_hash=hash_token(generate_token()), name="Keep")
    test_db.add_all([revoked, active])
    await test_db.commit()
    revoked_id, active_id = revoked.id, active.id
    response = await delete_revoked_tokens.__wrapped__(request(), test_admin, test_db)
    assert response["message"] == "Deleted 1 revoked tokens"
    assert await test_db.get(Token, revoked_id) is None
    assert await test_db.get(Token, active_id) is not None


def test_owner_index_defined():
    assert any(index.name == "ix_tokens_user_id" for index in Token.__table__.indexes)


def test_postgres_timeout_settings_preserve_explicit_connection_arguments():
    ssl_marker = object()
    supplied = {"ssl": ssl_marker, "timeout": 1.5, "command_timeout": 3,
                "server_settings": {"application_name": "controlled-test", "statement_timeout": "1500ms"}}
    merged = postgres_connect_args(supplied)
    assert merged["ssl"] is ssl_marker
    assert merged["timeout"] == 1.5
    assert merged["command_timeout"] == 3
    assert merged["server_settings"]["application_name"] == "controlled-test"
    assert merged["server_settings"]["statement_timeout"] == "1500ms"
    assert merged["server_settings"]["lock_timeout"] == "2000ms"
    assert merged["server_settings"]["idle_in_transaction_session_timeout"] == "15000ms"
    assert supplied["server_settings"] == {
        "application_name": "controlled-test", "statement_timeout": "1500ms",
    }


def test_runtime_and_migration_have_separate_bounded_statement_deadlines():
    runtime = postgres_connect_args()
    migration = postgres_connect_args(migration=True)
    assert runtime["timeout"] == migration["timeout"] == 5
    assert runtime["command_timeout"] == 5
    assert runtime["server_settings"]["statement_timeout"] == "5000ms"
    assert migration["command_timeout"] == 120
    assert migration["server_settings"]["statement_timeout"] == "120000ms"
    assert migration["server_settings"]["lock_timeout"] == "2000ms"
    assert migration["server_settings"]["idle_in_transaction_session_timeout"] == "120000ms"


def test_submillisecond_database_deadlines_are_not_rounded_to_disabled(monkeypatch):
    database = get_config().database
    for field in ("statement_timeout_seconds", "lock_timeout_seconds", "idle_transaction_timeout_seconds"):
        monkeypatch.setattr(database, field, 0.000001)
    settings = postgres_connect_args()["server_settings"]
    assert settings["statement_timeout"] == "1ms"
    assert settings["lock_timeout"] == "1ms"
    assert settings["idle_in_transaction_session_timeout"] == "1ms"


@pytest.mark.asyncio
async def test_postgres_server_settings_and_lock_deadline_are_enforced(mutation_sessions, monkeypatch):
    default_engine = mutation_sessions.kw["bind"]
    if default_engine.dialect.name != "postgresql":
        pytest.skip("Requires the disposable PostgreSQL integration database")
    (user_id,) = await seed_users(mutation_sessions)
    database = get_config().database
    monkeypatch.setattr(database, "statement_timeout_seconds", 0.3)
    monkeypatch.setattr(database, "lock_timeout_seconds", 0.03)
    monkeypatch.setattr(database, "idle_transaction_timeout_seconds", 1)
    engine = build_engine(default_engine.url, hide_parameters=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as settings_db:
            rows = await settings_db.execute(text(
                "SELECT name, setting::integer FROM pg_settings WHERE name IN "
                "('statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout')"
            ))
            assert dict(rows.all()) == {"statement_timeout": 300, "lock_timeout": 30,
                                        "idle_in_transaction_session_timeout": 1000}
        async with sessions() as holder, sessions() as blocked:
            await holder.execute(select(User.id).where(User.id == user_id).with_for_update())
            with pytest.raises(DBAPIError) as failure:
                await asyncio.wait_for(blocked.execute(
                    update(User).where(User.id == user_id).values(name="Blocked")
                ), 1)
            assert failure.value.orig.sqlstate == "55P03"
            await blocked.rollback()
            await holder.rollback()
            await blocked.execute(update(User).where(User.id == user_id).values(name="Released"))
            await blocked.commit()
        async with sessions() as verify:
            assert (await verify.get(User, user_id)).name == "Released"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe", [True, None])
async def test_database_privilege_check_rejects_unsafe_or_unknown_result(unsafe):
    connection = AsyncMock()
    connection.scalar.return_value = unsafe
    with pytest.raises(RuntimeError, match="unsafe or unverified privileges"):
        await verify_production_database_role(connection)


@pytest.mark.asyncio
async def test_database_privilege_check_accepts_verified_restricted_role():
    connection = AsyncMock()
    connection.scalar.return_value = False
    await verify_production_database_role(connection)


@pytest.mark.asyncio
async def test_production_startup_rejects_unsafe_role_before_schema_creation(monkeypatch):
    import app.database as database_module
    configuration = get_config().model_copy(deep=True)
    configuration.app.environment = "production"
    configuration.database.url = "postgresql+asyncpg://synthetic@127.0.0.1/isolated"
    connection = AsyncMock()
    connection.scalar.return_value = True
    engine = MagicMock()
    engine.begin.return_value.__aenter__.return_value = connection
    monkeypatch.setattr(database_module, "engine", None)
    monkeypatch.setattr(database_module, "async_session_maker", None)
    monkeypatch.setattr(database_module, "get_config", lambda: configuration)
    monkeypatch.setattr(database_module, "build_engine", lambda *args, **kwargs: engine)
    monkeypatch.setattr(database_module, "async_sessionmaker", MagicMock())
    with pytest.raises(RuntimeError, match="unsafe or unverified privileges"):
        await database_module.init_db()
    connection.execute.assert_not_called()
    connection.run_sync.assert_not_called()


@pytest.mark.asyncio
async def test_actual_postgres_role_guard_ownership_flags_and_memberships(mutation_sessions):
    administrative_engine = mutation_sessions.kw["bind"]
    url = administrative_engine.url
    if (administrative_engine.dialect.name != "postgresql" or url.host != "127.0.0.1"
            or url.port == 5432 or url.password != "SyntheticAuditOnlyPassword123"):
        pytest.skip("Requires the known synthetic disposable loopback PostgreSQL container")
    role = "tg_guard_" + uuid.uuid4().hex[:12]
    group = role + "_group"
    schema = role + "_schema"
    restricted_engine = None
    database_name = None
    original_owner = None
    try:
        async with administrative_engine.begin() as administrator:
            row = (await administrator.execute(text(
                "SELECT datname, pg_catalog.pg_get_userbyid(datdba) FROM pg_catalog.pg_database "
                "WHERE datname = current_database()"
            ))).one()
            database_name, original_owner = row
            assert database_name == "tokens" and original_owner == "tokens"
            await administrator.execute(text(
                f'CREATE ROLE "{role}" LOGIN PASSWORD \'SyntheticGuardRoleOnlyPassword123\' '
                'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
            ))
            await administrator.execute(text(f'CREATE ROLE "{group}" NOLOGIN CREATEDB'))
            await administrator.execute(text(f'CREATE SCHEMA "{schema}" AUTHORIZATION "{role}"'))
            await administrator.execute(text(f'ALTER DATABASE tokens OWNER TO "{role}"'))
            await administrator.execute(text(f'GRANT pg_monitor TO "{role}"'))
        restricted_engine = build_engine(url.set(username=role, password="SyntheticGuardRoleOnlyPassword123"),
                                         hide_parameters=True)
        async with restricted_engine.connect() as restricted:
            await verify_production_database_role(restricted)
            for granted, removed in (
                ("SUPERUSER", "NOSUPERUSER"), ("CREATEDB", "NOCREATEDB"),
                ("CREATEROLE", "NOCREATEROLE"), ("REPLICATION", "NOREPLICATION"),
                ("BYPASSRLS", "NOBYPASSRLS"),
            ):
                async with administrative_engine.begin() as administrator:
                    await administrator.execute(text(f'ALTER ROLE "{role}" {granted}'))
                await restricted.rollback()
                with pytest.raises(RuntimeError, match="unsafe or unverified privileges"):
                    await verify_production_database_role(restricted)
                async with administrative_engine.begin() as administrator:
                    await administrator.execute(text(f'ALTER ROLE "{role}" {removed}'))
            for dangerous in ("pg_read_server_files", "pg_write_server_files", "pg_execute_server_program", group):
                async with administrative_engine.begin() as administrator:
                    await administrator.execute(text(f'GRANT "{dangerous}" TO "{role}"'))
                await restricted.rollback()
                with pytest.raises(RuntimeError, match="unsafe or unverified privileges"):
                    await verify_production_database_role(restricted)
                async with administrative_engine.begin() as administrator:
                    await administrator.execute(text(f'REVOKE "{dangerous}" FROM "{role}"'))
            await restricted.rollback()
            await verify_production_database_role(restricted)
        async with administrative_engine.connect() as administrator:
            await administrator.execute(text(f'SET LOCAL ROLE "{role}"'))
            with pytest.raises(RuntimeError, match="unsafe or unverified privileges"):
                await verify_production_database_role(administrator)
    finally:
        if restricted_engine is not None:
            await restricted_engine.dispose()
        async with administrative_engine.begin() as administrator:
            if database_name is not None:
                await administrator.execute(text('ALTER DATABASE tokens OWNER TO tokens'))
            await administrator.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            await administrator.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
            await administrator.execute(text(f'DROP ROLE IF EXISTS "{group}"'))
