"""Schema migrations: fresh databases, adoption of databases created before
migrations existed, idempotence, refusal of unknown schemas and the CLI."""
import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import migrate
from app.auth import generate_token, hash_token
from app.config import get_config
from app.database import build_engine
from app.models import Base, Token
from tests.conftest import drop_schema

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def engine(tmp_path):
    url = os.environ.get("TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/migrations.db")
    engine = build_engine(url, hide_parameters=True)
    async with engine.begin() as conn:
        await drop_schema(conn)
    yield engine
    async with engine.begin() as conn:
        await drop_schema(conn)
    await engine.dispose()


@pytest.fixture
def audit_records():
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger("token_generator.audit")
    logger.addHandler(handler)
    yield records
    logger.removeHandler(handler)


async def schema_differences(engine) -> list:
    async with engine.connect() as conn:
        return await conn.run_sync(
            lambda sync: compare_metadata(MigrationContext.configure(sync), Base.metadata))


async def table_names(engine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda sync: inspect(sync).get_table_names()))


async def migrate_to(engine, revision: str) -> None:
    async with engine.connect() as conn:
        await conn.run_sync(lambda sync: command.upgrade(migrate.alembic_config(sync), revision))


async def create_pre_migration_database(engine) -> str:
    """What create_all built before migrations existed, with one token."""
    # The baseline revision builds exactly that schema, minus the version record.
    await migrate_to(engine, "0001")
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE alembic_version"))
        await conn.execute(text("DROP INDEX ix_revoked_jwts_expires_at"))
        await conn.execute(text(
            "INSERT INTO users (id, unity_id, email, name, is_admin, created_at, session_epoch) "
            "VALUES ('kept-user', 'kept-subject', 'kept@example.com', 'Kept', false, CURRENT_TIMESTAMP, 0)"))
        await conn.execute(text(
            "INSERT INTO tokens (id, user_id, token_hash, name, created_at) "
            "VALUES ('kept-token', 'kept-user', :hash, 'Kept token', CURRENT_TIMESTAMP)"),
            {"hash": hash_token(generate_token())})
    return "kept-user"


def test_single_linear_history():
    assert migrate.head_revision() == "0004"


@pytest.mark.asyncio
async def test_fresh_database_matches_the_models(engine, audit_records):
    assert await migrate.upgrade_database(engine) == migrate.head_revision()
    assert await schema_differences(engine) == []
    messages = [record.getMessage() for record in audit_records]
    assert messages == ["action=schema_migrated from=none to=0004"]


@pytest.mark.asyncio
async def test_upgrade_is_idempotent(engine, audit_records):
    await migrate.upgrade_database(engine)
    await migrate.upgrade_database(engine)
    assert sum("schema_migrated" in record.getMessage() for record in audit_records) == 1
    assert await schema_differences(engine) == []


@pytest.mark.asyncio
async def test_pre_migration_database_is_adopted_and_upgraded(engine, audit_records):
    user_id = await create_pre_migration_database(engine)
    assert await migrate.upgrade_database(engine) == "0004"
    assert await schema_differences(engine) == []
    messages = [record.getMessage() for record in audit_records]
    assert messages == ["action=schema_adopted revision=0001", "action=schema_migrated from=none to=0004"]
    async with AsyncSession(engine) as db:
        assert (await db.execute(select(Token.name).where(Token.user_id == user_id))).scalar_one() == "Kept token"


@pytest.mark.asyncio
async def test_older_unversioned_schema_is_refused_untouched(engine):
    async with engine.begin() as conn:
        # users as created by the August 2026 releases: no session_epoch.
        await conn.execute(text(
            "CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, unity_id VARCHAR(255), "
            "email VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL, password_hash VARCHAR(255), "
            "is_admin BOOLEAN NOT NULL, created_at TIMESTAMP NOT NULL)"))
    with pytest.raises(migrate.SchemaError) as error:
        await migrate.upgrade_database(engine)
    assert "missing column users.session_epoch" in str(error.value)
    assert "missing table tokens" in str(error.value)
    assert await table_names(engine) == {"users"}


@pytest.mark.asyncio
async def test_unexpected_owner_index_definition_is_refused(engine):
    await create_pre_migration_database(engine)
    async with engine.begin() as conn:
        await conn.execute(text("CREATE INDEX ix_tokens_user_id ON tokens (name)"))
    with pytest.raises(migrate.SchemaError, match="unexpected index ix_tokens_user_id on tokens"):
        await migrate.upgrade_database(engine)


@pytest.mark.asyncio
async def test_check_requires_the_latest_revision(engine):
    with pytest.raises(migrate.SchemaError, match="revision none"):
        await migrate.require_current_schema(engine)
    await migrate_to(engine, "0001")
    with pytest.raises(migrate.SchemaError, match="revision 0001"):
        await migrate.require_current_schema(engine)
    await migrate.upgrade_database(engine)
    assert await migrate.require_current_schema(engine) == "0004"


@pytest.mark.asyncio
async def test_startup_migrates_or_refuses_as_configured(engine, monkeypatch):
    database = get_config().database
    monkeypatch.setattr(database, "auto_migrate", False)
    with pytest.raises(migrate.SchemaError):
        await migrate.prepare_schema(engine)
    assert "users" not in await table_names(engine)
    monkeypatch.setattr(database, "auto_migrate", True)
    if engine.dialect.name == "postgresql":
        monkeypatch.setattr(migrate, "migration_engine", lambda: build_engine(engine.url, migration=True))
    await migrate.prepare_schema(engine)
    assert await migrate.database_revision(engine) == "0004"


@pytest.mark.asyncio
async def test_downgrade_to_baseline_and_back(engine):
    await migrate.upgrade_database(engine)
    async with engine.connect() as conn:
        await conn.run_sync(lambda sync: command.downgrade(migrate.alembic_config(sync), "0001"))
    assert await migrate.database_revision(engine) == "0001"
    await migrate.upgrade_database(engine)
    assert await schema_differences(engine) == []


@pytest.mark.asyncio
async def test_application_owners_become_members(engine):
    await migrate_to(engine, "0003")
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO users (id, unity_id, email, name, is_admin, created_at, session_epoch) "
            "VALUES ('owner', 'owner-subject', ' Owner@Example.com', 'Owner', false, CURRENT_TIMESTAMP, 0)"))
        await conn.execute(text(
            "INSERT INTO applications (id, user_id, name, created_at) "
            "VALUES ('app', 'owner', 'Bot', CURRENT_TIMESTAMP)"))
        for token_id, application_id in (("personal", None), ("bot", "app")):
            await conn.execute(text(
                "INSERT INTO tokens (id, user_id, application_id, token_hash, name, created_at) "
                "VALUES (:id, 'owner', :application, :hash, :id, CURRENT_TIMESTAMP)"),
                {"id": token_id, "application": application_id, "hash": hash_token(generate_token())})
    assert await migrate.upgrade_database(engine) == "0004"
    async with engine.connect() as conn:
        members = (await conn.execute(text(
            "SELECT application_id, user_id, email, role FROM application_members"))).all()
        tokens = dict((await conn.execute(text(
            "SELECT id, user_id || '/' || COALESCE(created_by_id, '-') FROM tokens WHERE user_id IS NOT NULL "
            "UNION SELECT id, '-/' || created_by_id FROM tokens WHERE user_id IS NULL"))).all())
    assert members == [("app", "owner", "owner@example.com", "owner")]
    assert tokens == {"personal": "owner/-", "bot": "-/owner"}
    async with engine.connect() as conn:
        await conn.run_sync(lambda sync: command.downgrade(migrate.alembic_config(sync), "0003"))
        restored = (await conn.execute(text("SELECT id, user_id FROM tokens ORDER BY id"))).all()
        owner = (await conn.execute(text("SELECT user_id FROM applications"))).scalar_one()
    assert restored == [("bot", "owner"), ("personal", "owner")] and owner == "owner"


@pytest.mark.asyncio
async def test_concurrent_postgres_startups_serialize(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("The schema lock is a PostgreSQL advisory lock")
    results = await asyncio.gather(*(migrate.upgrade_database(engine) for _ in range(4)))
    assert results == ["0004"] * 4
    assert await schema_differences(engine) == []


def run_cli(*args: str, database_url: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": database_url}
    return subprocess.run([sys.executable, "-m", "app.migrate", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


def test_command_line(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/cli.db"
    check = run_cli("check", database_url=url)
    assert check.returncode == 1 and "revision none" in check.stdout
    upgrade = run_cli(database_url=url)
    assert upgrade.returncode == 0, upgrade.stderr
    assert "revision 0004" in upgrade.stdout
    assert run_cli("check", database_url=url).returncode == 0
    assert run_cli("current", database_url=url).stdout.strip() == "0004"


def test_command_line_hides_connection_errors(tmp_path):
    result = run_cli("check", database_url="postgresql+asyncpg://user:synthetic-secret@127.0.0.1:1/x")
    assert result.returncode == 1
    assert "synthetic-secret" not in result.stdout + result.stderr


def test_command_line_explains_schema_problems(tmp_path):
    import sqlite3
    database = tmp_path / "wrong-index.db"
    url = f"sqlite+aiosqlite:///{database}"
    assert run_cli("upgrade", database_url=url).returncode == 0
    with sqlite3.connect(database) as connection:
        connection.execute("DROP INDEX ix_tokens_user_id")
        connection.execute("CREATE INDEX ix_tokens_user_id ON tokens (name)")
        connection.execute("UPDATE alembic_version SET version_num = '0001'")
    result = run_cli("upgrade", database_url=url)
    assert result.returncode == 1
    assert "unexpected definition" in result.stderr


@pytest.mark.asyncio
async def test_hand_patched_old_schema_is_not_adopted(engine):
    # An August database kept alive by adding the new columns by hand still
    # has the old unique email index (one account could block another).
    await create_pre_migration_database(engine)
    async with engine.begin() as conn:
        await conn.execute(text("DROP INDEX ix_users_email"))
        await conn.execute(text("CREATE UNIQUE INDEX ix_users_email ON users (email)"))
    with pytest.raises(migrate.SchemaError, match="ix_users_email"):
        await migrate.upgrade_database(engine)
    assert await migrate.database_revision(engine) is None


@pytest.mark.asyncio
async def test_newer_schema_is_refused_with_an_explanation(engine):
    await migrate.upgrade_database(engine)
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE alembic_version SET version_num = '0099'"))
    for check in (migrate.upgrade_database, migrate.require_current_schema):
        with pytest.raises(migrate.SchemaError, match="newer release"):
            await check(engine)


async def hold_schema_lock(engine):
    connection = await engine.connect()
    await connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": migrate.SCHEMA_LOCK_KEY})
    await connection.commit()
    return connection


@pytest.mark.asyncio
async def test_current_schema_starts_without_the_lock(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("The schema lock is a PostgreSQL advisory lock")
    await migrate.upgrade_database(engine)
    holder = await hold_schema_lock(engine)
    try:
        assert await asyncio.wait_for(migrate.upgrade_database(engine), 5) == "0004"
    finally:
        await holder.close()


@pytest.mark.asyncio
async def test_lock_timeout_names_the_holder(engine, monkeypatch):
    if engine.dialect.name != "postgresql":
        pytest.skip("The schema lock is a PostgreSQL advisory lock")
    monkeypatch.setattr(migrate, "LOCK_WAIT_SECONDS", 1)
    holder = await hold_schema_lock(engine)
    try:
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        with pytest.raises(migrate.SchemaError, match=f"server process {pid}"):
            await migrate.upgrade_database(engine)
    finally:
        await holder.close()


@pytest.mark.asyncio
async def test_failed_migration_reports_its_error_and_releases_the_lock(engine, monkeypatch):
    if engine.dialect.name != "postgresql":
        pytest.skip("The schema lock is a PostgreSQL advisory lock")

    def failing_upgrade(connection):
        connection.execute(text("SELECT 1 / 0"))

    monkeypatch.setattr(migrate, "_upgrade", failing_upgrade)
    with pytest.raises(Exception, match="division by zero"):
        await migrate.upgrade_database(engine)
    async with engine.connect() as conn:
        assert await conn.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": migrate.SCHEMA_LOCK_KEY})
        await conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": migrate.SCHEMA_LOCK_KEY})


def test_command_line_check_compares_the_schema(tmp_path):
    import sqlite3
    database = tmp_path / "partial.db"
    url = f"sqlite+aiosqlite:///{database}"
    assert run_cli("upgrade", database_url=url).returncode == 0
    assert "matches this release" in run_cli("check", database_url=url).stdout
    with sqlite3.connect(database) as connection:
        connection.execute("DROP INDEX ix_deleted_users_email_hash")
    result = run_cli("check", database_url=url)
    assert result.returncode == 1
    assert "missing index ix_deleted_users_email_hash on deleted_users" in result.stdout
