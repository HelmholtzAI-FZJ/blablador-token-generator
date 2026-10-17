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
from app.models import Base, Token, User
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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("DROP INDEX ix_tokens_user_id"))
        await conn.execute(text("DROP INDEX ix_revoked_jwts_expires_at"))
    async with AsyncSession(engine, expire_on_commit=False) as db:
        user = User(email="kept@example.com", name="Kept", unity_id="kept-subject")
        db.add(user)
        await db.flush()
        db.add(Token(user_id=user.id, name="Kept token", token_hash=hash_token(generate_token())))
        await db.commit()
        return user.id


def test_single_linear_history():
    assert migrate.head_revision() == "0002"


@pytest.mark.asyncio
async def test_fresh_database_matches_the_models(engine, audit_records):
    assert await migrate.upgrade_database(engine) == migrate.head_revision()
    assert await schema_differences(engine) == []
    messages = [record.getMessage() for record in audit_records]
    assert messages == ["action=schema_migrated from=none to=0002"]


@pytest.mark.asyncio
async def test_upgrade_is_idempotent(engine, audit_records):
    await migrate.upgrade_database(engine)
    await migrate.upgrade_database(engine)
    assert sum("schema_migrated" in record.getMessage() for record in audit_records) == 1
    assert await schema_differences(engine) == []


@pytest.mark.asyncio
async def test_pre_migration_database_is_adopted_and_upgraded(engine, audit_records):
    user_id = await create_pre_migration_database(engine)
    assert await migrate.upgrade_database(engine) == "0002"
    assert await schema_differences(engine) == []
    messages = [record.getMessage() for record in audit_records]
    assert messages == ["action=schema_adopted revision=0001", "action=schema_migrated from=none to=0002"]
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
    with pytest.raises(migrate.SchemaError, match="unexpected definition"):
        await migrate.upgrade_database(engine)


@pytest.mark.asyncio
async def test_check_requires_the_latest_revision(engine):
    with pytest.raises(migrate.SchemaError, match="revision none"):
        await migrate.require_current_schema(engine)
    await migrate_to(engine, "0001")
    with pytest.raises(migrate.SchemaError, match="revision 0001"):
        await migrate.require_current_schema(engine)
    await migrate.upgrade_database(engine)
    assert await migrate.require_current_schema(engine) == "0002"


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
    assert await migrate.database_revision(engine) == "0002"


@pytest.mark.asyncio
async def test_downgrade_to_baseline_and_back(engine):
    await migrate.upgrade_database(engine)
    async with engine.connect() as conn:
        await conn.run_sync(lambda sync: command.downgrade(migrate.alembic_config(sync), "0001"))
    assert await migrate.database_revision(engine) == "0001"
    await migrate.upgrade_database(engine)
    assert await schema_differences(engine) == []


@pytest.mark.asyncio
async def test_concurrent_postgres_startups_serialize(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("The schema lock is a PostgreSQL advisory lock")
    results = await asyncio.gather(*(migrate.upgrade_database(engine) for _ in range(4)))
    assert results == ["0002"] * 4
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
    assert "revision 0002" in upgrade.stdout
    assert run_cli("check", database_url=url).returncode == 0
    assert run_cli("current", database_url=url).stdout.strip() == "0002"


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
