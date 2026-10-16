"""Database schema migrations.

    python -m app.migrate            apply pending migrations (same as "upgrade")
    python -m app.migrate check      exit with status 1 unless the schema is current
    python -m app.migrate current    print the applied revision

The service applies migrations itself at startup unless
database.auto_migrate is false, in which case it refuses to start on an
outdated schema. Several replicas may start at once: on PostgreSQL a
session advisory lock lets one of them migrate while the others wait.

Databases created before migrations existed (by create_all, October 2026)
have the tables of revision 0001 but no version record. They are adopted
at 0001 when every expected table and column is present; anything older
is refused rather than guessed at.
"""
import argparse
import asyncio
import logging
import ssl
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, inspect, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.config import get_config
from app.database import SCHEMA_LOCK_KEY, build_engine

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
BASELINE_REVISION = "0001"
BASELINE_SCHEMA = {
    "users": {"id", "unity_id", "email", "name", "password_hash", "is_admin", "created_at", "session_epoch"},
    "tokens": {"id", "user_id", "token_hash", "name", "created_at", "expires_at", "last_used_at", "revoked_at"},
    "revoked_jwts": {"jti", "user_id", "revoked_at", "expires_at"},
    "deleted_users": {"id", "unity_id_hash", "email_hash", "deleted_at"},
}
LOCK_WAIT_SECONDS = 120
LOCK_POLL_SECONDS = 0.5

logger = logging.getLogger("token_generator.audit")


class SchemaError(RuntimeError):
    pass


def alembic_config(connection: Connection | None = None) -> AlembicConfig:
    config = AlembicConfig()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.attributes["connection"] = connection
    return config


def head_revision() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def migration_engine() -> AsyncEngine:
    """Engine for schema changes: verified TLS, longer statement deadline."""
    database = get_config().database
    connect_args = {}
    if database.url.startswith("postgresql") and database.ssl_ca_file:
        connect_args["ssl"] = ssl.create_default_context(cafile=database.ssl_ca_file)
    return build_engine(database.url, migration=True, hide_parameters=True, connect_args=connect_args)


def current_revision(connection: Connection) -> str | None:
    return MigrationContext.configure(connection).get_current_revision()


def unversioned_schema_problems(connection: Connection) -> list[str] | None:
    """None for an empty database, else what keeps it from being adopted."""
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    if not tables & BASELINE_SCHEMA.keys():
        return None
    problems = []
    for table, columns in BASELINE_SCHEMA.items():
        if table not in tables:
            problems.append(f"missing table {table}")
            continue
        present = {column["name"] for column in inspector.get_columns(table)}
        problems.extend(f"missing column {table}.{column}" for column in sorted(columns - present))
    return problems


def _upgrade(connection: Connection) -> tuple[str | None, str]:
    before = current_revision(connection)
    problems = unversioned_schema_problems(connection) if before is None else None
    # Alembic only manages (and commits) transactions it begins itself.
    connection.commit()
    if problems:
        raise SchemaError(
            "The database has tables but no migration history, and does not match the "
            f"first supported schema ({'; '.join(problems)}). It was created by a release "
            "older than October 2026; see the upgrade guide."
        )
    if problems is not None:
        command.stamp(alembic_config(connection), BASELINE_REVISION)
        logger.warning("action=schema_adopted revision=%s", BASELINE_REVISION)
    command.upgrade(alembic_config(connection), "head")
    after = current_revision(connection)
    connection.commit()
    return before, after


async def _acquire_schema_lock(connection: AsyncConnection) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + LOCK_WAIT_SECONDS
    while True:
        acquired = await connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": SCHEMA_LOCK_KEY})
        await connection.commit()
        if acquired:
            return
        if loop.time() >= deadline:
            raise SchemaError("Timed out waiting for another process to finish migrating the schema")
        await asyncio.sleep(LOCK_POLL_SECONDS)


async def upgrade_database(engine: AsyncEngine) -> str:
    """Apply pending migrations; returns the resulting revision."""
    async with engine.connect() as connection:
        postgres = connection.dialect.name == "postgresql"
        if postgres:
            await _acquire_schema_lock(connection)
        try:
            before, after = await connection.run_sync(_upgrade)
        finally:
            if postgres:
                await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": SCHEMA_LOCK_KEY})
                await connection.commit()
    if before != after:
        logger.warning("action=schema_migrated from=%s to=%s", before or "none", after)
    return after


async def database_revision(engine: AsyncEngine) -> str | None:
    async with engine.connect() as connection:
        return await connection.run_sync(current_revision)


async def require_current_schema(engine: AsyncEngine) -> str:
    revision = await database_revision(engine)
    if revision != head_revision():
        raise SchemaError(
            f"Database schema is at revision {revision or 'none'}, this release needs "
            f"{head_revision()}. Run 'python -m app.migrate' or enable database.auto_migrate."
        )
    return revision


async def prepare_schema(runtime_engine: AsyncEngine) -> None:
    """Startup hook: migrate or verify, as configured."""
    database = get_config().database
    # SQLite has no statement deadlines to relax, and an in-memory database
    # exists only inside its own engine.
    engine = runtime_engine if runtime_engine.dialect.name == "sqlite" else migration_engine()
    try:
        if database.auto_migrate:
            await upgrade_database(engine)
        else:
            await require_current_schema(engine)
    finally:
        if engine is not runtime_engine:
            await engine.dispose()


async def _run(action: str) -> int:
    engine = migration_engine()
    try:
        if action == "upgrade":
            print(f"Database schema is at revision {await upgrade_database(engine)} (latest).")
        elif action == "check":
            try:
                print(f"Database schema is current (revision {await require_current_schema(engine)}).")
            except SchemaError as error:
                print(error)
                return 1
        else:
            print(await database_revision(engine) or "none")
    finally:
        await engine.dispose()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.migrate", description="Manage the database schema.")
    parser.add_argument("action", nargs="?", default="upgrade", choices=("upgrade", "check", "current"))
    args = parser.parse_args()
    try:
        status = asyncio.run(_run(args.action))
    except SchemaError as error:
        parser.exit(status=1, message=f"{error}\n")
    except Exception as error:
        # Connection errors can echo connection parameters; print the type only.
        parser.exit(status=1, message=(
            f"Migration failed ({type(error).__name__}). Check database availability, TLS "
            "settings and the migration role's permissions.\n"
        ))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
