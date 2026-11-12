"""Alembic environment.

The application runs migrations through app.migrate, which hands over an
open connection. The alembic command line (used to author revisions) gets
an engine built from the application configuration instead.
"""
import asyncio

from alembic import context

from app.models import Base

target_metadata = Base.metadata


def run_migrations(connection) -> None:
    if connection.dialect.name != "sqlite":
        _run(connection)
        return
    # SQLite alters a table by rebuilding it, and dropping the old copy
    # would cascade-delete the rows referencing it. The pragma only takes
    # effect outside a transaction.
    connection.commit()
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    try:
        _run(connection)
        dangling = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
        if dangling:
            raise RuntimeError(f"Migration left {len(dangling)} rows with dangling references")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Revisions may need autocommit blocks (CREATE INDEX CONCURRENTLY).
        transaction_per_migration=True,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_with_configured_database() -> None:
    from app.migrate import migration_engine

    engine = migration_engine()
    try:
        async with engine.connect() as connection:
            await connection.run_sync(run_migrations)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (--sql) migrations are not supported; use python -m app.migrate.")
connection = context.config.attributes.get("connection")
if connection is not None:
    run_migrations(connection)
else:
    asyncio.run(run_with_configured_database())
