import os
import ssl
from math import ceil
from pathlib import Path
from sqlalchemy import event, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.engine import URL, make_url
from app.config import get_config
from app.models import Base, User

SCHEMA_LOCK_KEY = 7_316_201
ADMIN_MEMBERSHIP_LOCK_KEY = 7_316_202
MIGRATION_STATEMENT_TIMEOUT_SECONDS = 120

engine = None
async_session_maker = None


def postgres_connect_args(connect_args: dict | None = None, *, migration: bool = False) -> dict:
    database = get_config().database
    statement_timeout = (MIGRATION_STATEMENT_TIMEOUT_SECONDS if migration
                         else database.statement_timeout_seconds)
    idle_timeout = max(database.idle_transaction_timeout_seconds, statement_timeout)
    options = dict(connect_args or {})
    options.setdefault("timeout", database.connect_timeout_seconds)
    options.setdefault("command_timeout", statement_timeout)
    settings = dict(options.get("server_settings", {}))
    for name, seconds in (
        ("statement_timeout", statement_timeout),
        ("lock_timeout", database.lock_timeout_seconds),
        ("idle_in_transaction_session_timeout", idle_timeout),
    ):
        settings.setdefault(name, f"{max(1, ceil(seconds * 1000))}ms")
    options["server_settings"] = settings
    return options


def build_engine(url: str | URL, *, migration: bool = False, **kwargs) -> AsyncEngine:
    """Create an async engine; SQLite gets foreign-key enforcement like Postgres."""
    if make_url(url).drivername == "postgresql+asyncpg":
        kwargs["connect_args"] = postgres_connect_args(kwargs.get("connect_args"), migration=migration)
    new_engine = create_async_engine(url, **kwargs)
    if new_engine.dialect.name == "sqlite":
        @event.listens_for(new_engine.sync_engine, "connect")
        def _enable_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return new_engine


async def lock_user_for_update(
    db: AsyncSession, user_id: str, *, admin_membership: bool = False
) -> User | None:
    """Start a serialized mutation after authentication's read-only transaction."""
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        if db.new or db.dirty or db.deleted:
            raise RuntimeError("Acquire the account lock before making changes")
        if db.in_transaction():
            await db.rollback()
        await db.execute(text("BEGIN IMMEDIATE"))
    elif dialect == "postgresql":
        if admin_membership:
            await db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": ADMIN_MEMBERSHIP_LOCK_KEY},
            )
    else:
        raise RuntimeError("Account mutations require PostgreSQL or SQLite")
    result = await db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def migrate_token_owner_index(migration_engine: AsyncEngine) -> None:
    """Explicit, idempotent migration; PostgreSQL builds without blocking writes."""
    dialect = migration_engine.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError("Index migration requires PostgreSQL or SQLite")
    async with migration_engine.connect() as conn:
        if dialect == "postgresql":
            conn = await conn.execution_options(isolation_level="AUTOCOMMIT")

        def inspect_index(sync_conn, require_present: bool = False) -> None:
            inspector = inspect(sync_conn)
            if not inspector.has_table("tokens"):
                raise RuntimeError("The tokens table must exist before this migration")
            matches = [index for index in inspector.get_indexes("tokens")
                       if index["name"] == "ix_tokens_user_id"]
            if require_present and not matches:
                raise RuntimeError("Token owner index was not created")
            if matches and (matches[0]["column_names"] != ["user_id"] or matches[0]["unique"]):
                raise RuntimeError("Existing ix_tokens_user_id has an unexpected definition")

        await conn.run_sync(inspect_index)
        concurrently = " CONCURRENTLY" if dialect == "postgresql" else ""
        await conn.execute(text(
            f"CREATE INDEX{concurrently} IF NOT EXISTS ix_tokens_user_id ON tokens (user_id)"
        ))
        if dialect == "sqlite":
            await conn.commit()
        else:
            valid = await conn.scalar(text(
                "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass('ix_tokens_user_id')"
            ))
            if valid is not True:
                raise RuntimeError("Existing owner index is invalid; review and rebuild it")
        await conn.run_sync(lambda sync_conn: inspect_index(sync_conn, require_present=True))


async def verify_production_database_role(conn: AsyncConnection) -> None:
    unsafe = await conn.scalar(text(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS role WHERE "
        "(role.rolname = current_user OR role.rolname = session_user OR "
        "pg_catalog.pg_has_role(current_user, role.oid, 'MEMBER') OR "
        "pg_catalog.pg_has_role(session_user, role.oid, 'MEMBER')) AND "
        "(role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR "
        "role.rolreplication OR role.rolbypassrls OR role.rolname IN "
        "('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')))"
    ))
    if unsafe is not False:
        raise RuntimeError("Production database role has unsafe or unverified privileges")


async def init_db():
    global engine, async_session_maker
    config = get_config()
    # hide_parameters keeps bound values (password hashes, token hashes,
    # emails) out of logs and error messages.
    connect_args = {}
    if config.database.url.startswith("postgresql") and config.database.ssl_ca_file:
        connect_args["ssl"] = ssl.create_default_context(cafile=config.database.ssl_ca_file)
    engine = build_engine(
        config.database.url,
        echo=config.database.echo,
        hide_parameters=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        if config.app.environment == "production":
            await verify_production_database_role(conn)
        # Several workers/pods start at once; serialize schema creation.
        if engine.dialect.name == "postgresql":
            await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SCHEMA_LOCK_KEY})
        await conn.run_sync(Base.metadata.create_all)

    # Restrict SQLite database file permissions to owner-only (600)
    # This prevents other users on the system from reading token hashes
    # and user data.
    if config.database.url.startswith("sqlite"):
        db_path = config.database.url.split("///")[-1]
        if db_path and Path(db_path).exists():
            os.chmod(db_path, 0o600)


async def get_db() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


async def close_db():
    global engine
    if engine:
        await engine.dispose()
