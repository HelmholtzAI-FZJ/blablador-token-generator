import os
import ssl
from math import ceil
from pathlib import Path
from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.engine import URL, make_url
from app.config import get_config
from app.models import User

SCHEMA_LOCK_KEY = 7_316_201
ADMIN_MEMBERSHIP_LOCK_KEY = 7_316_202
MIGRATION_STATEMENT_TIMEOUT_SECONDS = 120
# CREATE INDEX CONCURRENTLY waits for older transactions (a running
# backup, an idle transaction) through lock waits.
MIGRATION_LOCK_TIMEOUT_SECONDS = 30

engine = None
async_session_maker = None


def postgres_connect_args(connect_args: dict | None = None, *, migration: bool = False) -> dict:
    database = get_config().database
    statement_timeout = (MIGRATION_STATEMENT_TIMEOUT_SECONDS if migration
                         else database.statement_timeout_seconds)
    lock_timeout = (max(database.lock_timeout_seconds, MIGRATION_LOCK_TIMEOUT_SECONDS) if migration
                    else database.lock_timeout_seconds)
    idle_timeout = max(database.idle_transaction_timeout_seconds, statement_timeout)
    options = dict(connect_args or {})
    options.setdefault("timeout", database.connect_timeout_seconds)
    options.setdefault("command_timeout", statement_timeout)
    settings = dict(options.get("server_settings", {}))
    for name, seconds in (
        ("statement_timeout", statement_timeout),
        ("lock_timeout", lock_timeout),
        ("idle_in_transaction_session_timeout", idle_timeout),
    ):
        settings.setdefault(name, f"{max(1, ceil(seconds * 1000))}ms")
    # Lets an operator tell the service's sessions apart in pg_stat_activity.
    settings.setdefault("application_name", "token-generator-migrate" if migration else "token-generator")
    if migration:
        # A migrator on a lost node holds the schema lock until the server
        # notices; probe idle connections instead of waiting for TCP's hours.
        settings.setdefault("tcp_keepalives_idle", "30")
        settings.setdefault("tcp_keepalives_interval", "10")
        settings.setdefault("tcp_keepalives_count", "3")
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


# Predefined roles that reach beyond the application's own tables: server
# files and programs, every table in the cluster, other sessions.
UNSAFE_PREDEFINED_ROLES = (
    "pg_read_server_files", "pg_write_server_files", "pg_execute_server_program",
    "pg_read_all_data", "pg_write_all_data", "pg_create_subscription", "pg_signal_backend",
)
# Superuser-only functions that read, list or write server files, or reload
# the server configuration, when EXECUTE has been granted on them.
UNSAFE_FUNCTIONS = (
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "lo_import", "lo_export", "pg_reload_conf", "pg_file_write", "pg_file_rename", "pg_file_unlink",
)
_ROLE_OR_MEMBER = (
    "(pg_catalog.pg_has_role(current_user, {oid}, 'MEMBER') "
    "OR pg_catalog.pg_has_role(session_user, {oid}, 'MEMBER'))"
)


async def verify_production_database_role(conn: AsyncConnection) -> None:
    """Refuse a runtime role that can do more than use its own schema."""
    checks = [
        "SELECT 1 FROM pg_catalog.pg_roles AS role WHERE "
        + _ROLE_OR_MEMBER.format(oid="role.oid")
        + " AND (role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolreplication "
        "OR role.rolbypassrls OR role.rolname = ANY(:roles))",
        "SELECT 1 FROM pg_catalog.pg_proc AS function WHERE function.proname = ANY(:functions) "
        "AND (pg_catalog.has_function_privilege(current_user, function.oid, 'EXECUTE') "
        "OR pg_catalog.has_function_privilege(session_user, function.oid, 'EXECUTE'))",
    ]
    if int(await conn.scalar(text("SHOW server_version_num")) or 0) >= 150000:
        # GRANT SET / ALTER SYSTEM ON PARAMETER (PostgreSQL 15+), to the role,
        # a role it belongs to, or PUBLIC (grantee 0).
        checks.append(
            "SELECT 1 FROM pg_catalog.pg_parameter_acl AS parameter, "
            "pg_catalog.aclexplode(parameter.paracl) AS entry WHERE CASE WHEN entry.grantee = 0 "
            "THEN true ELSE " + _ROLE_OR_MEMBER.format(oid="entry.grantee") + " END"
        )
    unsafe = await conn.scalar(
        text("SELECT " + " OR ".join(f"EXISTS ({check})" for check in checks)),
        {"roles": list(UNSAFE_PREDEFINED_ROLES), "functions": list(UNSAFE_FUNCTIONS)},
    )
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

    if config.app.environment == "production":
        async with engine.begin() as conn:
            await verify_production_database_role(conn)
    from app.migrate import prepare_schema
    await prepare_schema(engine)

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
