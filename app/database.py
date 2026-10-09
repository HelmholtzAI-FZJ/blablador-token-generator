import os
from pathlib import Path
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, AsyncSession, async_sessionmaker
from app.config import get_config
from app.models import Base

SCHEMA_LOCK_KEY = 7_316_201

engine = None
async_session_maker = None


def build_engine(url: str, **kwargs) -> AsyncEngine:
    """Create an async engine; SQLite gets foreign-key enforcement like Postgres."""
    new_engine = create_async_engine(url, **kwargs)
    if new_engine.dialect.name == "sqlite":
        @event.listens_for(new_engine.sync_engine, "connect")
        def _enable_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return new_engine


async def init_db():
    global engine, async_session_maker
    config = get_config()
    engine = build_engine(config.database.url, echo=config.app.debug, pool_pre_ping=True)
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
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