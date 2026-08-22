import os
from pathlib import Path
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import get_config
from app.models import Base

engine = None
async_session_maker = None


async def init_db():
    global engine, async_session_maker
    config = get_config()
    engine = create_async_engine(config.database.url, echo=config.app.debug)
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
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