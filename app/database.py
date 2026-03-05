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


async def get_db() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


async def close_db():
    global engine
    if engine:
        await engine.dispose()