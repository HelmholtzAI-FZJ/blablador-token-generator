import os
import tempfile
from pathlib import Path

# Never pick up the developer's config.yaml, secrets or database: tests run
# against tests/config.test.yaml and a throwaway SQLite file unless
# TEST_DATABASE_URL points them at another database.
os.environ["CONFIG_PATH"] = str(Path(__file__).parent / "config.test.yaml")
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL",
    f"sqlite+aiosqlite:///{tempfile.mkdtemp(prefix='token_generator_tests_')}/app.db",
)
os.environ["RATE_LIMIT_STORAGE_URI"] = "memory://"
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-" + "0" * 32)
os.environ.setdefault("TOKEN_HASH_KEY", "test-token-hash-key-" + "0" * 32)

import pytest
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from app.database import build_engine
from app.models import Base, User, Token
from app.auth import hash_token, generate_token
from app.config import TokenConfig
from unittest.mock import patch


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db():
    url = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = build_engine(url, echo=False)
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with async_session_maker() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def test_user(test_db):
    user = User(
        unity_id="test-user-123",
        email="test@example.com",
        name="Test User",
        is_admin=False
    )
    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)
    return user


@pytest.fixture
async def test_admin(test_db):
    admin = User(
        unity_id="admin-user-456",
        email="admin@example.com",
        name="Admin User",
        is_admin=True
    )
    test_db.add(admin)
    await test_db.commit()
    await test_db.refresh(admin)
    return admin


@pytest.fixture
async def test_token(test_db, test_user):
    plain_token = generate_token()
    token = Token(
        user_id=test_user.id,
        token_hash=hash_token(plain_token),
        name="Test Token"
    )
    test_db.add(token)
    await test_db.commit()
    await test_db.refresh(token)
    return {"token": token, "plain_token": plain_token}