"""Local security audit probe. Uses synthetic credentials and disposable databases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import os
import sys
import tempfile
from pathlib import Path
os.environ['CONFIG_PATH'] = str(Path(__file__).resolve().parents[2] / 'tests/config.test.yaml')
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'
os.environ['OAUTH_CLIENT_SECRET'] = 'audit-only-synthetic-oauth-secret'
os.environ['RATE_LIMIT_STORAGE_URI'] = 'memory://'
os.environ['JWT_SECRET_KEY'] = 'isolated-audit-jwt-' + '1' * 40
os.environ['TOKEN_HASH_KEY'] = 'isolated-audit-hmac-' + '2' * 40
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import asyncio
from datetime import datetime, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import Request
from app.database import build_engine
from app.models import Base, User, Token
from app.auth import generate_token, hash_token
from app.config import get_config
from app.api.tokens import create_token, CreateTokenRequest
from app.api.admin import update_user, UpdateUserRequest
from app.api.validate import validate_token
from app.main import delete_my_account

def request(path='/', method='POST'):
    return Request({'type': 'http', 'method': method, 'path': path,
                    'query_string': b'', 'headers': [], 'client': ('127.0.0.1', 0)})

class CountGateSession(AsyncSession):
    ready = None
    seen = 0
    async def execute(self, statement, *args, **kwargs):
        result = await super().execute(statement, *args, **kwargs)
        if str(statement).startswith('SELECT count('):
            type(self).seen += 1
            if type(self).seen == 2:
                type(self).ready.set()
            await type(self).ready.wait()
        return result

async def isolated_engine():
    directory = tempfile.mkdtemp(prefix='token-generator-api-audit-')
    engine = build_engine(f'sqlite+aiosqlite:///{directory}/isolated.db', hide_parameters=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine

async def quota_race():
    engine = await isolated_engine()
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        u = User(email='quota@example.invalid', name='Quota')
        db.add(u); await db.commit(); uid = u.id
    gated = async_sessionmaker(engine, class_=CountGateSession, expire_on_commit=False)
    CountGateSession.ready = asyncio.Event(); CountGateSession.seen = 0
    get_config().tokens.max_tokens_per_user = 1
    async def create_one(i):
        async with gated() as db:
            u = await db.get(User, uid)
            try:
                await create_token.__wrapped__(request('/tokens'), CreateTokenRequest(name=f'Test {i}'), u, db)
                return 'created'
            except Exception as exc:
                return type(exc).__name__
    results = await asyncio.gather(create_one(1), create_one(2))
    async with sessions() as db:
        count = (await db.execute(select(func.count()).select_from(Token))).scalar_one()
    print('quota_race', {'configured_max': 1, 'results': results, 'stored_count': count})
    await engine.dispose()

async def last_admin_self_delete():
    engine = await isolated_engine(); sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        u = User(email='sole-admin@example.invalid', name='Sole admin', is_admin=True)
        db.add(u); await db.commit()
        response = await delete_my_account.__wrapped__(request('/account/delete'), u, db)
        count = (await db.execute(select(func.count()).select_from(User).where(User.is_admin.is_(True)))).scalar_one()
        print('last_admin_self_delete', {'response_status': response.status_code, 'remaining_admins': count})
    await engine.dispose()

async def admin_demotion_race():
    engine = await isolated_engine(); sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        users = [User(email=f'admin-{i}@example.invalid', name='Admin', is_admin=True) for i in range(2)]
        db.add_all(users); await db.commit(); ids = [u.id for u in users]
    gated = async_sessionmaker(engine, class_=CountGateSession, expire_on_commit=False)
    CountGateSession.ready = asyncio.Event(); CountGateSession.seen = 0
    async def demote(uid):
        async with gated() as db:
            u = await db.get(User, uid)
            try:
                await update_user.__wrapped__(request('/api/admin/users/' + uid, 'PATCH'), uid,
                    UpdateUserRequest(is_admin=False), u, db)
                return 'demoted'
            except Exception as exc:
                return type(exc).__name__
    results = await asyncio.gather(*(demote(uid) for uid in ids))
    async with sessions() as db:
        count = (await db.execute(select(func.count()).select_from(User).where(User.is_admin.is_(True)))).scalar_one()
    print('admin_demotion_race', {'results': results, 'remaining_admins': count})
    await engine.dispose()

async def extreme_date():
    engine = await isolated_engine(); sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        u = User(email='dates@example.invalid', name='Dates')
        db.add(u); await db.commit()
        try:
            await create_token.__wrapped__(request('/tokens'),
                CreateTokenRequest(name='Test', expires_at='9999-12-31T23:59:59-01:00'), u, db)
            result = 'accepted'
        except Exception as exc:
            result = type(exc).__name__
        print('extreme_date', {'result': result})
    await engine.dispose()

class CommitFailSession(AsyncSession):
    async def commit(self):
        raise RuntimeError('simulated database write outage')

async def validation_write_failure():
    engine = await isolated_engine(); sessions = async_sessionmaker(engine, expire_on_commit=False)
    plain = generate_token()
    async with sessions() as db:
        u = User(email='validation@example.invalid', name='Validation')
        db.add(u); await db.flush()
        db.add(Token(user_id=u.id, token_hash=hash_token(plain), name='Test', expires_at=datetime.utcnow()+timedelta(days=1)))
        await db.commit()
    failed_sessions = async_sessionmaker(engine, class_=CommitFailSession, expire_on_commit=False)
    async with failed_sessions() as db:
        try:
            await validate_token.__wrapped__(request('/api/v1/auth/validate'), plain, db)
            result = 'valid-response'
        except Exception as exc:
            result = type(exc).__name__
        print('validation_write_failure', {'result': result})
    await engine.dispose()

async def main():
    await quota_race()
    await last_admin_self_delete()
    await admin_demotion_race()
    await extreme_date()
    await validation_write_failure()
asyncio.run(main())
