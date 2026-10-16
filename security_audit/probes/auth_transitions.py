"""Local security audit probe. Uses synthetic credentials and disposable databases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import asyncio
import os
import pathlib
import tempfile
import time

for key in ('CONFIG_PATH', 'DATABASE_URL', 'TEST_DATABASE_URL', 'RATE_LIMIT_STORAGE_URI', 'JWT_SECRET_KEY', 'TOKEN_HASH_KEY', 'OAUTH_CLIENT_SECRET', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
    os.environ.pop(key, None)

root = pathlib.Path(__file__).resolve().parents[2]
tmp = pathlib.Path(tempfile.mkdtemp(prefix='token_auth_security_probe_'))
os.environ['CONFIG_PATH'] = str(root / 'tests/config.test.yaml')
os.environ['DATABASE_URL'] = f'sqlite+aiosqlite:///{tmp}/probe.db'
os.environ['OAUTH_CLIENT_SECRET'] = 'audit-only-synthetic-oauth-secret'
os.environ['RATE_LIMIT_STORAGE_URI'] = 'memory://'
os.environ['JWT_SECRET_KEY'] = 'auth-audit-synthetic-jwt-key-' + '0' * 32
os.environ['TOKEN_HASH_KEY'] = 'auth-audit-synthetic-hash-key-' + '1' * 32
os.environ['OAUTH_CLIENT_SECRET'] = 'synthetic-oauth-secret'

from sqlalchemy import func, select
from starlette.requests import Request
from app import database
from app.auth import authenticate_local_user, config, create_session_token, decode_access_token, get_current_user, get_or_create_user, revoke_jwt
from app.api.admin import UpdateUserRequest, update_user
from app.main import delete_my_account
from app.models import User, RevokedJWT


def req(token=None, method='GET', path='/dashboard'):
    headers = [(b'cookie', f'access_token={token}; csrf_token=audit'.encode())] if token else []
    return Request({'type': 'http', 'method': method, 'path': path, 'query_string': b'', 'headers': headers, 'client': ('127.0.0.21', 10000)})


async def main():
    await database.init_db()
    async with database.async_session_maker() as db:
        config.admin.admin_subjects = ['configured-admin']
        configured = await get_or_create_user({'sub':'configured-admin', 'email':'admin@audit.invalid'}, db)
        other = User(email='other@audit.invalid', name='Other', unity_id='other-admin', is_admin=True)
        db.add(other)
        await db.commit()
        await update_user.__wrapped__(req(method='PATCH'), configured.id, UpdateUserRequest(is_admin=False), other, db)
        print('Configured admin after explicit demotion:', configured.is_admin)
        relogged = await get_or_create_user({'sub':'configured-admin', 'email':'admin@audit.invalid'}, db)
        print('Configured admin after next OAuth login:', relogged.is_admin)

        victim = User(email='logout@audit.invalid', name='Logout', unity_id='logout-sub')
        db.add(victim)
        await db.commit()
        token = create_session_token(victim)
        payload = decode_access_token(token)
        real_commit = db.commit
        async def reject_commit():
            raise RuntimeError('synthetic write failure')
        db.commit = reject_commit
        await revoke_jwt(payload, db)
        db.commit = real_commit
        exists = (await db.execute(select(RevokedJWT).where(RevokedJWT.jti == payload['jti']))).scalar_one_or_none()
        user = await get_current_user(req(token), db)
        print('Logout revocation write failure raised to caller:', False)
        print('Revocation row persisted:', exists is not None)
        print('Original session accepted after failed revocation:', user is not None)

    async with database.async_session_maker() as db:
        config.admin.admin_subjects = []
        admins = (await db.execute(select(User).where(User.is_admin.is_(True)))).scalars().all()
        for a in admins:
            a.is_admin = False
        lone = User(email='lone@audit.invalid', name='Lone', unity_id='lone-admin', is_admin=True)
        db.add(lone)
        await db.commit()
        response = await delete_my_account.__wrapped__(req(create_session_token(lone), method='POST', path='/account/delete'), lone, db)
        remaining = (await db.execute(select(func.count()).where(User.is_admin.is_(True)))).scalar_one()
        print('Sole admin self-deletion response:', response.status_code)
        print('Remaining admin count:', remaining)

    async with database.async_session_maker() as db:
        observed = []
        async def ticker():
            start = time.perf_counter()
            await asyncio.sleep(0.01)
            observed.append(time.perf_counter() - start)
        await authenticate_local_user('unknown@audit.invalid', 'WrongPass1', db)
        tick = asyncio.create_task(ticker())
        await asyncio.sleep(0)
        start = time.perf_counter()
        from app.auth import verify_password, _DUMMY_HASH
        verify_password('WrongPass1', _DUMMY_HASH)
        elapsed = time.perf_counter() - start
        await tick
        print('Synchronous bcrypt duration seconds:', round(elapsed, 3))
        print('10ms event-loop timer delay seconds:', round(observed[0], 3))
    await database.close_db()

asyncio.run(main())
