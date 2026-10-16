"""Local security audit probe. Uses synthetic credentials and disposable databases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import asyncio
import os
from pathlib import Path
import tempfile

for key in ('CONFIG_PATH', 'DATABASE_URL', 'TEST_DATABASE_URL', 'RATE_LIMIT_STORAGE_URI', 'JWT_SECRET_KEY', 'TOKEN_HASH_KEY', 'OAUTH_CLIENT_SECRET', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
    os.environ.pop(key, None)
root = Path(str(Path(__file__).resolve().parents[2]))
tmp = Path(tempfile.mkdtemp(prefix='token_session_epoch_probe_'))
os.environ['CONFIG_PATH'] = str(root / 'tests/config.test.yaml')
os.environ['DATABASE_URL'] = f'sqlite+aiosqlite:///{tmp}/probe.db'
os.environ['OAUTH_CLIENT_SECRET'] = 'audit-only-synthetic-oauth-secret'
os.environ['RATE_LIMIT_STORAGE_URI'] = 'memory://'
os.environ['JWT_SECRET_KEY'] = 'session-epoch-audit-synthetic-jwt-' + '0' * 32
os.environ['TOKEN_HASH_KEY'] = 'session-epoch-audit-synthetic-hmac-' + '1' * 32
os.environ['OAUTH_CLIENT_SECRET'] = 'synthetic-oauth-secret'

from sqlalchemy import select
from starlette.requests import Request
from app import database
from app.auth import create_session_token, get_current_user, hash_password
from app.api.admin import UpdateUserRequest, update_user
from app.models import User


def request(method='PATCH', token=None):
    headers = [(b'cookie', f'access_token={token}'.encode())] if token else []
    return Request({'type': 'http', 'method': method, 'path': '/api/admin/users/synthetic', 'query_string': b'', 'headers': headers, 'client': ('127.0.0.44', 10000)})


async def main():
    await database.init_db()
    async with database.async_session_maker() as seed:
        target = User(email='epoch-target@audit.invalid', name='Target', password_hash=hash_password('InitialPassw0rd'))
        admin = User(email='epoch-admin@audit.invalid', name='Admin', unity_id='epoch-admin-sub', is_admin=True)
        seed.add_all([target, admin])
        await seed.commit()
        target_id, admin_id = target.id, admin.id

    async with database.async_session_maker() as first, database.async_session_maker() as second:
        first_target = (await first.execute(select(User).where(User.id == target_id))).scalar_one()
        second_target = (await second.execute(select(User).where(User.id == target_id))).scalar_one()
        first_admin = (await first.execute(select(User).where(User.id == admin_id))).scalar_one()
        second_admin = (await second.execute(select(User).where(User.id == admin_id))).scalar_one()
        print('Initial epoch seen by both concurrent sessions:', first_target.session_epoch, second_target.session_epoch)
        await update_user.__wrapped__(request(), target_id, UpdateUserRequest(password='FirstResetPassw0rd'), first_admin, first)
        print('Epoch after first password reset:', first_target.session_epoch)
        intermediate_cookie = create_session_token(first_target)
        print('Second session still holds stale epoch:', second_target.session_epoch)
        await update_user.__wrapped__(request(), target_id, UpdateUserRequest(password='SecondResetPassw0rd'), second_admin, second)
        print('Epoch after second concurrent password reset:', second_target.session_epoch)

    async with database.async_session_maker() as verify:
        current = await get_current_user(request(method='GET', token=intermediate_cookie), verify)
        print('Session issued between the two resets accepted after second reset:', current is not None)
    await database.close_db()

asyncio.run(main())
