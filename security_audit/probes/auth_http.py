"""Local security audit probe. Uses synthetic credentials and disposable databases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import os
import pathlib
import tempfile
from sqlalchemy import select
from starlette.testclient import TestClient

for key in ('CONFIG_PATH', 'DATABASE_URL', 'TEST_DATABASE_URL', 'RATE_LIMIT_STORAGE_URI', 'JWT_SECRET_KEY', 'TOKEN_HASH_KEY', 'OAUTH_CLIENT_SECRET', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
    os.environ.pop(key, None)

root=pathlib.Path(__file__).resolve().parents[2]
tmp=pathlib.Path(tempfile.mkdtemp(prefix='token_auth_http_probe_'))
os.environ['CONFIG_PATH']=str(root / 'tests/config.test.yaml')
os.environ['DATABASE_URL']=f'sqlite+aiosqlite:///{tmp}/probe.db'
os.environ['OAUTH_CLIENT_SECRET'] = 'audit-only-synthetic-oauth-secret'
os.environ['RATE_LIMIT_STORAGE_URI']='memory://'
os.environ['JWT_SECRET_KEY']='auth-audit-synthetic-jwt-key-'+'0'*32
os.environ['TOKEN_HASH_KEY']='auth-audit-synthetic-hash-key-'+'1'*32
os.environ['OAUTH_CLIENT_SECRET']='synthetic-oauth-secret'
from app import database
from app.auth import config, create_session_token, decode_access_token, get_or_create_user, revoke_jwt
from app.main import app
from app.models import User

async def promotion_setup():
    async with database.async_session_maker() as db:
        user=await get_or_create_user({'sub':'promoted-sub','email':'promote@audit.invalid'},db)
        old_token=create_session_token(user)
        config.admin.admin_subjects=['promoted-sub']
        await get_or_create_user({'sub':'promoted-sub','email':'promote@audit.invalid'},db)
        return old_token

async def revoked_setup():
    async with database.async_session_maker() as db:
        user=User(email='revoked@audit.invalid',name='Revoked',unity_id='revoked-sub')
        db.add(user)
        await db.commit()
        token=create_session_token(user)
        await revoke_jwt(decode_access_token(token),db)
        return token

with TestClient(app,follow_redirects=False) as client:
    client.cookies.set('access_token',client.portal.call(promotion_setup))
    response=client.get('/api/admin/users')
    print('Pre-promotion session accepted by admin endpoint after config promotion:',response.status_code)
    client.cookies.set('access_token',client.portal.call(revoked_setup))
    statuses=[client.get('/dashboard').status_code for _ in range(130)]
    print('Revoked-session dashboard requests:',len(statuses),'rate limit:',config.rate_limits.pages)
    print('Responses:',{s:statuses.count(s) for s in set(statuses)})
