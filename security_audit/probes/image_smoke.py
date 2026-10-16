"""Run an isolated ASGI smoke check inside the built production image."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, '/app')
os.environ['CONFIG_PATH'] = '/audit/config.test.yaml'
os.environ['APP_ENVIRONMENT'] = 'development'
os.environ['DATABASE_URL'] = f"sqlite+aiosqlite:///{tempfile.mkdtemp(prefix='image_audit_')}/test.db"
os.environ['JWT_SECRET_KEY'] = 'image-audit-synthetic-jwt-' + '0' * 40
os.environ['TOKEN_HASH_KEY'] = 'image-audit-synthetic-hmac-' + '1' * 40
os.environ['OAUTH_CLIENT_SECRET'] = 'image-audit-synthetic-oauth'
os.environ['RATE_LIMIT_STORAGE_URI'] = 'memory://'

from starlette.testclient import TestClient
from app import database
from app.auth import create_session_token
from app.main import app
from app.models import User

async def seed():
    async with database.async_session_maker() as db:
        user = User(email='image@example.invalid', name='Image audit', unity_id='image-audit-sub')
        db.add(user)
        await db.commit()
        return create_session_token(user)

with TestClient(app, follow_redirects=False) as client:
    assert client.get('/healthz').status_code == 200
    client.get('/')
    client.cookies.set('access_token', client.portal.call(seed))
    csrf = {'X-CSRF-Token': client.cookies.get('csrf_token')}
    created = client.post('/tokens', headers=csrf, json={'name': 'Image audit', 'expires_in_days': 1})
    assert created.status_code == 200
    value = created.json()
    valid = client.post('/api/v1/auth/validate', headers={'Authorization': 'Bearer ' + value['token']})
    assert valid.status_code == 200 and valid.json()['valid'] is True
    assert client.delete('/tokens/' + value['id'], headers=csrf).status_code == 200
    assert client.post('/api/v1/auth/validate', headers={'Authorization': 'Bearer ' + value['token']}).status_code == 401
    assert client.post('/logout', headers=csrf).status_code == 200
    assert client.get('/dashboard').status_code == 303
print(json.dumps({'uid': os.getuid(), 'health': True, 'create': True, 'validate': True, 'revoke': True, 'logout': True}))
