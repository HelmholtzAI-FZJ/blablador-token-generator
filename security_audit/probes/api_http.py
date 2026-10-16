"""Local security audit probe. Uses synthetic credentials and disposable databases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import os
import sys
import tempfile
os.environ['CONFIG_PATH'] = str(Path(__file__).resolve().parents[2] / 'tests/config.test.yaml')
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///' + tempfile.mkdtemp(prefix='token-generator-http-audit-') + '/isolated.db'
os.environ['OAUTH_CLIENT_SECRET'] = 'audit-only-synthetic-oauth-secret'
os.environ['RATE_LIMIT_STORAGE_URI'] = 'memory://'
os.environ['JWT_SECRET_KEY'] = 'isolated-http-audit-jwt-' + '1'*40
os.environ['TOKEN_HASH_KEY'] = 'isolated-http-audit-hmac-' + '2'*40
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from app.main import app
from app import database
from app.models import User, Token
from app.auth import generate_token, hash_token, create_session_token

with TestClient(app, raise_server_exceptions=False) as client:
    async def seed():
        async with database.async_session_maker() as db:
            a=User(email='a@example.invalid',name='A',is_admin=False)
            b=User(email='b@example.invalid',name='B',is_admin=False)
            admin=User(email='admin@example.invalid',name='Admin',is_admin=True)
            db.add_all([a,b,admin]); await db.flush()
            tokens=[]
            for owner,label,expires,revoked in [(a,'A token',None,None),(b,'B token',None,None),
                  (a,'A expired',datetime.utcnow()-timedelta(days=1),None),
                  (a,'A revoked',None,datetime.utcnow())]:
                plain=generate_token()
                t=Token(user_id=owner.id, name=label,token_hash=hash_token(plain),expires_at=expires,revoked_at=revoked)
                db.add(t); await db.flush(); tokens.append((t.id,plain))
            await db.commit()
            return create_session_token(a),create_session_token(admin),tokens
    a_session,admin_session,tokens=client.portal.call(seed)
    client.cookies.set('access_token',a_session); client.cookies.set('csrf_token','isolated')
    csrf={'X-CSRF-Token':'isolated'}
    results={}
    results['list_own_only']={item['name'] for item in client.get('/tokens').json()}=={'A token','A expired','A revoked'}
    target=tokens[1][0]
    results['other_user_revoke']=client.delete('/tokens/'+target,headers=csrf).status_code
    results['other_user_delete']=client.delete('/tokens/'+target+'/permanent',headers=csrf).status_code
    results['other_user_renew']=client.post('/tokens/'+target+'/renew',headers=csrf,json={'expires_in_days':1}).status_code
    results['nonadmin_users']=client.get('/api/admin/users',follow_redirects=False).status_code
    results['nonadmin_create_user']=client.post('/api/admin/users',headers=csrf,json={'email':'x@example.invalid','name':'X','password':'Passw0rdOK'}).status_code
    results['expired_validate']=client.post('/api/v1/auth/validate',headers={'Authorization':'Bearer '+tokens[2][1]}).status_code
    results['revoked_renew']=client.post('/tokens/'+tokens[3][0]+'/renew',headers=csrf,json={'expires_in_days':1}).json()['revoked']
    results['revoked_validate_after_renew']=client.post('/api/v1/auth/validate',headers={'Authorization':'Bearer '+tokens[3][1]}).status_code
    results['extreme_date']=client.post('/tokens',headers=csrf,json={'name':'Extreme','expires_at':'9999-12-31T23:59:59-01:00'}).status_code
    client.cookies.set('access_token',admin_session)
    marker='AuditSecret9'+'x'*130
    response=client.post('/api/admin/users',headers=csrf,json={'email':'long@example.invalid','name':'Long','password':marker})
    results['password_422']={'status':response.status_code,'echoes_input':marker in response.text,
        'cache_control':response.headers.get('cache-control')}
    results['large_page']=client.get('/api/admin/users',params={'page':10**40}).status_code
    response=client.post('/tokens',headers=csrf,content=b'x'*70000)
    results['large_body']={'status':response.status_code,'security_headers':{
        name: name in response.headers for name in ['cache-control','content-security-policy','strict-transport-security','x-content-type-options']}}
    print(results)
