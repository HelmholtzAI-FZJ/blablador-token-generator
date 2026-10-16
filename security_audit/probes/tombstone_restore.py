"""Local security audit probe. Uses synthetic credentials and disposable databases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import os, sys
os.environ['CONFIG_PATH']=str(Path(__file__).resolve().parents[2] / 'tests/config.test.yaml')
os.environ['JWT_SECRET_KEY']='isolated-tombstone-jwt-'+'1'*40
os.environ['TOKEN_HASH_KEY']='isolated-tombstone-hmac-'+'2'*40
os.environ['OAUTH_CLIENT_SECRET'] = 'audit-only-synthetic-oauth-secret'
os.environ['RATE_LIMIT_STORAGE_URI']='memory://'
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
import asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker
from starlette.requests import Request
from app.database import build_engine
from app.models import Base,User
from app.auth import get_or_create_user
from app.tombstones import record_deletion,is_subject_deleted
from app.api.admin import create_user,CreateUserRequest
async def run():
    engine=build_engine('sqlite+aiosqlite:///:memory:',hide_parameters=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions=async_sessionmaker(engine,expire_on_commit=False)
    async with sessions() as db:
        admin=User(email='admin@example.invalid',name='Admin',is_admin=True)
        db.add(admin);await db.commit()
        gone=await get_or_create_user({'sub':'unrelated-banned-subject','email':'owner@example.invalid','email_verified':False},db)
        record_deletion(db,gone);await db.delete(gone);await db.commit()
        blocked_before=await is_subject_deleted(db,'unrelated-banned-subject')
        request=Request({'type':'http','method':'POST','path':'/api/admin/users','headers':[],'query_string':b'','client':('127.0.0.1',0)})
        await create_user.__wrapped__(request,CreateUserRequest(email='owner@example.invalid',name='Real owner',password='IsolatedPass9'),admin,db)
        blocked_after=await is_subject_deleted(db,'unrelated-banned-subject')
        resurrected=await get_or_create_user({'sub':'unrelated-banned-subject','email':'owner@example.invalid','email_verified':False},db)
        print({'subject_blocked_before_local_creation':blocked_before,'subject_blocked_after_local_creation':blocked_after,'oauth_resurrected':resurrected.unity_id=='unrelated-banned-subject'})
    await engine.dispose()
asyncio.run(run())
