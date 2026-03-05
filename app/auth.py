import hashlib
import secrets
import httpx
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import get_config
from app.database import get_db
from app.models import User, Token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
config = get_config()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return secrets.token_hex(config.tokens.token_length_bytes)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=24))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.app.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, config.app.secret_key, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> User:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=302, detail="Not authenticated")
    
    payload = decode_access_token(token)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=302, detail="Invalid token payload")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if user is None:
        raise HTTPException(status_code=302, detail="User not found")
    
    return user


async def get_current_admin(
    user: User = Depends(get_current_user)
) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def get_unity_userinfo(code: str) -> dict:
    import base64
    async with httpx.AsyncClient() as client:
        auth_header = base64.b64encode(f"{config.oauth.client_id}:{config.oauth.client_secret}".encode()).decode()
        
        response = await client.post(
            config.oauth.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.oauth.redirect_uri,
            },
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        
        if response.status_code != 200:
            error_detail = f"Failed to exchange code for token. Status: {response.status_code}, Response: {response.text}"
            raise HTTPException(status_code=400, detail=error_detail)
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        userinfo_response = await client.get(
            config.oauth.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if userinfo_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        return userinfo_response.json()


async def get_or_create_user(userinfo: dict, db: AsyncSession) -> User:
    unity_id = userinfo.get("sub")
    email = userinfo.get("email", "")
    name = userinfo.get("name", userinfo.get("preferred_username", email))
    
    # First try to find by unity_id
    result = await db.execute(select(User).where(User.unity_id == unity_id))
    user = result.scalar_one_or_none()
    
    if user is None and email:
        # Try to find by email (in case of different unity_id)
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
    
    if user is None:
        is_admin = email in config.admin.admin_emails
        user = User(unity_id=unity_id, email=email, name=name, is_admin=is_admin)
        db.add(user)
        try:
            await db.commit()
            await db.refresh(user)
        except Exception:
            await db.rollback()
            # If creation fails, try to fetch existing user
            result = await db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
    
    return user