import hashlib
import secrets
import httpx
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import get_config
from app.database import get_db
from app.models import User, Token, RevokedJWT

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
config = get_config()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


MIN_PASSWORD_LENGTH = 8


def validate_password_strength(password: str) -> None:
    """Enforce basic password complexity.

    Raises:
        HTTPException: 400 if the password is too short, missing
        uppercase, lowercase, or digit requirements.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters long",
        )
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one uppercase letter",
        )
    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one lowercase letter",
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one digit",
        )


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    prefix = config.tokens.token_prefix
    return f"{prefix}-{secrets.token_hex(config.tokens.token_length_bytes)}"


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=config.app.jwt_expiration_hours)
    # Add a unique JWT ID so individual session tokens can be
    # revoked (blacklisted) without rotating the signing key.
    to_encode.update({"exp": expire, "jti": secrets.token_hex(16)})
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


async def revoke_jwt(payload: dict, db: AsyncSession) -> None:
    """Add a JWT's jti to the revocation blacklist."""
    jti = payload.get("jti")
    if not jti:
        return
    exp_ts = payload.get("exp", 0)
    exp = datetime.utcfromtimestamp(exp_ts)
    existing = await db.execute(select(RevokedJWT).where(RevokedJWT.jti == jti))
    if existing.scalar_one_or_none() is None:
        db.add(RevokedJWT(
            jti=jti,
            user_id=payload.get("sub", ""),
            expires_at=exp,
        ))
        await db.commit()


async def is_jwt_revoked(payload: dict, db: AsyncSession) -> bool:
    """Check if a JWT has been revoked."""
    jti = payload.get("jti")
    if not jti:
        return False
    result = await db.execute(select(RevokedJWT).where(RevokedJWT.jti == jti))
    return result.scalar_one_or_none() is not None


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

    # Check JWT revocation blacklist
    if await is_jwt_revoked(payload, db):
        raise HTTPException(status_code=302, detail="Token has been revoked")

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
            raise HTTPException(status_code=400, detail="Failed to exchange authorization code")

        token_data = response.json()
        access_token = token_data.get("access_token")

        userinfo_response = await client.get(
            config.oauth.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if userinfo_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve user information")
        
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

    # Sync admin status from config on every login so that
    # adding/removing emails in admin_emails takes effect for
    # existing users, not just new ones.
    is_admin = email in config.admin.admin_emails

    if user is None:
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
    elif user.is_admin != is_admin:
        user.is_admin = is_admin
        await db.commit()
        await db.refresh(user)

    return user

async def authenticate_local_user(email: str, password: str, db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.email == email, User.password_hash.isnot(None)))
    user = result.scalar_one_or_none()
    if not user or not user.password_hash:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user