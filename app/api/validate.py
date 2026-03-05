from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from pydantic import BaseModel
from app.database import get_db
from app.models import Token, User
from app.auth import hash_token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class ValidateRequest(BaseModel):
    token: str | None = None


class ValidateResponse(BaseModel):
    valid: bool
    user_id: str | None = None
    id: int | None = None
    username: str | None = None
    email: str | None = None
    name: str | None = None
    state: str = "active"
    locked: bool = False
    created_at: str | None = None
    last_sign_in_at: str | None = None
    expires_at: str | None = None
    error: str | None = None


async def extract_bearer_token(authorization: str | None = Header(None)) -> str | None:
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    return None


@router.post("/validate", response_model=ValidateResponse)
async def validate_token(
    bearer_token: str = Depends(extract_bearer_token),
    db: AsyncSession = Depends(get_db)
):
    if not bearer_token:
        raise HTTPException(status_code=401, detail="No token provided. Use Bearer token.")
    
    token_hash = hash_token(bearer_token)
    
    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user))
        .where(
            Token.token_hash == token_hash,
            Token.revoked_at.is_(None)
        )
    )
    token = result.scalar_one_or_none()
    
    if token is None:
        raise HTTPException(status_code=401, detail="Token not found or revoked")
    
    now = datetime.now(timezone.utc)
    if token.expires_at:
        # Make expires_at timezone-aware if it's naive
        expires = token.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            raise HTTPException(status_code=401, detail="Token has expired")
    
    last_used = now
    token.last_used_at = now.replace(tzinfo=None)  # Store as naive for SQLite
    await db.commit()
    
    user = token.user
    username = user.email.split("@")[0] if user.email else None
    
    def format_datetime(dt):
        if dt is None:
            return None
        # Make timezone-aware if naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    
    return ValidateResponse(
        valid=True,
        user_id=user.id,
        id=hash_string(user.id[:8], 16) if user.id else None,
        username=username,
        email=user.email,
        name=user.name,
        state="active",
        locked=False,
        created_at=format_datetime(user.created_at),
        last_sign_in_at=format_datetime(last_used),
        expires_at=format_datetime(token.expires_at)
    )


def hash_string(s: str, base: int) -> int:
    """Simple hash to generate integer from string"""
    return sum(ord(c) * (base ** i) for i, c in enumerate(s[:8]))