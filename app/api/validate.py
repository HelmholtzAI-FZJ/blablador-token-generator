from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field
import logging as _logging
from app.database import get_db
from app.models import Token, User, DeletedUser
from app.auth import hash_token
from app.config import get_config
from app.rate_limit import limiter

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_audit = _logging.getLogger("token_generator.audit")


class ValidateRequest(BaseModel):
    token: str | None = Field(None, max_length=256)


class ValidateResponse(BaseModel):
    valid: bool
    user_id: str | None = None
    expires_at: str | None = None
    error: str | None = None


MAX_TOKEN_LENGTH = 256

async def extract_bearer_token(authorization: str | None = Header(None)) -> str | None:
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        if len(token) > MAX_TOKEN_LENGTH:
            return None
        return token
    return None


@router.post("/validate", response_model=ValidateResponse)
@limiter.limit(get_config().app.validate_rate_limit)
async def validate_token(
    request: Request,
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
    
    # Check if the account was deleted after this token was created
    if token.user:
        match = DeletedUser.email == token.user.email
        if token.user.unity_id is not None:
            match = match | (DeletedUser.unity_id == token.user.unity_id)
        tombstone = (await db.execute(select(DeletedUser).where(match))).first()
        if tombstone:
            _audit.warning(
                "user=%s action=revoked_token_used_by_deleted_account "
                "token_id=%s user_email=%s",
                token.user_id,
                token.id,
                token.user.email,
            )
            raise HTTPException(
                status_code=401,
                detail="Token invalid: account has been deleted"
            )
    
    now = datetime.now(timezone.utc)
    if token.expires_at:
        expires = token.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            raise HTTPException(status_code=401, detail="Token has expired")

    token.last_used_at = now.replace(tzinfo=None)
    try:
        await db.commit()
    except Exception:
        await db.rollback()

    def format_datetime(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    return ValidateResponse(
        valid=True,
        user_id=token.user_id,
        expires_at=format_datetime(token.expires_at)
    )