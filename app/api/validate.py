from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import or_, select, update
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field
import logging as _logging
from app.database import get_db
from app.config import get_config
from app.models import Token, User
from app.tombstones import is_user_deleted
from app.auth import hash_token
from app.rate_limit import limiter, RATE_LIMITS, is_token_validation_exempt
from app.timeutil import isoformat_utc

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
@limiter.limit(RATE_LIMITS.token_validation, exempt_when=is_token_validation_exempt)
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
    
    if token is None or token.user is None:
        raise HTTPException(status_code=401, detail="Token not found or revoked")
    
    # Check if the account was deleted after this token was created
    if await is_user_deleted(db, token.user):
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
        if expires <= now:
            raise HTTPException(status_code=401, detail="Token has expired")

    response = ValidateResponse(
        valid=True,
        user_id=token.user_id,
        expires_at=isoformat_utc(token.expires_at)
    )
    token_id = token.id
    now_naive = now.replace(tzinfo=None)
    cutoff = now_naive - timedelta(seconds=get_config().tokens.last_used_update_seconds)
    last_used_at = token.last_used_at
    if last_used_at is not None and last_used_at.tzinfo is not None:
        last_used_at = last_used_at.astimezone(timezone.utc).replace(tzinfo=None)
    if last_used_at is None or last_used_at <= cutoff:
        try:
            await db.execute(
                update(Token)
                .where(
                    Token.id == token_id,
                    Token.token_hash == token_hash,
                    Token.revoked_at.is_(None),
                    or_(Token.last_used_at.is_(None), Token.last_used_at <= cutoff),
                )
                .values(last_used_at=now_naive)
                .execution_options(synchronize_session=False)
            )
            await db.commit()
        except Exception as exc:
            await db.rollback()
            _audit.warning(
                "action=token_usage_update_failed token_id=%s error_type=%s",
                token_id, type(exc).__name__,
            )
    return response
