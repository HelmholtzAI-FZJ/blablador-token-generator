import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select, update
from pydantic import BaseModel, Field, field_validator, model_validator
from app.database import get_db, lock_user_for_update
from app.models import User, Token
from app.auth import get_current_user, generate_token, hash_token, invalidate_sessions
from app.config import get_config
from app.cookies import SESSION_COOKIE
from app.rate_limit import limiter, RATE_LIMITS, user_or_ip

router = APIRouter(prefix="/tokens", tags=["tokens"])
logger = logging.getLogger("token_generator.audit")

# Per signed-in user, so people behind one NAT address do not share a budget.
TOKEN_READ_LIMIT = RATE_LIMITS.tokens_read
TOKEN_WRITE_LIMIT = RATE_LIMITS.tokens_write


async def lock_token_owner(request: Request, user: User, db: AsyncSession) -> User:
    locked = await lock_user_for_update(db, user.id)
    if locked is None:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    if request.cookies.get(SESSION_COOKIE):
        await get_current_user(request, db)
    return locked


class TokenExpirationRequest(BaseModel):
    expires_in_days: int | None = Field(None, ge=1, le=365)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def normalize_expiration(cls, value: datetime | None) -> datetime | None:
        if value is None or value.tzinfo is None:
            return value
        try:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        except (ValueError, OverflowError) as exc:
            raise ValueError("Invalid expires_at value") from exc

    @model_validator(mode="after")
    def validate_expiration_choice(self) -> "TokenExpirationRequest":
        if self.expires_at is not None and self.expires_in_days is not None:
            raise ValueError("Supply expires_at or expires_in_days, not both")
        return self


class CreateTokenRequest(TokenExpirationRequest):
    name: str = Field(..., min_length=1, max_length=255)


def check_expiration(expires_at: datetime) -> None:
    now = datetime.utcnow()
    max_days = get_config().tokens.max_expiration_days
    if expires_at <= now:
        raise HTTPException(status_code=400, detail="Token expiration must be in the future")
    if expires_at > now + timedelta(days=max_days):
        raise HTTPException(
            status_code=400,
            detail=f"Token expiration cannot exceed {max_days} days from now",
        )


class TokenResponse(BaseModel):
    id: str
    name: str
    created_at: str
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked: bool = False


class TokenWithValueResponse(BaseModel):
    id: str
    name: str
    token: str
    created_at: str
    expires_at: str | None = None


@router.post("", response_model=TokenWithValueResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def create_token(
    request: Request,
    body: CreateTokenRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenWithValueResponse:
    config = get_config()
    user = await lock_token_owner(request, user, db)

    token_count = (
        await db.execute(select(func.count()).select_from(Token).where(Token.user_id == user.id))
    ).scalar_one()
    if token_count >= config.tokens.max_tokens_per_user:
        raise HTTPException(
            status_code=400,
            detail=f"Token limit reached ({config.tokens.max_tokens_per_user}). "
                   "Delete tokens you no longer need.",
        )

    plain_token = generate_token()
    token_hash = hash_token(plain_token)

    if body.expires_at is not None:
        expires_at = body.expires_at
    elif body.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)
    else:
        expires_at = datetime.utcnow() + timedelta(days=config.tokens.default_expiration_days)

    check_expiration(expires_at)

    token = Token(
        user_id=user.id,
        token_hash=token_hash,
        name=body.name,
        expires_at=expires_at,
    )

    db.add(token)
    try:
        await db.commit()
        await db.refresh(token)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create token")
    logger.info("user=%s action=create_token token_id=%s expires_at=%s",
                user.id, token.id, token.expires_at.isoformat())

    return TokenWithValueResponse(
        id=token.id,
        name=token.name,
        token=plain_token,
        created_at=token.created_at.isoformat(),
        expires_at=token.expires_at.isoformat() if token.expires_at else None,
    )


@router.post("/revoke-all")
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def revoke_all_tokens(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await lock_token_owner(request, user, db)
    user_id = user.id
    try:
        result = await db.execute(
            update(Token)
            .where(Token.user_id == user_id, Token.revoked_at.is_(None))
            .values(revoked_at=datetime.utcnow())
        )
        await invalidate_sessions(user, db)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to revoke credentials")
    logger.info("user=%s action=revoke_all_credentials count=%d", user_id, result.rowcount)
    return {"message": "All API tokens and sessions revoked", "tokens_revoked": result.rowcount}


@router.get("", response_model=list[TokenResponse])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_tokens(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Token)
        .where(Token.user_id == user.id)
        .order_by(Token.created_at.desc())
    )
    tokens = result.scalars().all()

    return [
        TokenResponse(
            id=t.id,
            name=t.name,
            created_at=t.created_at.isoformat(),
            expires_at=t.expires_at.isoformat() if t.expires_at else None,
            last_used_at=t.last_used_at.isoformat() if t.last_used_at else None,
            revoked=t.revoked_at is not None,
        )
        for t in tokens
    ]


@router.delete("/{token_id}")
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def revoke_token(
    request: Request,
    token_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = await lock_token_owner(request, user, db)
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    token.revoked_at = datetime.utcnow()
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to revoke token")
    logger.info("user=%s action=revoke_token token_id=%s", user.id, token.id)

    return {"message": "Token revoked successfully"}


@router.delete("/{token_id}/permanent")
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def delete_token(
    request: Request,
    token_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = await lock_token_owner(request, user, db)
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    await db.delete(token)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete token")
    logger.info("user=%s action=delete_token token_id=%s", user.id, token_id)

    return {"message": "Token deleted successfully"}


class RenewTokenRequest(TokenExpirationRequest):
    pass


@router.post("/{token_id}/renew", response_model=TokenResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def renew_token(
    request: Request,
    token_id: str,
    body: RenewTokenRequest | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = await lock_token_owner(request, user, db)
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id)
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    config = get_config()

    if token.expires_at and token.created_at:
        original_duration = token.expires_at - token.created_at
    else:
        original_duration = timedelta(days=config.tokens.default_expiration_days)

    if body and body.expires_at is not None:
        new_expires_at = body.expires_at
    elif body and body.expires_in_days:
        new_expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)
    else:
        new_expires_at = datetime.utcnow() + original_duration

    check_expiration(new_expires_at)

    token.expires_at = new_expires_at
    try:
        await db.commit()
        await db.refresh(token)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to renew token")
    logger.info("user=%s action=renew_token token_id=%s expires_at=%s",
                user.id, token.id, token.expires_at.isoformat())

    return TokenResponse(
        id=token.id,
        name=token.name,
        created_at=token.created_at.isoformat(),
        expires_at=token.expires_at.isoformat() if token.expires_at else None,
        last_used_at=token.last_used_at.isoformat() if token.last_used_at else None,
        revoked=token.revoked_at is not None,
    )


@router.post("/{token_id}/rotate", response_model=TokenWithValueResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def rotate_token(
    request: Request,
    token_id: str,
    body: RenewTokenRequest | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenWithValueResponse:
    user = await lock_token_owner(request, user, db)
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id).with_for_update()
    )
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=404, detail="Token not found")
    if token.revoked_at is not None:
        raise HTTPException(status_code=400, detail="Create a new token to replace a revoked token")
    expires_at = token.expires_at
    if body and body.expires_at is not None:
        expires_at = body.expires_at
    elif body and body.expires_in_days is not None:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)
    if expires_at is None:
        expires_at = datetime.utcnow() + timedelta(days=get_config().tokens.default_expiration_days)
    check_expiration(expires_at)
    plain_token = generate_token()
    token.token_hash = hash_token(plain_token)
    token.expires_at = expires_at
    token.last_used_at = None
    try:
        await db.commit()
        await db.refresh(token)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to rotate token")
    logger.info("user=%s action=rotate_token token_id=%s", user.id, token.id)
    return TokenWithValueResponse(
        id=token.id,
        name=token.name,
        token=plain_token,
        created_at=token.created_at.isoformat(),
        expires_at=token.expires_at.isoformat(),
    )
