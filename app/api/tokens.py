from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from app.database import get_db
from app.models import User, Token
from app.auth import get_current_user, generate_token, hash_token
from app.config import get_config

router = APIRouter(prefix="/tokens", tags=["["])


class CreateTokenRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    expires_in_days: int | None = Field(None, ge=1, le=365)
    expires_at: str | None = None


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
async def create_token(
    request: CreateTokenRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    config = get_config()
    
    plain_token = generate_token()
    token_hash = hash_token(plain_token)
    
    if request.expires_at:
        expires_at = datetime.fromisoformat(request.expires_at.replace('Z', '+00:00'))
        # Normalize to naive UTC to match other code paths
        if expires_at.tzinfo is not None:
            expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    elif request.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)
    else:
        expires_at = datetime.utcnow() + timedelta(days=config.tokens.default_expiration_days)
    
    # Enforce maximum expiration
    max_expires = datetime.utcnow() + timedelta(days=config.tokens.max_expiration_days)
    if expires_at > max_expires:
        raise HTTPException(
            status_code=400,
            detail=f"Token expiration cannot exceed {config.tokens.max_expiration_days} days from now"
        )
    
    token = Token(
        user_id=user.id,
        token_hash=token_hash,
        name=request.name,
        expires_at=expires_at
    )
    
    db.add(token)
    await db.commit()
    await db.refresh(token)
    
    return TokenWithValueResponse(
        id=token.id,
        name=token.name,
        token=plain_token,
        created_at=token.created_at.isoformat(),
        expires_at=token.expires_at.isoformat() if token.expires_at else None
    )


@router.get("", response_model=list[TokenResponse])
async def list_tokens(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
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
            revoked=t.revoked_at is not None
        )
        for t in tokens
    ]


@router.delete("/{token_id}")
async def revoke_token(
    token_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id)
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    token.revoked_at = datetime.utcnow()
    await db.commit()
    
    return {"message": "Token revoked successfully"}


@router.delete("/{token_id}/permanent")
async def delete_token(
    token_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id)
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    await db.delete(token)
    await db.commit()
    
    return {"message": "Token deleted successfully"}


class RenewTokenRequest(BaseModel):
    expires_in_days: int | None = Field(None, ge=1, le=365)
    expires_at: str | None = None


@router.post("/{token_id}/renew", response_model=TokenResponse)
async def renew_token(
    token_id: str,
    request: RenewTokenRequest | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Fetch token
    result = await db.execute(
        select(Token).where(Token.id == token_id, Token.user_id == user.id)
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    config = get_config()
    # Determine original duration
    if token.expires_at and token.created_at:
        original_duration = token.expires_at - token.created_at
    else:
        original_duration = timedelta(days=config.tokens.default_expiration_days)
    # Compute new expiration
    if request and request.expires_at:
        new_expires_at = datetime.fromisoformat(request.expires_at.replace('Z', '+00:00'))
        # Normalize to naive UTC to match other code paths
        if new_expires_at.tzinfo is not None:
            new_expires_at = new_expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    elif request and request.expires_in_days:
        new_expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)
    else:
        new_expires_at = datetime.utcnow() + original_duration

    # Enforce maximum expiration
    max_expires = datetime.utcnow() + timedelta(days=config.tokens.max_expiration_days)
    if new_expires_at > max_expires:
        raise HTTPException(
            status_code=400,
            detail=f"Token expiration cannot exceed {config.tokens.max_expiration_days} days from now"
        )
    token.expires_at = new_expires_at
    await db.commit()
    await db.refresh(token)
    return TokenResponse(
        id=token.id,
        name=token.name,
        created_at=token.created_at.isoformat(),
        expires_at=token.expires_at.isoformat() if token.expires_at else None,
        last_used_at=token.last_used_at.isoformat() if token.last_used_at else None,
        revoked=token.revoked_at is not None
    )