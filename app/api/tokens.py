from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.database import get_db
from app.models import User, Token
from app.auth import get_current_user, generate_token, hash_token
from app.config import get_config

router = APIRouter(prefix="/tokens", tags=["tokens"])


class CreateTokenRequest(BaseModel):
    name: str
    expires_in_days: int | None = None
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
    elif request.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)
    else:
        expires_at = datetime.utcnow() + timedelta(days=config.tokens.default_expiration_days)
    
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