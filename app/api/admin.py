from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from pydantic import BaseModel
from app.database import get_db
from app.models import User, Token
from app.auth import get_current_admin

router = APIRouter(prefix="/admin", tags=["admin"])


class AdminTokenResponse(BaseModel):
    id: str
    name: str
    user_id: str
    user_email: str
    user_name: str
    created_at: str
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked: bool = False


@router.get("/tokens", response_model=list[AdminTokenResponse])
async def list_all_tokens(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user))
        .order_by(Token.created_at.desc())
    )
    tokens = result.scalars().all()
    
    return [
        AdminTokenResponse(
            id=t.id,
            name=t.name,
            user_id=t.user_id,
            user_email=t.user.email,
            user_name=t.user.name,
            created_at=t.created_at.isoformat(),
            expires_at=t.expires_at.isoformat() if t.expires_at else None,
            last_used_at=t.last_used_at.isoformat() if t.last_used_at else None,
            revoked=t.revoked_at is not None
        )
        for t in tokens
    ]


@router.delete("/tokens/{token_id}")
async def revoke_token_admin(
    token_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token).where(Token.id == token_id)
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    token.revoked_at = datetime.utcnow()
    await db.commit()
    
    return {"message": "Token revoked successfully"}


@router.delete("/tokens/{token_id}/permanent")
async def delete_token_admin(
    token_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token).where(Token.id == token_id)
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    await db.delete(token)
    await db.commit()
    
    return {"message": "Token deleted successfully"}


@router.delete("/tokens/revoked")
async def delete_revoked_tokens(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    from datetime import datetime
    result = await db.execute(
        select(Token).where(Token.revoked_at.isnot(None))
    )
    tokens = result.scalars().all()
    
    count = 0
    for token in tokens:
        await db.delete(token)
        count += 1
    
    await db.commit()
    
    return {"message": f"Deleted {count} revoked tokens"}