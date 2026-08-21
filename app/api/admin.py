from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from pydantic import BaseModel
from app.database import get_db
from app.models import User, Token
from app.auth import get_current_admin, hash_password

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

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    is_admin: bool
    created_at: str
    has_password: bool
    unity_id: str | None = None

class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    is_admin: bool = False

class UpdateUserRequest(BaseModel):
    name: str | None = None
    password: str | None = None
    is_admin: bool | None = None

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

@router.get("/users", response_model=list[UserResponse])
async def list_users(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            name=u.name,
            is_admin=u.is_admin,
            created_at=u.created_at.isoformat(),
            has_password=u.password_hash is not None,
            unity_id=u.unity_id
        )
        for u in users
    ]

@router.post("/users", response_model=UserResponse)
async def create_user(
    request: CreateUserRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    # Check if user exists
    result = await db.execute(select(User).where(User.email == request.email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")
    
    user = User(
        email=request.email,
        name=request.name,
        password_hash=hash_password(request.password),
        is_admin=request.is_admin,
        unity_id=None
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat(),
        has_password=True,
        unity_id=user.unity_id
    )

@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    request: UpdateUserRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if request.name is not None:
        user.name = request.name
    if request.password is not None:
        user.password_hash = hash_password(request.password)
    if request.is_admin is not None:
        user.is_admin = request.is_admin
    
    await db.commit()
    await db.refresh(user)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat(),
        has_password=user.password_hash is not None,
        unity_id=user.unity_id
    )

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deletion
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    await db.delete(user)
    await db.commit()
    
    return {"message": "User deleted successfully"}
