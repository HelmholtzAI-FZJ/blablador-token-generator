from datetime import datetime
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field
from app.database import get_db
from app.models import User, Token
from app.auth import get_current_admin, hash_password, validate_password_strength
from app.rate_limit import limiter

logger = logging.getLogger("token_generator.audit")
router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_RATE_LIMIT = "60/minute"
MAX_PAGE_SIZE = 100


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
    unity_id: str | None = None


class CreateUserRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    name: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    is_admin: bool = False


class UpdateUserRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    password: str | None = Field(None, min_length=8, max_length=128)
    is_admin: bool | None = None


@router.get("/tokens", response_model=list[AdminTokenResponse])
@limiter.limit(ADMIN_RATE_LIMIT)
async def list_all_tokens(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=MAX_PAGE_SIZE),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user))
        .order_by(Token.created_at.desc())
        .offset(offset)
        .limit(page_size)
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
            revoked=t.revoked_at is not None,
        )
        for t in tokens
    ]


@router.delete("/tokens/{token_id}")
@limiter.limit(ADMIN_RATE_LIMIT)
async def revoke_token_admin(
    request: Request,
    token_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Token).where(Token.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    token.revoked_at = datetime.utcnow()
    await db.commit()
    logger.info(
        "admin=%s action=revoke_token token_id=%s user_id=%s",
        admin.id,
        token.id,
        token.user_id,
    )
    return {"message": "Token revoked successfully"}


@router.delete("/tokens/{token_id}/permanent")
@limiter.limit(ADMIN_RATE_LIMIT)
async def delete_token_admin(
    request: Request,
    token_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Token).where(Token.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    await db.delete(token)
    await db.commit()
    logger.info(
        "admin=%s action=delete_token token_id=%s user_id=%s",
        admin.id,
        token.id,
        token.user_id,
    )
    return {"message": "Token deleted successfully"}


@router.delete("/tokens/revoked")
@limiter.limit(ADMIN_RATE_LIMIT)
async def delete_revoked_tokens(
    request: Request,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Token).where(Token.revoked_at.isnot(None)))
    tokens = result.scalars().all()

    count = 0
    for token in tokens:
        await db.delete(token)
        count += 1

    await db.commit()
    logger.info(
        "admin=%s action=delete_revoked_tokens count=%d",
        admin.id,
        count,
    )
    return {"message": f"Deleted {count} revoked tokens"}


@router.get("/users", response_model=list[UserResponse])
@limiter.limit(ADMIN_RATE_LIMIT)
async def list_users(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=MAX_PAGE_SIZE),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * page_size
    result = await db.execute(
        select(User)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    users = result.scalars().all()

    return [
        UserResponse(
            id=u.id,
            email=u.email,
            name=u.name,
            is_admin=u.is_admin,
            created_at=u.created_at.isoformat(),
            unity_id=u.unity_id,
        )
        for u in users
    ]


@router.post("/users", response_model=UserResponse)
@limiter.limit(ADMIN_RATE_LIMIT)
async def create_user(
    request: Request,
    body: CreateUserRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    # Prevent privilege escalation: only existing admins can grant admin status
    result = await db.execute(select(User).where(User.email == body.email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    validate_password_strength(body.password)

    user = User(
        email=body.email,
        name=body.name,
        password_hash=hash_password(body.password),
        is_admin=body.is_admin,
        unity_id=None,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info(
        "admin=%s action=create_user user_id=%s email=%s is_admin=%s",
        admin.id,
        user.id,
        user.email,
        user.is_admin,
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat(),
        unity_id=user.unity_id,
    )


@router.patch("/users/{user_id}", response_model=UserResponse)
@limiter.limit(ADMIN_RATE_LIMIT)
async def update_user(
    request: Request,
    user_id: str,
    body: UpdateUserRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.name is not None:
        user.name = body.name
    if body.password is not None:
        validate_password_strength(body.password)
        user.password_hash = hash_password(body.password)
    if body.is_admin is not None:
        user.is_admin = body.is_admin

    try:
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update user")

    logger.info(
        "admin=%s action=update_user user_id=%s is_admin=%s",
        admin.id,
        user.id,
        user.is_admin,
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat(),
        unity_id=user.unity_id,
    )


@router.delete("/users/{user_id}")
@limiter.limit(ADMIN_RATE_LIMIT)
async def delete_user(
    request: Request,
    user_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    await db.delete(user)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete user")
    logger.info("admin=%s action=delete_user user_id=%s", admin.id, user.id)
    return {"message": "User deleted successfully"}
