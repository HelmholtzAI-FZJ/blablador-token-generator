from datetime import datetime
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field
from app.database import get_db
from app.models import User, Token
from app.tombstones import lift_deletions_for_email, record_deletion
from app.auth import (
    get_current_admin, hash_password, invalidate_sessions, normalize_email,
    validate_password_strength,
)
from app.rate_limit import limiter, RATE_LIMITS, user_or_ip

logger = logging.getLogger("token_generator.audit")
router = APIRouter(prefix="/api/admin", tags=["admin"])

ADMIN_RATE_LIMIT = RATE_LIMITS.admin
MAX_PAGE_SIZE = 100


async def is_last_admin(db: AsyncSession, user_id: str) -> bool:
    """Return True if the user with user_id is an admin and the only one."""
    result = await db.execute(select(func.count()).where(User.is_admin.is_(True)))
    admin_count = result.scalar_one()
    if admin_count > 1:
        return False
    target = await db.execute(select(User).where(User.id == user_id))
    target_user = target.scalar_one_or_none()
    return bool(target_user and target_user.is_admin)


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
    has_password: bool = False


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
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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


@router.delete("/tokens/revoked")
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete revoked tokens")
    logger.info(
        "admin=%s action=delete_revoked_tokens count=%d",
        admin.id,
        count,
    )
    return {"message": f"Deleted {count} revoked tokens"}


@router.delete("/tokens/{token_id}")
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to revoke token")
    logger.info(
        "admin=%s action=revoke_token token_id=%s user_id=%s",
        admin.id,
        token.id,
        token.user_id,
    )
    return {"message": "Token revoked successfully"}


@router.delete("/tokens/{token_id}/permanent")
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete token")
    logger.info(
        "admin=%s action=delete_token token_id=%s user_id=%s",
        admin.id,
        token.id,
        token.user_id,
    )
    return {"message": "Token deleted successfully"}


@router.get("/users", response_model=list[UserResponse])
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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
            has_password=u.password_hash is not None,
        )
        for u in users
    ]


@router.post("/users", response_model=UserResponse)
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
async def create_user(
    request: Request,
    body: CreateUserRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    email = normalize_email(body.email)
    # Local accounts log in by email, so it must be unique among them.
    result = await db.execute(select(User).where(User.email == email, User.unity_id.is_(None)))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User with this email already exists")

    validate_password_strength(body.password)

    # Explicit admin re-creation lifts deletion records for this email.
    await lift_deletions_for_email(db, email)

    user = User(
        email=email,
        name=body.name,
        password_hash=hash_password(body.password),
        is_admin=body.is_admin,
        unity_id=None,
    )
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")
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
        has_password=user.password_hash is not None,
    )


@router.patch("/users/{user_id}", response_model=UserResponse)
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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
        invalidate_sessions(user)
    if body.is_admin is False and await is_last_admin(db, user_id):
        raise HTTPException(
            status_code=400,
            detail="Cannot demote the last remaining admin",
        )
    if body.is_admin is not None and body.is_admin != user.is_admin:
        user.is_admin = body.is_admin
        invalidate_sessions(user)

    try:
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update user")

    logger.info(
        "admin=%s action=update_user user_id=%s is_admin=%s password_changed=%s name_changed=%s",
        admin.id,
        user.id,
        user.is_admin,
        body.password is not None,
        body.name is not None,
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat(),
        unity_id=user.unity_id,
        has_password=user.password_hash is not None,
    )


@router.delete("/users/{user_id}")
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
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

    if user.is_admin and await is_last_admin(db, user_id):
        raise HTTPException(
            status_code=400,
            detail="Cannot delete the last remaining admin",
        )

    # Tombstone so the account isn't resurrected by logging in again
    record_deletion(db, user)
    await db.delete(user)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete user")
    logger.info("admin=%s action=delete_user user_id=%s", admin.id, user.id)
    return {"message": "User deleted successfully"}
