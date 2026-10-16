import logging
import unicodedata
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select, update
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field, field_validator
from app.database import get_db, lock_user_for_update
from app.models import User, Token
from app.tombstones import (
    is_user_deleted, lift_deletions_for_email, lift_deletions_for_subject, record_deletion,
)
from app.auth import (
    get_current_admin, get_current_user, hash_password_async, invalidate_sessions, normalize_email,
    validate_password_strength,
)
from app.rate_limit import limiter, RATE_LIMITS, user_or_ip
from app.cookies import SESSION_COOKIE
from app.timeutil import isoformat_utc, utcnow

logger = logging.getLogger("token_generator.audit")
router = APIRouter(prefix="/api/admin", tags=["admin"])

ADMIN_RATE_LIMIT = RATE_LIMITS.admin
MAX_PAGE_SIZE = 100
MAX_PAGE = 1_000_000


async def lock_admin_actor(db: AsyncSession, admin_id: str, request: Request) -> User:
    admin = await lock_user_for_update(db, admin_id, admin_membership=True)
    if request.cookies.get(SESSION_COOKIE):
        await get_current_user(request, db)
    if admin is None or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return admin


async def is_last_admin(db: AsyncSession, user_id: str) -> bool:
    """Call under the admin membership lock when deciding a mutation."""
    target = await db.execute(select(User).where(User.id == user_id))
    target_user = target.scalar_one_or_none()
    if target_user is None or not target_user.is_admin or await is_user_deleted(db, target_user):
        return False
    result = await db.execute(
        select(User)
        .where(User.is_admin.is_(True), User.id != user_id)
        .order_by(User.id)
        .limit(MAX_PAGE_SIZE + 1)
    )
    candidates = result.scalars().all()
    for candidate in candidates[:MAX_PAGE_SIZE]:
        if not await is_user_deleted(db, candidate):
            return False
    if len(candidates) > MAX_PAGE_SIZE:
        raise HTTPException(
            status_code=503,
            detail="Review disabled administrator accounts before changing administrator access",
        )
    return True


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

    @field_validator("email")
    @classmethod
    def validate_local_email(cls, value: str) -> str:
        if any(character.isspace() or unicodedata.category(character).startswith("C")
               for character in value):
            raise ValueError("Email must not contain whitespace or control characters")
        email = normalize_email(value)
        if email.count("@") != 1 or not all(email.split("@")):
            raise ValueError("Invalid email address")
        return email


class UpdateUserRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    password: str | None = Field(None, min_length=8, max_length=128)
    is_admin: bool | None = None


class RestoreOAuthRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=255)


@router.get("/tokens", response_model=list[AdminTokenResponse])
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
async def list_all_tokens(
    request: Request,
    page: int = Query(1, ge=1, le=MAX_PAGE),
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
            created_at=isoformat_utc(t.created_at),
            expires_at=isoformat_utc(t.expires_at),
            last_used_at=isoformat_utc(t.last_used_at),
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
    admin = await lock_admin_actor(db, admin.id, request)
    try:
        result = await db.execute(delete(Token).where(Token.revoked_at.isnot(None)))
        count = result.rowcount
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
    admin = await lock_admin_actor(db, admin.id, request)
    result = await db.execute(select(Token).where(Token.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    token.revoked_at = utcnow()
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
    admin = await lock_admin_actor(db, admin.id, request)
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
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 20,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * page_size
    result = await db.execute(
        select(User)
        .order_by(User.created_at.desc(), User.id.desc())
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
            created_at=isoformat_utc(u.created_at),
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
    if not email:
        raise HTTPException(status_code=400, detail="Email must not be empty")
    validate_password_strength(body.password)
    password_hash = await hash_password_async(body.password)
    admin = await lock_admin_actor(db, admin.id, request)
    # Local accounts log in by email, so it must be unique among them.
    result = await db.execute(select(User).where(User.email == email, User.unity_id.is_(None)))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Explicit admin re-creation lifts deletion records for this email.
    await lift_deletions_for_email(db, email)

    user = User(
        email=email,
        name=body.name,
        password_hash=password_hash,
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
        created_at=isoformat_utc(user.created_at),
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
    password_hash = None
    if body.password is not None:
        validate_password_strength(body.password)
        password_hash = await hash_password_async(body.password)
    admin = await lock_admin_actor(db, admin.id, request)
    result = await db.execute(
        select(User).where(User.id == user_id).with_for_update()
        .execution_options(populate_existing=True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.name is not None:
        user.name = body.name
    if body.password is not None:
        if user.unity_id is not None:
            raise HTTPException(
                status_code=400,
                detail="OAuth accounts sign in through the identity provider and cannot have a password",
            )
        user.password_hash = password_hash
    if body.is_admin is False and await is_last_admin(db, user_id):
        raise HTTPException(
            status_code=400,
            detail="Cannot demote the last remaining admin",
        )
    role_changed = body.is_admin is not None and body.is_admin != user.is_admin
    if role_changed:
        user.is_admin = body.is_admin
    if body.password is not None or role_changed:
        await invalidate_sessions(user, db)

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
        created_at=isoformat_utc(user.created_at),
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
    admin = await lock_admin_actor(db, admin.id, request)
    result = await db.execute(
        select(User).where(User.id == user_id).with_for_update()
        .execution_options(populate_existing=True)
    )
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


@router.post("/users/{user_id}/revoke-credentials")
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
async def revoke_user_credentials(
    request: Request,
    user_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    admin = await lock_admin_actor(db, admin.id, request)
    result = await db.execute(
        select(User).where(User.id == user_id).with_for_update()
        .execution_options(populate_existing=True)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        result = await db.execute(
            update(Token)
            .where(Token.user_id == user_id, Token.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        await invalidate_sessions(user, db)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to revoke credentials")
    logger.info(
        "admin=%s action=revoke_user_credentials user_id=%s count=%d",
        admin.id, user_id, result.rowcount,
    )
    return {"message": "All API tokens and sessions revoked", "tokens_revoked": result.rowcount}


@router.post("/users/restore-oauth")
@limiter.limit(ADMIN_RATE_LIMIT, key_func=user_or_ip)
async def restore_oauth_identity(
    request: Request,
    body: RestoreOAuthRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    admin = await lock_admin_actor(db, admin.id, request)
    try:
        count = await lift_deletions_for_subject(db, body.subject)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to restore OAuth identity")
    logger.info("admin=%s action=restore_oauth_identity count=%d", admin.id, count)
    return {"message": "OAuth identity may sign in again", "deletions_lifted": count}
