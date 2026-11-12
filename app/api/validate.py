from datetime import datetime, timezone, timedelta
from typing import Callable, TypeVar
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import or_, select, update
from sqlalchemy.orm import joinedload
from pydantic import BaseModel
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


class UserInfo(BaseModel):
    id: str
    email: str
    name: str


class ApplicationInfo(BaseModel):
    id: str
    name: str


class ValidateResponse(BaseModel):
    valid: bool
    user_id: str | None = None
    expires_at: str | None = None
    error: str | None = None
    token_type: str | None = None
    user: UserInfo | None = None
    application: ApplicationInfo | None = None


class CurrentUserResponse(BaseModel):
    # None for an application token whose creator's account was deleted.
    user: UserInfo | None = None
    token_type: str
    application: ApplicationInfo | None = None


MAX_TOKEN_LENGTH = 256
T = TypeVar("T")

async def extract_bearer_token(authorization: str | None = Header(None)) -> str | None:
    # The authentication scheme is case-insensitive (RFC 7235).
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    return token


def invalid_token(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


async def authenticate_api_token(
    bearer_token: str | None, db: AsyncSession, respond: Callable[[Token], T],
) -> T:
    """respond() applied to the live token for a bearer value, with its
    owner and application loaded; raises 401 otherwise. The response is
    built before recording the token's use, which may roll back and
    expire it."""
    if not bearer_token:
        raise invalid_token("No token provided. Use Bearer token.")

    token_hash = hash_token(bearer_token)

    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user), joinedload(Token.application), joinedload(Token.created_by))
        .where(
            Token.token_hash == token_hash,
            Token.revoked_at.is_(None)
        )
    )
    token = result.scalar_one_or_none()

    if token is None or (token.user is None and token.application is None):
        raise invalid_token("Token not found or revoked")

    # Check if the account was deleted after this token was created
    if token.user is not None and await is_user_deleted(db, token.user):
        _audit.warning(
            "user=%s action=revoked_token_used_by_deleted_account token_id=%s",
            token.user_id,
            token.id,
        )
        raise invalid_token("Token invalid: account has been deleted")

    now = datetime.now(timezone.utc)
    if token.expires_at:
        expires = token.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            raise invalid_token("Token has expired")

    response = respond(token)
    await record_token_use(token, token_hash, now, db)
    return response


async def record_token_use(token: Token, token_hash: str, now: datetime, db: AsyncSession) -> None:
    token_id = token.id
    now_naive = now.replace(tzinfo=None)
    cutoff = now_naive - timedelta(seconds=get_config().tokens.last_used_update_seconds)
    last_used_at = token.last_used_at
    if last_used_at is not None and last_used_at.tzinfo is not None:
        last_used_at = last_used_at.astimezone(timezone.utc).replace(tzinfo=None)
    if last_used_at is not None and last_used_at > cutoff:
        return
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


def user_info(user: User | None) -> UserInfo | None:
    if user is None:
        return None
    return UserInfo(id=user.id, email=user.email, name=user.name)


def application_info(token: Token) -> ApplicationInfo | None:
    if token.application is None:
        return None
    return ApplicationInfo(id=token.application.id, name=token.application.name)


def token_type(token: Token) -> str:
    return "application" if token.application_id else "personal"


@router.post("/validate", response_model=ValidateResponse)
@limiter.limit(RATE_LIMITS.token_validation, exempt_when=is_token_validation_exempt)
async def validate_token(
    request: Request,
    bearer_token: str = Depends(extract_bearer_token),
    db: AsyncSession = Depends(get_db)
):
    return await authenticate_api_token(bearer_token, db, validation_response)


def validation_response(token: Token) -> ValidateResponse:
    return ValidateResponse(
        valid=True,
        user_id=token.reported_user.id if token.reported_user else None,
        expires_at=isoformat_utc(token.expires_at),
        token_type=token_type(token),
        user=user_info(token.reported_user),
        application=application_info(token),
    )


# For gateways that can only issue GET subrequests (e.g. nginx auth_request).
@router.get("/validate", response_model=ValidateResponse)
@limiter.limit(RATE_LIMITS.token_validation, exempt_when=is_token_validation_exempt)
async def validate_token_get(
    request: Request,
    bearer_token: str = Depends(extract_bearer_token),
    db: AsyncSession = Depends(get_db)
):
    return await authenticate_api_token(bearer_token, db, validation_response)


user_router = APIRouter(prefix="/api/v1", tags=["auth"])


@user_router.get("/user", response_model=CurrentUserResponse)
@limiter.limit(RATE_LIMITS.token_validation, exempt_when=is_token_validation_exempt)
async def current_user(
    request: Request,
    bearer_token: str = Depends(extract_bearer_token),
    db: AsyncSession = Depends(get_db)
):
    return await authenticate_api_token(bearer_token, db, current_user_response)


def current_user_response(token: Token) -> CurrentUserResponse:
    return CurrentUserResponse(
        user=user_info(token.reported_user),
        token_type=token_type(token),
        application=application_info(token),
    )
