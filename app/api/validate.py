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
from app.models import Course, Token, User
from app.tombstones import is_user_deleted
from app.auth import COURSE_TOKEN_MARKER, hash_token
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


class CourseInfo(BaseModel):
    id: str
    name: str
    starts_at: str
    ends_at: str


class ValidateResponse(BaseModel):
    valid: bool
    user_id: str | None = None
    # Also reported at the top level, so the shape matches what other
    # identity providers return to the gateways.
    email: str | None = None
    expires_at: str | None = None
    error: str | None = None
    token_type: str | None = None
    user: UserInfo | None = None
    application: ApplicationInfo | None = None
    course: CourseInfo | None = None


class CurrentUserResponse(BaseModel):
    # None for an application token whose creator's account was deleted.
    user: UserInfo | None = None
    token_type: str
    application: ApplicationInfo | None = None
    course: CourseInfo | None = None


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


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def token_shape(token: str) -> str | None:
    """"course" or "personal" when generate_token can have produced this
    value: the configured prefix, "course-" for a course token, then whole
    random bytes, so an even and non-zero number of hex characters. None for
    a value that cannot be a token of this service, however it was
    truncated, copied or transcribed."""
    prefix = f"{get_config().tokens.token_prefix}-"
    if not token.startswith(prefix):
        return None
    body = token[len(prefix):]
    shape = "personal"
    if body.startswith(f"{COURSE_TOKEN_MARKER}-"):
        body = body[len(COURSE_TOKEN_MARKER) + 1:]
        shape = "course"
    if (
        2 <= len(body) <= MAX_TOKEN_LENGTH
        and len(body) % 2 == 0
        and all(character in _HEX_DIGITS for character in body)
    ):
        return shape
    return None


def is_possible_token(token: str) -> bool:
    return token_shape(token) is not None


def course_problem(course: Course, now: datetime) -> str | None:
    """Why a course's tokens do not work now, or None."""
    if course.suspended_at is not None:
        return "Token revoked: the course was closed"
    if now < as_utc(course.starts_at):
        return "Token not valid yet: the course has not started"
    if now >= as_utc(course.ends_at):
        return "Token has expired: the course has ended"
    return None


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


async def authenticate_api_token(
    bearer_token: str | None, db: AsyncSession, respond: Callable[[Token], T],
) -> T:
    """respond() applied to the live token for a bearer value, with its
    owner and application loaded; raises 401 otherwise. The response is
    built before recording the token's use, which may roll back and
    expire it."""
    if not bearer_token:
        raise invalid_token("No token provided. Use Bearer token.")

    shape = token_shape(bearer_token)
    if shape is None:
        raise invalid_token(
            f"Token is malformed: expected '{get_config().tokens.token_prefix}-' "
            "followed by an even number of hexadecimal characters"
        )

    token_hash = hash_token(bearer_token)

    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user), joinedload(Token.application), joinedload(Token.created_by),
                 joinedload(Token.course))
        .where(
            Token.token_hash == token_hash,
            Token.revoked_at.is_(None)
        )
    )
    token = result.scalar_one_or_none()

    if token is None or (token.user is None and token.application is None):
        raise invalid_token("Token not found or revoked")
    # A value's shape must agree with its record, so a course token cannot
    # pass as a personal one (and the gateway's course limits be skipped).
    if (shape == "course") != (token.course_id is not None):
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
    if token.course is not None:
        problem = course_problem(token.course, now)
        if problem:
            raise invalid_token(problem)

    response = respond(token)
    await record_token_use(token, token_hash, now, db)
    return response


async def record_token_use(token: Token, token_hash: str, now: datetime, db: AsyncSession) -> None:
    token_id = token.id
    now_naive = now.replace(tzinfo=None)
    cutoff = now_naive - timedelta(seconds=get_config().tokens.last_used_update_seconds)
    if token.course_id is not None:
        await count_course_token_use(token_id, token_hash, now_naive, db)
        return
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


async def count_course_token_use(token_id: str, token_hash: str, now: datetime, db: AsyncSession) -> None:
    """Every use of a course token is counted, so a teacher can spot one
    that is shared or leaked."""
    try:
        await db.execute(
            update(Token)
            .where(Token.id == token_id, Token.token_hash == token_hash, Token.revoked_at.is_(None))
            .values(last_used_at=now, use_count=Token.use_count + 1)
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


def course_info(token: Token) -> CourseInfo | None:
    if token.course is None:
        return None
    return CourseInfo(
        id=token.course.id, name=token.course.name,
        starts_at=isoformat_utc(token.course.starts_at), ends_at=isoformat_utc(token.course.ends_at),
    )


def token_type(token: Token) -> str:
    if token.course_id:
        return "course"
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
    reported = token.reported_user
    return ValidateResponse(
        valid=True,
        user_id=reported.id if reported else None,
        # An application token authenticates an application, not a person, so
        # the flat field stays empty; the nested user still names the owner.
        email=reported.email if reported and token.application_id is None else None,
        expires_at=isoformat_utc(token.expires_at),
        token_type=token_type(token),
        user=user_info(token.reported_user),
        application=application_info(token),
        course=course_info(token),
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
        course=course_info(token),
    )
