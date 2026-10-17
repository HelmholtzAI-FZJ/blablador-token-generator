import asyncio
import base64
import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Callable, TypeVar
from weakref import WeakKeyDictionary

import bcrypt
import httpx
import jwt
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.config import get_config
from app.cookies import SESSION_COOKIE
from app.database import get_db
from app.models import User, RevokedJWT
from app.timeutil import utcnow
from app.tombstones import is_subject_deleted, is_user_deleted
from app.validation import has_unsafe_characters, without_unsafe_characters

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
config = get_config()
_audit = logging.getLogger("token_generator.audit")
_password_operations: WeakKeyDictionary[asyncio.AbstractEventLoop, int] = WeakKeyDictionary()
_PasswordResult = TypeVar("_PasswordResult")
# bcrypt only uses the first 72 bytes; older bcrypt releases truncated
# silently, so verify against the same prefix to keep existing hashes valid.
BCRYPT_MAX_BYTES = 72


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode()[:BCRYPT_MAX_BYTES], hashed_password.encode()
        )
    except ValueError:
        return False


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


async def _password_operation(
    function: Callable[..., _PasswordResult], *args: object
) -> _PasswordResult:
    loop = asyncio.get_running_loop()
    active = _password_operations.get(loop, 0)
    if active >= config.local.max_concurrent_password_operations:
        raise HTTPException(status_code=503, detail="Authentication temporarily unavailable")
    _password_operations[loop] = active + 1
    task = asyncio.create_task(asyncio.to_thread(function, *args))

    def completed(done: asyncio.Task) -> None:
        _password_operations[loop] -= 1
        if not done.cancelled():
            done.exception()

    task.add_done_callback(completed)
    return await asyncio.shield(task)


async def hash_password_async(password: str) -> str:
    return await _password_operation(hash_password, password)


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    return await _password_operation(verify_password, plain_password, hashed_password)


MIN_PASSWORD_LENGTH = 15

# Precomputed bcrypt hash used so that password verification takes the same
# amount of time for unknown users (anti user-enumeration timing attack).
_DUMMY_HASH = "$2b$12$2dBl/Zl3eBe5sjpf7Wv7Z.IlSzv0e0Zc6m10oMkoh4K3qPGftIFI2"


def validate_password_strength(password: str) -> None:
    """Require long passwords and reject configured common passwords."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters long",
        )
    if password.casefold() in {entry.casefold() for entry in config.local.blocked_passwords}:
        raise HTTPException(
            status_code=400,
            detail="Choose a password that is not commonly used",
        )
    try:
        password_bytes = password.encode()
    except UnicodeError:
        raise HTTPException(status_code=400, detail="Password contains invalid characters") from None
    if len(password_bytes) > BCRYPT_MAX_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Password must not exceed {BCRYPT_MAX_BYTES} bytes",
        )


def hash_token(token: str) -> str:
    """HMAC-SHA256 of the token keyed with token_hash_key.

    A keyed hash prevents offline cracking of token hashes if the database
    is compromised, since the key is not in the DB.
    """
    import hmac
    return hmac.new(
        config.app.token_hash_key.encode(),
        token.encode(),
        hashlib.sha256,
    ).hexdigest()


def new_pkce_verifier() -> str:
    """PKCE code verifier (RFC 7636): 86 URL-safe characters."""
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier: str) -> str:
    """S256 code challenge for a PKCE verifier."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def generate_token() -> str:
    prefix = config.tokens.token_prefix
    return f"{prefix}-{secrets.token_hex(config.tokens.token_length_bytes)}"


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(hours=config.app.jwt_expiration_hours)
    # Add a unique JWT ID so individual session tokens can be
    # revoked (blacklisted) without rotating the signing key.
    to_encode.update({"exp": expire, "jti": secrets.token_hex(16)})
    return jwt.encode(to_encode, config.app.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, config.app.secret_key, algorithms=["HS256"],
            options={"require": ["exp", "sub", "jti", "sep"]},
        )
        if (
            not isinstance(payload["sub"], str) or not 1 <= len(payload["sub"]) <= 255
            or not isinstance(payload["jti"], str) or not 1 <= len(payload["jti"]) <= 64
            or type(payload["sep"]) is not int or payload["sep"] < 0
        ):
            raise ValueError("Invalid session claims")
        return payload
    except (jwt.PyJWTError, ValueError, TypeError, OverflowError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def revoke_jwt(payload: dict, db: AsyncSession) -> None:
    """Add a JWT's jti to the revocation blacklist.

    Entries for sessions that have expired anyway are purged on the way, so
    the table only ever holds still-valid revoked sessions.
    """
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="Invalid session")
    exp_ts = payload.get("exp", 0)
    exp = datetime.fromtimestamp(exp_ts, UTC).replace(tzinfo=None)
    try:
        existing = await db.execute(select(RevokedJWT).where(RevokedJWT.jti == jti))
        if existing.scalar_one_or_none() is None:
            await db.execute(delete(RevokedJWT).where(RevokedJWT.expires_at < utcnow()))
            db.add(RevokedJWT(
                jti=jti,
                user_id=payload.get("sub", ""),
                expires_at=exp,
            ))
            await db.commit()
            _audit.info("user=%s action=session_revoked", payload["sub"])
    except IntegrityError as exc:
        try:
            await db.rollback()
            if await is_jwt_revoked(payload, db):
                return
        except Exception as rollback_error:
            _audit.error("action=session_rollback_failed error=%s", type(rollback_error).__name__)
        _audit.error("action=session_revocation_failed error=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Unable to complete session logout") from None
    except Exception as exc:
        try:
            await db.rollback()
        except Exception as rollback_error:
            _audit.error("action=session_rollback_failed error=%s", type(rollback_error).__name__)
        _audit.error("action=session_revocation_failed error=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Unable to complete session logout") from None


async def is_jwt_revoked(payload: dict, db: AsyncSession) -> bool:
    """Check if a JWT has been revoked."""
    jti = payload.get("jti")
    if not jti:
        return False
    result = await db.execute(select(RevokedJWT).where(RevokedJWT.jti == jti))
    return result.scalar_one_or_none() is not None


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=302, detail="Not authenticated")

    try:
        payload = decode_access_token(token)
    except HTTPException:
        # An expired or malformed session is handled like a missing one:
        # pages go back to sign-in, API calls get 401.
        raise HTTPException(status_code=302, detail="Session expired") from None
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=302, detail="Invalid token payload")

    # Check JWT revocation blacklist
    if await is_jwt_revoked(payload, db):
        raise HTTPException(status_code=302, detail="Token has been revoked")

    result = await db.execute(
        select(User).where(User.id == user_id).execution_options(populate_existing=True)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=302, detail="User not found")

    if await is_user_deleted(db, user):
        raise HTTPException(status_code=403, detail="Account has been disabled")

    if payload.get("sep") != user.session_epoch:
        raise HTTPException(status_code=302, detail="Session expired")

    return user


def create_session_token(user: User) -> str:
    lifetime = config.app.admin_jwt_expiration_hours if user.is_admin else config.app.jwt_expiration_hours
    return create_access_token(
        data={"sub": user.id, "sep": user.session_epoch},
        expires_delta=timedelta(hours=lifetime),
    )


async def invalidate_sessions(user: User, db: AsyncSession) -> None:
    """End every existing session of the user (takes effect on commit)."""
    result = await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(session_epoch=User.session_epoch + 1)
        .returning(User.session_epoch)
        .execution_options(synchronize_session=False)
    )
    epoch = result.scalar_one_or_none()
    if epoch is None:
        raise HTTPException(status_code=404, detail="User not found")
    set_committed_value(user, "session_epoch", epoch)


async def get_current_admin(
    user: User = Depends(get_current_user)
) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def get_unity_userinfo(code: str, code_verifier: str) -> dict:
    operation = "token_exchange"
    try:
        async with asyncio.timeout(config.oauth.request_timeout_seconds), httpx.AsyncClient(
            timeout=httpx.Timeout(config.oauth.request_timeout_seconds),
            follow_redirects=False,
            headers={"Accept-Encoding": "identity"},
        ) as client:
            auth_header = base64.b64encode(
                f"{config.oauth.client_id}:{config.oauth.client_secret}".encode()
            ).decode()
            token_data = await _provider_json(
                client, "POST", config.oauth.token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": config.oauth.redirect_uri,
                    "code_verifier": code_verifier,
                },
                headers={
                    "Authorization": f"Basic {auth_header}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            token = _OAuthTokenResponse.model_validate(token_data)
            operation = "userinfo"
            userinfo = await _provider_json(
                client, "GET", config.oauth.userinfo_url,
                headers={"Authorization": f"Bearer {token.access_token}"},
            )
            return _OAuthUserInfo.model_validate(userinfo).model_dump()
    except HTTPException as exc:
        _audit.warning("action=oauth_authentication_failed operation=%s status=%d", operation, exc.status_code)
        raise
    except (httpx.HTTPError, ValueError, ValidationError, TimeoutError) as exc:
        _audit.error("action=oauth_provider_failed operation=%s error=%s", operation, type(exc).__name__)
        raise HTTPException(status_code=503, detail="Authentication provider temporarily unavailable") from None


class _OAuthTokenResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    access_token: str = Field(min_length=1, max_length=8192)
    token_type: str = "Bearer"

    @field_validator("access_token")
    @classmethod
    def valid_access_token(cls, value: str) -> str:
        if not value.isascii() or any(not 33 <= ord(character) <= 126 for character in value):
            raise ValueError("Invalid provider access token")
        return value

    @field_validator("token_type")
    @classmethod
    def bearer_token_type(cls, value: str) -> str:
        if value.lower() != "bearer":
            raise ValueError("Unsupported provider token type")
        return value


class _OAuthUserInfo(BaseModel):
    model_config = ConfigDict(strict=True)

    sub: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=3, max_length=255)
    name: str | None = Field(None, max_length=4096)
    preferred_username: str | None = Field(None, max_length=4096)
    email_verified: bool = False

    @field_validator("sub")
    @classmethod
    def valid_subject(cls, value: str) -> str:
        if not value.isascii() or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Invalid provider subject")
        return value

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        if value.count("@") != 1 or has_unsafe_characters(value) or any(character.isspace() for character in value):
            raise ValueError("Invalid provider email")
        local, domain = value.split("@")
        if not local or not domain:
            raise ValueError("Invalid provider email")
        return value


async def _provider_json(
    client: httpx.AsyncClient, method: str, url: str, **kwargs: object
) -> dict:
    async with client.stream(method, url, **kwargs) as response:
        if response.status_code != 200:
            if response.status_code in (400, 401, 403):
                raise HTTPException(status_code=400, detail="OAuth authentication failed")
            raise ValueError("Unexpected provider response")
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise ValueError("Unsupported provider content encoding")
        limit = config.oauth.max_response_bytes
        content_length = response.headers.get("content-length")
        if content_length is not None and int(content_length) > limit:
            raise ValueError("Provider response too large")
        content = bytearray()
        async for chunk in response.aiter_bytes():
            if len(content) + len(chunk) > limit:
                raise ValueError("Provider response too large")
            content.extend(chunk)
        result = json.loads(content)
        if not isinstance(result, dict):
            raise ValueError("Invalid provider response")
        return result


PROFILE_FIELD_MAX = 255


def normalize_email(email: str) -> str:
    return email.strip().lower()


async def get_or_create_user(userinfo: dict, db: AsyncSession) -> User:
    """Find or create the account for an OAuth identity.

    The subject ("sub") is the only identifier. The asserted email is
    profile data: it never links to, blocks or takes over another account.
    Configured administrative grants apply only when creating an account.
    """
    try:
        profile = _OAuthUserInfo.model_validate(userinfo)
    except ValidationError:
        _audit.error("action=oauth_provider_failed operation=profile_validation error=ValidationError")
        raise HTTPException(status_code=503, detail="Authentication provider temporarily unavailable") from None
    unity_id = profile.sub
    email = profile.email
    # Names are free text the person may edit at the provider; drop control
    # and invisible formatting characters rather than refusing the sign-in.
    name = without_unsafe_characters(profile.name or profile.preferred_username or "").strip()
    name = (name or email)[:PROFILE_FIELD_MAX]
    email_trusted = (
        profile.email_verified or config.oauth.trust_provider_emails
    )

    # A deleted account must not be resurrected by logging in again until
    # an admin re-creates it.
    if await is_subject_deleted(db, unity_id):
        raise HTTPException(
            status_code=403,
            detail="Account has been disabled. Contact an administrator.",
        )

    result = await db.execute(select(User).where(User.unity_id == unity_id))
    user = result.scalar_one_or_none()

    if user is None:
        admin_emails = {normalize_email(e) for e in config.admin.admin_emails}
        in_admin_config = unity_id in config.admin.admin_subjects or (
            email_trusted and normalize_email(email) in admin_emails
        )
        user = User(unity_id=unity_id, email=email, name=name, is_admin=in_admin_config)
        db.add(user)
        try:
            await db.commit()
            await db.refresh(user)
            _audit.info("user=%s action=oauth_account_created is_admin=%s", user.id, user.is_admin)
        except Exception as exc:
            await db.rollback()
            _audit.error("action=oauth_account_creation_failed error=%s", type(exc).__name__)
            # A concurrent first login of the same subject may have won.
            result = await db.execute(select(User).where(User.unity_id == unity_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise HTTPException(status_code=500, detail="Failed to create user")
        if await is_subject_deleted(db, unity_id):
            _audit.warning("user=%s action=oauth_disabled_account_observed cleanup_required=True", user.id)
            raise HTTPException(status_code=403, detail="Account has been disabled. Contact an administrator.")
        return user

    changed = False
    # Keep profile attributes up to date with the identity provider.
    if user.name != name:
        user.name = name
        changed = True
    if email_trusted and user.email != email:
        user.email = email
        changed = True
    if changed:
        try:
            await db.commit()
        except Exception as exc:
            await db.rollback()
            _audit.error("action=profile_update_failed error=%s", type(exc).__name__)
        # Rollback expires the instance; reload it so callers can use it.
        await db.refresh(user)
    if await is_subject_deleted(db, unity_id):
        _audit.warning("user=%s action=oauth_disabled_account_observed cleanup_required=True", user.id)
        raise HTTPException(status_code=403, detail="Account has been disabled. Contact an administrator.")
    return user


async def authenticate_local_user(email: str, password: str, db: AsyncSession) -> User | None:
    user = None
    # No local account can have such an email (and PostgreSQL refuses NUL).
    if not has_unsafe_characters(email):
        result = await db.execute(
            select(User).where(
                User.email == normalize_email(email),
                User.unity_id.is_(None),
                User.password_hash.isnot(None),
            )
        )
        user = result.scalar_one_or_none()
    stored_hash = user.password_hash if (user and user.password_hash) else _DUMMY_HASH
    # Always run bcrypt so response timing doesn't reveal whether the
    # email exists (prevents user enumeration via timing side-channel).
    if not await verify_password_async(password, stored_hash):
        return None
    return user
