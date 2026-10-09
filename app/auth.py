import base64
import hashlib
import secrets
import bcrypt
import httpx
from datetime import datetime, timedelta
import jwt
from fastapi import HTTPException, status, Depends, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select
from app.config import get_config
from app.cookies import SESSION_COOKIE
from app.database import get_db
from app.models import User, Token, RevokedJWT
from app.tombstones import is_subject_deleted

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
config = get_config()
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


MIN_PASSWORD_LENGTH = 8

# Precomputed bcrypt hash used so that password verification takes the same
# amount of time for unknown users (anti user-enumeration timing attack).
_DUMMY_HASH = "$2b$12$2dBl/Zl3eBe5sjpf7Wv7Z.IlSzv0e0Zc6m10oMkoh4K3qPGftIFI2"


def validate_password_strength(password: str) -> None:
    """Enforce basic password complexity.

    Raises:
        HTTPException: 400 if the password is too short, missing
        uppercase, lowercase, or digit requirements.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters long",
        )
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one uppercase letter",
        )
    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one lowercase letter",
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one digit",
        )
    if len(password.encode()) > BCRYPT_MAX_BYTES:
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
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=config.app.jwt_expiration_hours)
    # Add a unique JWT ID so individual session tokens can be
    # revoked (blacklisted) without rotating the signing key.
    to_encode.update({"exp": expire, "jti": secrets.token_hex(16)})
    return jwt.encode(to_encode, config.app.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token, config.app.secret_key, algorithms=["HS256"],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
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
        return
    exp_ts = payload.get("exp", 0)
    exp = datetime.utcfromtimestamp(exp_ts)
    existing = await db.execute(select(RevokedJWT).where(RevokedJWT.jti == jti))
    if existing.scalar_one_or_none() is None:
        try:
            await db.execute(delete(RevokedJWT).where(RevokedJWT.expires_at < datetime.utcnow()))
            db.add(RevokedJWT(
                jti=jti,
                user_id=payload.get("sub", ""),
                expires_at=exp,
            ))
            await db.commit()
        except Exception:
            await db.rollback()


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

    payload = decode_access_token(token)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=302, detail="Invalid token payload")

    # Check JWT revocation blacklist
    if await is_jwt_revoked(payload, db):
        raise HTTPException(status_code=302, detail="Token has been revoked")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=302, detail="User not found")

    if payload.get("sep") != user.session_epoch:
        raise HTTPException(status_code=302, detail="Session expired")

    return user


def create_session_token(user: User) -> str:
    return create_access_token(data={"sub": user.id, "sep": user.session_epoch})


def invalidate_sessions(user: User) -> None:
    """End every existing session of the user (takes effect on commit)."""
    user.session_epoch = (user.session_epoch or 0) + 1


async def get_current_admin(
    user: User = Depends(get_current_user)
) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def get_unity_userinfo(code: str, code_verifier: str) -> dict:
    async with httpx.AsyncClient() as client:
        auth_header = base64.b64encode(
            f"{config.oauth.client_id}:{config.oauth.client_secret}".encode()
        ).decode()

        response = await client.post(
            config.oauth.token_url,
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

        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to exchange authorization code",
            )

        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=400,
                detail="OAuth provider did not return an access token",
            )

        userinfo_response = await client.get(
            config.oauth.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to retrieve user information",
            )

        userinfo = userinfo_response.json()
        # Validate required fields before persisting
        if not userinfo.get("sub"):
            raise HTTPException(
                status_code=400,
                detail="OAuth provider did not return a subject identifier",
            )
        if not userinfo.get("email"):
            raise HTTPException(
                status_code=400,
                detail="OAuth provider did not return an email address",
            )

        return userinfo


PROFILE_FIELD_MAX = 255


def normalize_email(email: str) -> str:
    return email.strip().lower()


async def get_or_create_user(userinfo: dict, db: AsyncSession) -> User:
    """Find or create the account for an OAuth identity.

    The subject ("sub") is the only identifier. The asserted email is
    profile data: it never links to, blocks or takes over another account.
    """
    unity_id = str(userinfo["sub"])
    email = str(userinfo.get("email") or "")[:PROFILE_FIELD_MAX]
    name = str(userinfo.get("name") or userinfo.get("preferred_username") or email)[:PROFILE_FIELD_MAX]
    email_trusted = (
        userinfo.get("email_verified") is True or config.oauth.trust_provider_emails
    )

    # A deleted account must not be resurrected by logging in again until
    # an admin re-creates it.
    if await is_subject_deleted(db, unity_id):
        raise HTTPException(
            status_code=403,
            detail="Account has been disabled. Contact an administrator.",
        )

    # Promote admin status from config on every login so that additions take
    # effect for existing users. Never demote here: revocation is an explicit
    # admin action that must not be silently undone at login.
    admin_emails = {normalize_email(e) for e in config.admin.admin_emails}
    in_admin_config = unity_id in config.admin.admin_subjects or (
        email_trusted and normalize_email(email) in admin_emails
    )

    result = await db.execute(select(User).where(User.unity_id == unity_id))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(unity_id=unity_id, email=email, name=name, is_admin=in_admin_config)
        db.add(user)
        try:
            await db.commit()
            await db.refresh(user)
        except Exception:
            await db.rollback()
            # A concurrent first login of the same subject may have won.
            result = await db.execute(select(User).where(User.unity_id == unity_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise HTTPException(status_code=500, detail="Failed to create user")
        return user

    changed = False
    if in_admin_config and not user.is_admin:
        user.is_admin = True
        changed = True
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
        except Exception:
            await db.rollback()
        # Rollback expires the instance; reload it so callers can use it.
        await db.refresh(user)
    return user


async def authenticate_local_user(email: str, password: str, db: AsyncSession) -> User | None:
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
    if not verify_password(password, stored_hash):
        return None
    return user
