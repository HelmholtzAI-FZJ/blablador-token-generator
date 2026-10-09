"""Deletion records ("tombstones") that keep deleted accounts from coming back.

OAuth accounts are identified by their subject only: the email an identity
provider asserts may be unverified, so it must never block another person.
Local accounts are identified by their (admin-provided) email.

Only keyed hashes of the subject and email are stored, never the identifiers
themselves, so a deleted user's personal data does not linger in the
database. The key is app.token_hash_key, which must never change.
"""
import hashlib
import hmac

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_config
from app.models import DeletedUser, User


def _identifier_hash(kind: str, value: str) -> str:
    key = get_config().app.token_hash_key.encode()
    return hmac.new(key, f"tombstone:{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def _subject_hash(unity_id: str) -> str:
    return _identifier_hash("sub", unity_id)


def _email_hash(email: str) -> str:
    # Same normalization as local account emails.
    return _identifier_hash("email", email.strip().lower())


def record_deletion(db: AsyncSession, user: User) -> None:
    db.add(DeletedUser(
        unity_id_hash=_subject_hash(user.unity_id) if user.unity_id else None,
        email_hash=_email_hash(user.email),
    ))


async def is_subject_deleted(db: AsyncSession, unity_id: str) -> bool:
    result = await db.execute(
        select(DeletedUser.id).where(DeletedUser.unity_id_hash == _subject_hash(unity_id)).limit(1)
    )
    return result.first() is not None


async def is_user_deleted(db: AsyncSession, user: User) -> bool:
    if user.unity_id is not None:
        return await is_subject_deleted(db, user.unity_id)
    result = await db.execute(
        select(DeletedUser.id)
        .where(DeletedUser.unity_id_hash.is_(None), DeletedUser.email_hash == _email_hash(user.email))
        .limit(1)
    )
    return result.first() is not None


async def lift_deletions_for_email(db: AsyncSession, email: str) -> None:
    """An admin explicitly re-creating an account lifts deletions for that email."""
    await db.execute(delete(DeletedUser).where(DeletedUser.email_hash == _email_hash(email)))
