"""Deletion records ("tombstones") that keep deleted accounts from coming back.

OAuth accounts are identified by their subject only: the email an identity
provider asserts may be unverified, so it must never block another person.
Local accounts are identified by their (admin-provided) email.

Only keyed hashes of the subject and email are stored, never the plaintext
identifiers. These retained records are pseudonymous and linkable. The key
is app.token_hash_key and must be preserved until an explicit migration.
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


def identity_reference(*, user: User | None = None, subject: str | None = None) -> str:
    """Short keyed reference to an account's identity for audit lines: it
    matches the deletion record and a later restoration without putting the
    subject or email in the logs."""
    if user is not None:
        subject = user.unity_id
        if subject is None:
            return "local:" + _email_hash(user.email)[:16]
    return "oauth:" + _subject_hash(subject)[:16]


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
    """Creating a local account restores only local identities with that email."""
    await db.execute(
        delete(DeletedUser).where(
            DeletedUser.unity_id_hash.is_(None),
            DeletedUser.email_hash == _email_hash(email),
        )
    )


async def lift_deletions_for_subject(db: AsyncSession, subject: str) -> int:
    result = await db.execute(
        delete(DeletedUser).where(DeletedUser.unity_id_hash == _subject_hash(subject))
    )
    return result.rowcount
