"""Deletion records ("tombstones") that keep deleted accounts from coming back.

OAuth accounts are identified by their subject only: the email an identity
provider asserts may be unverified, so it must never block another person.
Local accounts are identified by their (admin-provided) email.
"""
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DeletedUser, User


def record_deletion(db: AsyncSession, user: User) -> None:
    db.add(DeletedUser(unity_id=user.unity_id, email=user.email))


async def is_subject_deleted(db: AsyncSession, unity_id: str) -> bool:
    result = await db.execute(
        select(DeletedUser.id).where(DeletedUser.unity_id == unity_id).limit(1)
    )
    return result.first() is not None


async def is_user_deleted(db: AsyncSession, user: User) -> bool:
    if user.unity_id is not None:
        return await is_subject_deleted(db, user.unity_id)
    result = await db.execute(
        select(DeletedUser.id)
        .where(DeletedUser.unity_id.is_(None), DeletedUser.email == user.email)
        .limit(1)
    )
    return result.first() is not None


async def lift_deletions_for_email(db: AsyncSession, email: str) -> None:
    """An admin explicitly re-creating an account lifts deletions for that email."""
    await db.execute(
        delete(DeletedUser).where(func.lower(DeletedUser.email) == email.lower())
    )
