"""Who may manage an application, invitations, and applications left
without an owner."""
import logging

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import normalize_email
from app.config import get_config
from app.mailer import send_mail_later
from app.models import Application, ApplicationMember, ROLE_OWNER, User
from app.timeutil import utcnow

logger = logging.getLogger("token_generator.audit")


async def active_owner_count(db: AsyncSession, application_id: str, excluding: str | None = None) -> int:
    """Owners who have signed in; invitations do not count."""
    query = select(func.count()).select_from(ApplicationMember).where(
        ApplicationMember.application_id == application_id,
        ApplicationMember.role == ROLE_OWNER,
        ApplicationMember.user_id.isnot(None),
    )
    if excluding is not None:
        query = query.where(ApplicationMember.id != excluding)
    return (await db.execute(query)).scalar_one()


async def adopt_if_owned(db: AsyncSession, application: Application) -> None:
    if application.orphaned_at is not None and await active_owner_count(db, application.id):
        application.orphaned_at = None


async def verified_user_for(db: AsyncSession, email: str) -> User | None:
    """The one account that verified this email, if exactly one did."""
    users = (await db.execute(
        select(User).where(func.lower(User.email) == email, User.email_verified.is_(True)).limit(2)
    )).scalars().all()
    return users[0] if len(users) == 1 else None


async def claim_invitations(db: AsyncSession, user: User) -> None:
    """Link invitations to the user's verified email to their account. A
    failure only delays that to the next sign-in."""
    if not user.email_verified:
        return
    try:
        await _claim(db, user)
    except Exception as exc:
        await db.rollback()
        logger.error("user=%s action=claim_invitations_failed error_type=%s", user.id, type(exc).__name__)


async def _claim(db: AsyncSession, user: User) -> None:
    joined = select(ApplicationMember.application_id).where(ApplicationMember.user_id == user.id)
    claimed = (await db.execute(
        update(ApplicationMember)
        .where(
            ApplicationMember.email == normalize_email(user.email),
            ApplicationMember.user_id.is_(None),
            ApplicationMember.application_id.not_in(joined),
        )
        .values(user_id=user.id)
        .returning(ApplicationMember.application_id, ApplicationMember.role)
    )).all()
    if not claimed:
        return
    owned = [application_id for application_id, role in claimed if role == ROLE_OWNER]
    if owned:
        await db.execute(
            update(Application).where(Application.id.in_(owned)).values(orphaned_at=None)
        )
    await db.commit()
    logger.info("user=%s action=claim_invitations applications=%d", user.id, len(claimed))


async def orphan_applications_left_by(db: AsyncSession, user: User) -> list[Application]:
    """Mark orphaned the applications the user is the last owner of, ahead
    of their account being deleted (in the same transaction)."""
    owned = (await db.execute(
        select(ApplicationMember).where(
            ApplicationMember.user_id == user.id, ApplicationMember.role == ROLE_OWNER
        )
    )).scalars().all()
    orphaned = []
    for membership in owned:
        if not await active_owner_count(db, membership.application_id, excluding=membership.id):
            application = await db.get(Application, membership.application_id)
            application.orphaned_at = utcnow()
            orphaned.append(application)
    return orphaned


async def admin_recipients(db: AsyncSession) -> list[str]:
    emails = (await db.execute(select(User.email).where(User.is_admin.is_(True)))).scalars().all()
    configured = get_config().admin.admin_emails
    return sorted({normalize_email(e) for e in [*emails, *configured] if e})


async def notify_orphaned(db: AsyncSession, applications: list[Application]) -> None:
    """Tell the admins (after the change is committed)."""
    if not applications:
        return
    for application in applications:
        logger.warning("action=application_orphaned application_id=%s", application.id)
    names = "\n".join(f"- {a.name} ({a.id})" for a in applications)
    send_mail_later(
        await admin_recipients(db),
        f"{get_config().app.name}: applications without an owner",
        "The last owner left these applications. Their tokens keep working; "
        "take them over or delete them in the admin panel.\n\n" + names + "\n",
    )


def application_query_for(user: User):
    """Applications the user belongs to, with their membership."""
    return (
        select(Application, ApplicationMember)
        .join(ApplicationMember, ApplicationMember.application_id == Application.id)
        .where(ApplicationMember.user_id == user.id)
    )


def orphaned_query():
    return select(Application).where(Application.orphaned_at.isnot(None)).order_by(Application.orphaned_at)
