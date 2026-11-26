"""Course rules shared by the course API, the admin API and account deletion."""
import logging
import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_token
from app.config import get_config
from app.models import Course, CourseInvitation, Token, User
from app.timeutil import utcnow
from app.validation import is_unsafe_character

logger = logging.getLogger("token_generator.audit")

SUSPENDED_BY_TEACHER = "closed_by_teacher"
SUSPENDED_BY_ADMIN = "suspended_by_admin"
TEACHER_ROLE_REMOVED = "teacher_role_removed"
TEACHER_DELETED = "teacher_deleted"


def new_join_code() -> tuple[str, str]:
    """A join code and the hash stored for it."""
    code = secrets.token_hex(get_config().courses.join_code_bytes)
    return code, join_code_hash(code)


def join_code_hash(code: str) -> str:
    return hash_token(f"course-join:{code}")


def new_invite_code() -> tuple[str, str]:
    """A single-use invitation code and the hash stored for it."""
    code = secrets.token_hex(get_config().courses.join_code_bytes)
    return code, invite_code_hash(code)


def invite_code_hash(code: str) -> str:
    return hash_token(f"course-invite:{code}")


def open_invitations():
    return CourseInvitation.claimed_at.is_(None) & CourseInvitation.cancelled_at.is_(None)


async def open_invitation_count(db: AsyncSession, course_id: str) -> int:
    return (await db.execute(
        select(func.count()).select_from(CourseInvitation)
        .where(CourseInvitation.course_id == course_id, open_invitations())
    )).scalar_one()


def is_join_code(code: str) -> bool:
    return len(code) == 2 * get_config().courses.join_code_bytes and all(c in "0123456789abcdef" for c in code)


def is_active(course: Course, now: datetime | None = None) -> bool:
    return course.suspended_at is None and course.ends_at > (now or utcnow())


def active_condition(now: datetime):
    return (Course.suspended_at.is_(None)) & (Course.ends_at > now)


async def active_course_count(db: AsyncSession, teacher_id: str) -> int:
    return (await db.execute(
        select(func.count()).select_from(Course)
        .where(Course.teacher_id == teacher_id, active_condition(utcnow()))
    )).scalar_one()


async def close_course(db: AsyncSession, course: Course, reason: str) -> int:
    """Suspend a course and revoke its tokens; the caller commits. Returns
    the number of tokens revoked."""
    now = utcnow()
    if course.suspended_at is None:
        course.suspended_at = now
        course.suspended_reason = reason
    course.join_code_hash = None
    await db.execute(
        update(CourseInvitation)
        .where(CourseInvitation.course_id == course.id, open_invitations())
        .values(cancelled_at=now, code_hash=None, link=None)
        .execution_options(synchronize_session=False)
    )
    result = await db.execute(
        update(Token)
        .where(Token.course_id == course.id, Token.revoked_at.is_(None))
        .values(revoked_at=now)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount


async def close_courses_of(db: AsyncSession, teacher: User, reason: str) -> list[str]:
    """Close every active course a teacher runs; the caller commits."""
    courses = (await db.execute(
        select(Course).where(Course.teacher_id == teacher.id, active_condition(utcnow())).with_for_update()
    )).scalars().all()
    for course in courses:
        revoked = await close_course(db, course, reason)
        logger.info("action=close_course course_id=%s teacher=%s reason=%s tokens_revoked=%d",
                    course.id, teacher.id, reason, revoked)
    return [course.id for course in courses]


async def purge_ended_courses(db: AsyncSession) -> int:
    """Delete the tokens of courses that ended more than retention_days
    ago. Courses and seats stay as a record."""
    cutoff = utcnow() - timedelta(days=get_config().courses.retention_days)
    ended = select(Course.id).where(Course.ends_at <= cutoff)
    result = await db.execute(delete(Token).where(Token.course_id.in_(ended)))
    # Invited addresses are personal data with no further use.
    await db.execute(delete(CourseInvitation).where(CourseInvitation.course_id.in_(ended)))
    await db.execute(update(Course).where(Course.ends_at <= cutoff).values(join_code_hash=None))
    await db.commit()
    logger.info("action=purge_course_tokens count=%d", result.rowcount)
    return result.rowcount


def invitation_text(value: str, *, multiline: bool) -> str:
    """Teacher-written mail text: no control or invisible characters, and
    for the subject no line breaks (which would forge headers)."""
    value = value.replace("\r\n", "\n").strip()
    allowed = {"\n", "\t"} if multiline else set()
    if any(character not in allowed and is_unsafe_character(character) for character in value):
        raise ValueError("must not contain control or invisible formatting characters")
    return value


def invitation_message(course: Course, teacher: User, body: str, link: str) -> str:
    """The teacher's text, then what the service always adds."""
    config = get_config()
    footer = config.courses.invitation_footer.format(
        course=course.name,
        start=course.starts_at.date().isoformat(),
        end=(course.ends_at - timedelta(days=1)).date().isoformat(),
        link=link,
        app_name=config.app.name,
        teacher_name=teacher.name,
        teacher_email=teacher.email,
    )
    return f"{body}\n\n{footer}"


async def deliver_invitation(invitation_id: str, email: str, subject: str, text: str, reply_to: str) -> None:
    """Send one invitation; record a failure so the teacher sees it."""
    from app import database
    from app.mailer import send_mail

    if await send_mail([email], subject, text, reply_to=reply_to):
        return
    async with database.async_session_maker() as db:
        await db.execute(
            update(CourseInvitation).where(CourseInvitation.id == invitation_id)
            .values(delivery_failed_at=utcnow())
        )
        await db.commit()
    logger.warning("action=course_invitation_undelivered invitation_id=%s", invitation_id)


async def delete_course(db: AsyncSession, course: Course) -> int:
    """Delete a course with its tokens, seats and invitations; the caller
    commits. Returns the number of tokens deleted."""
    from app.models import CourseSeat

    # Explicit, so SQLite without foreign key enforcement agrees.
    result = await db.execute(delete(Token).where(Token.course_id == course.id))
    await db.execute(delete(CourseInvitation).where(CourseInvitation.course_id == course.id))
    await db.execute(delete(CourseSeat).where(CourseSeat.course_id == course.id))
    await db.delete(course)
    return result.rowcount


async def course_user_for(db: AsyncSession, email: str) -> User:
    """The account a mailed course token goes to: a password account with
    this address if there is one, else this address's course user, created
    on first use. Never an OAuth account: their email may be unverified."""
    from app.auth import normalize_email

    address = normalize_email(email)
    existing = (await db.execute(
        select(User).where(func.lower(User.email) == address, User.unity_id.is_(None))
    )).scalars().first()
    if existing is not None:
        return existing
    user = User(email=address, name=address, is_course_user=True, email_verified=False)
    db.add(user)
    await db.flush()
    logger.info("action=create_course_user user_id=%s", user.id)
    return user


async def claim_course_tokens(db: AsyncSession, user: User) -> int:
    """Move what a course user of the user's verified email holds (seats,
    tokens, invitations) to their account, so the course tokens become a
    known person's. Only a verified address may claim: an unverified one
    could be anyone's. A course the user is already in keeps the token they
    have. The course user is removed once it holds nothing. A failure only
    delays this to the next sign-in."""
    from app.auth import normalize_email
    from app.models import CourseSeat

    if not user.email_verified or user.is_course_user or not get_config().courses.enabled:
        return 0
    try:
        address = normalize_email(user.email)
        moved = 0
        course_users = (await db.execute(
            select(User).where(User.is_course_user.is_(True), func.lower(User.email) == address,
                               User.id != user.id).with_for_update()
        )).scalars().all()
        for course_user in course_users:
            seats = (await db.execute(
                select(CourseSeat).where(CourseSeat.user_id == course_user.id).with_for_update()
            )).scalars().all()
            for seat in seats:
                if await db.scalar(select(CourseSeat.id).where(
                    CourseSeat.course_id == seat.course_id, CourseSeat.user_id == user.id
                )):
                    continue
                seat.user_id = user.id
                await db.execute(
                    update(Token).where(Token.user_id == course_user.id, Token.course_id == seat.course_id)
                    .values(user_id=user.id).execution_options(synchronize_session=False)
                )
                await db.execute(
                    update(CourseInvitation)
                    .where(CourseInvitation.claimed_by_id == course_user.id,
                           CourseInvitation.course_id == seat.course_id)
                    .values(claimed_by_id=user.id).execution_options(synchronize_session=False)
                )
                moved += 1
            await db.flush()
            left = await db.scalar(select(CourseSeat.id).where(CourseSeat.user_id == course_user.id))
            if left is None and await db.scalar(select(Token.id).where(Token.user_id == course_user.id)) is None:
                await db.delete(course_user)
                logger.info("user=%s action=remove_course_user course_user=%s", user.id, course_user.id)
        # Tokens issued before course users existed belong to the invitation.
        rows = (await db.execute(
            select(Token, CourseInvitation)
            .join(CourseInvitation, Token.course_invitation_id == CourseInvitation.id)
            .where(CourseInvitation.email == address, Token.revoked_at.is_(None))
            .with_for_update()
        )).all()
        for token, invitation in rows:
            if await db.scalar(select(CourseSeat.id).where(
                CourseSeat.course_id == token.course_id, CourseSeat.user_id == user.id
            )):
                continue
            db.add(CourseSeat(course_id=token.course_id, user_id=user.id))
            token.course_invitation_id = None
            token.user_id = user.id
            invitation.claimed_by_id = user.id
            moved += 1
        if moved or course_users:
            await db.commit()
        if moved:
            logger.info("user=%s action=claim_course_tokens count=%d", user.id, moved)
        return moved
    except Exception as exc:
        await db.rollback()
        logger.error("user=%s action=claim_course_tokens_failed error_type=%s", user.id, type(exc).__name__)
        return 0
