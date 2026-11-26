"""Course rules shared by the course API, the admin API and account deletion."""
import logging
import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_token
from app.config import get_config
from app.models import Course, Token, User
from app.timeutil import utcnow

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
    await db.execute(update(Course).where(Course.ends_at <= cutoff).values(join_code_hash=None))
    await db.commit()
    logger.info("action=purge_course_tokens count=%d", result.rowcount)
    return result.rowcount
