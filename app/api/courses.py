import logging
from datetime import date, datetime, time, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field, StrictBool
from app.database import get_db
from app.models import Course, CourseSeat, Token, User
from app.auth import generate_token, get_current_user, hash_token
from app.api.tokens import TOKEN_READ_LIMIT, TOKEN_WRITE_LIMIT, lock_token_owner
from app.config import get_config
from app.courses import (
    SUSPENDED_BY_TEACHER, active_course_count, close_course, is_active, is_join_code, join_code_hash,
    new_join_code,
)
from app.rate_limit import limiter, RATE_LIMITS, user_or_ip
from app.timeutil import isoformat_utc, utcnow
from app.validation import DisplayText, ResourceId

router = APIRouter(prefix="/courses", tags=["courses"])
logger = logging.getLogger("token_generator.audit")


def require_courses_enabled() -> None:
    if not get_config().courses.enabled:
        raise HTTPException(status_code=404, detail="Courses are not enabled")


class CreateCourseRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=200), DisplayText]
    # First and last day, inclusive, in UTC.
    starts_on: date
    ends_on: date
    max_seats: int = Field(..., ge=1)
    accept_terms: StrictBool


class CourseResponse(BaseModel):
    id: str
    name: str
    starts_at: str
    ends_at: str
    max_seats: int
    seats_claimed: int
    active: bool
    suspended_at: str | None = None
    suspended_reason: str | None = None
    created_at: str

    @classmethod
    def of(cls, course: Course) -> "CourseResponse":
        return cls(
            id=course.id, name=course.name,
            starts_at=isoformat_utc(course.starts_at), ends_at=isoformat_utc(course.ends_at),
            max_seats=course.max_seats, seats_claimed=course.seats_claimed, active=is_active(course),
            suspended_at=isoformat_utc(course.suspended_at), suspended_reason=course.suspended_reason,
            created_at=isoformat_utc(course.created_at),
        )


class JoinLinkResponse(BaseModel):
    join_url: str


class CourseWithLinkResponse(CourseResponse):
    join_url: str


class SeatResponse(BaseModel):
    id: str
    student_name: str
    student_email: str
    claimed_at: str
    token_id: str | None = None
    # active, revoked, expired, or deleted (by the student).
    token_status: str
    last_used_at: str | None = None
    use_count: int = 0


class JoinedCourseResponse(BaseModel):
    token_id: str
    token: str
    expires_at: str
    course: CourseResponse


def join_url(code: str) -> str:
    return f"{get_config().app.api_url.rstrip('/')}/courses/join/{code}"


def course_window(body: CreateCourseRequest) -> tuple[datetime, datetime]:
    settings = get_config().courses
    if body.max_seats > settings.max_seats:
        raise HTTPException(status_code=400, detail=f"A course has at most {settings.max_seats} seats")
    if body.ends_on < body.starts_on:
        raise HTTPException(status_code=400, detail="The course must end on or after its first day")
    days = (body.ends_on - body.starts_on).days + 1
    if days > settings.max_days:
        raise HTTPException(status_code=400, detail=f"A course lasts at most {settings.max_days} days")
    now = utcnow()
    if body.starts_on > now.date() + timedelta(days=settings.max_days_ahead):
        raise HTTPException(
            status_code=400, detail=f"A course starts at most {settings.max_days_ahead} days from today"
        )
    starts_at = datetime.combine(body.starts_on, time.min)
    ends_at = datetime.combine(body.ends_on + timedelta(days=1), time.min)
    if ends_at <= now:
        raise HTTPException(status_code=400, detail="The course must end in the future")
    return starts_at, ends_at


async def teacher_course(course_id: str, user: User, db: AsyncSession, lock: bool = False) -> Course:
    query = select(Course).where(Course.id == course_id, Course.teacher_id == user.id)
    if lock:
        query = query.with_for_update()
    course = (await db.execute(query)).scalar_one_or_none()
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    return course


async def commit(db: AsyncSession, failure: str) -> None:
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail=failure)


@router.post("", response_model=CourseWithLinkResponse, dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def create_course(
    request: Request,
    body: CreateCourseRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CourseWithLinkResponse:
    user = await lock_token_owner(request, user, db)
    if not user.is_teacher:
        raise HTTPException(status_code=403, detail="Only teachers can create courses; ask an administrator")
    if not body.accept_terms:
        raise HTTPException(status_code=400, detail="Accept the course terms to create a course")
    starts_at, ends_at = course_window(body)
    settings = get_config().courses
    if await active_course_count(db, user.id) >= settings.max_active_per_teacher:
        raise HTTPException(
            status_code=400,
            detail=f"You can run {settings.max_active_per_teacher} course(s) at a time; "
                   "close the current one or wait until it ends",
        )
    code, code_hash = new_join_code()
    now = utcnow()
    course = Course(
        name=body.name, teacher_id=user.id, starts_at=starts_at, ends_at=ends_at,
        max_seats=body.max_seats, seats_claimed=0, join_code_hash=code_hash,
        terms_version=settings.terms_version, terms_accepted_at=now,
    )
    db.add(course)
    await commit(db, "Failed to create course")
    logger.info("user=%s action=create_course course_id=%s starts_at=%s ends_at=%s seats=%d terms_version=%s",
                user.id, course.id, isoformat_utc(starts_at), isoformat_utc(ends_at), body.max_seats,
                settings.terms_version)
    return CourseWithLinkResponse(**CourseResponse.of(course).model_dump(), join_url=join_url(code))


@router.get("", response_model=list[CourseResponse], dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_courses(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    courses = (await db.execute(
        select(Course).where(Course.teacher_id == user.id).order_by(Course.starts_at.desc())
    )).scalars().all()
    return [CourseResponse.of(course) for course in courses]


@router.get("/{course_id}", response_model=CourseResponse, dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def get_course(
    request: Request,
    course_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CourseResponse:
    return CourseResponse.of(await teacher_course(course_id, user, db))


def seat_status(token: Token | None, now: datetime) -> str:
    if token is None:
        return "deleted"
    if token.revoked_at is not None:
        return "revoked"
    if token.expires_at is not None and token.expires_at <= now:
        return "expired"
    return "active"


async def course_seats(db: AsyncSession, course: Course) -> list[SeatResponse]:
    seats = (await db.execute(
        select(CourseSeat).options(joinedload(CourseSeat.user))
        .where(CourseSeat.course_id == course.id).order_by(CourseSeat.claimed_at)
    )).scalars().all()
    tokens = {
        token.user_id: token for token in (await db.execute(
            select(Token).where(Token.course_id == course.id)
        )).scalars().all()
    }
    now = utcnow()
    result = []
    for seat in seats:
        token = tokens.get(seat.user_id)
        result.append(SeatResponse(
            id=seat.id, student_name=seat.user.name, student_email=seat.user.email,
            claimed_at=isoformat_utc(seat.claimed_at), token_id=token.id if token else None,
            token_status=seat_status(token, now),
            last_used_at=isoformat_utc(token.last_used_at) if token else None,
            use_count=token.use_count if token else 0,
        ))
    return result


@router.get("/{course_id}/seats", response_model=list[SeatResponse],
            dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_seats(
    request: Request,
    course_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await course_seats(db, await teacher_course(course_id, user, db))


@router.post("/{course_id}/join-link", response_model=JoinLinkResponse,
             dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def regenerate_join_link(
    request: Request,
    course_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JoinLinkResponse:
    """A new link replaces the old one; seats already claimed stay claimed."""
    user = await lock_token_owner(request, user, db)
    course = await teacher_course(course_id, user, db, lock=True)
    if not is_active(course):
        raise HTTPException(status_code=400, detail="The course has ended or was closed")
    code, course.join_code_hash = new_join_code()
    await commit(db, "Failed to create a new join link")
    logger.info("user=%s action=regenerate_course_link course_id=%s", user.id, course.id)
    return JoinLinkResponse(join_url=join_url(code))


@router.post("/{course_id}/close", dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def close_course_endpoint(
    request: Request,
    course_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke every token of the course and disable its join link, for good."""
    user = await lock_token_owner(request, user, db)
    course = await teacher_course(course_id, user, db, lock=True)
    revoked = await close_course(db, course, SUSPENDED_BY_TEACHER)
    await commit(db, "Failed to close course")
    logger.info("user=%s action=close_course course_id=%s reason=%s tokens_revoked=%d",
                user.id, course.id, SUSPENDED_BY_TEACHER, revoked)
    return {"message": "Course closed and all its tokens revoked", "tokens_revoked": revoked}


@router.post("/{course_id}/seats/{seat_id}/revoke", dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def revoke_seat(
    request: Request,
    course_id: ResourceId,
    seat_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke one student's token. The seat stays used: they cannot rejoin."""
    user = await lock_token_owner(request, user, db)
    course = await teacher_course(course_id, user, db, lock=True)
    seat = (await db.execute(
        select(CourseSeat).where(CourseSeat.id == seat_id, CourseSeat.course_id == course.id)
    )).scalar_one_or_none()
    if seat is None:
        raise HTTPException(status_code=404, detail="Seat not found")
    result = await db.execute(
        update(Token)
        .where(Token.course_id == course.id, Token.user_id == seat.user_id, Token.revoked_at.is_(None))
        .values(revoked_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    await commit(db, "Failed to revoke the student's token")
    logger.info("user=%s action=revoke_course_seat course_id=%s seat_id=%s student=%s",
                user.id, course.id, seat.id, seat.user_id)
    return {"message": "The student's token was revoked", "tokens_revoked": result.rowcount}


async def course_for_code(db: AsyncSession, code: str, lock: bool = False) -> Course | None:
    if not is_join_code(code):
        return None
    query = select(Course).where(Course.join_code_hash == join_code_hash(code))
    if lock:
        query = query.with_for_update()
    return (await db.execute(query)).scalar_one_or_none()


def join_problem(course: Course | None) -> str | None:
    """Why the join link cannot be used now, or None."""
    if course is None:
        return "This join link is not valid. Ask your teacher for the current one."
    if not is_active(course) or course.teacher_id is None:
        return "This course has ended or was closed."
    if course.seats_claimed >= course.max_seats:
        return "This course is full. Ask your teacher."
    return None


@router.post("/join/{code}", response_model=JoinedCourseResponse, dependencies=[Depends(require_courses_enabled)])
@limiter.limit(RATE_LIMITS.course_join, key_func=user_or_ip)
async def join_course(
    request: Request,
    code: Annotated[str, Path(max_length=128)],
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JoinedCourseResponse:
    user = await lock_token_owner(request, user, db)
    course = await course_for_code(db, code, lock=True)
    problem = join_problem(course)
    if problem:
        raise HTTPException(status_code=404 if course is None else 410, detail=problem)
    if await db.scalar(select(CourseSeat.id).where(
        CourseSeat.course_id == course.id, CourseSeat.user_id == user.id
    )):
        raise HTTPException(
            status_code=409,
            detail="You already joined this course. Your token is on your dashboard; rotate it there if you lost it.",
        )
    plain_token = generate_token(course=True)
    token = Token(
        user_id=user.id, course_id=course.id, token_hash=hash_token(plain_token),
        name=f"Course: {course.name}", expires_at=course.ends_at,
    )
    course.seats_claimed += 1
    db.add_all([CourseSeat(course_id=course.id, user_id=user.id), token])
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="You already joined this course")
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to join course")
    logger.info("user=%s action=join_course course_id=%s token_id=%s seat=%d/%d",
                user.id, course.id, token.id, course.seats_claimed, course.max_seats)
    return JoinedCourseResponse(
        token_id=token.id, token=plain_token, expires_at=isoformat_utc(token.expires_at),
        course=CourseResponse.of(course),
    )
