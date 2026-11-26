import logging
from datetime import date, datetime, time, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field, StrictBool, field_validator
from app.database import get_db
from app.models import Course, CourseInvitation, CourseSeat, Token, User
from app.auth import generate_token, get_current_user, hash_token
from app.api.applications import email_address
from app.api.tokens import TOKEN_READ_LIMIT, TOKEN_WRITE_LIMIT, lock_token_owner
from app.config import get_config
from app.courses import (
    SUSPENDED_BY_TEACHER, active_course_count, close_course, course_user_for, delete_course, deliver_invitation, invitation_message,
    invitation_text, invite_code_hash, is_active, is_join_code, join_code_hash, new_invite_code, new_join_code,
    open_invitation_count, open_invitations,
)
from app.mailer import run_later
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
    # Known only by a mailed invitation's address, without an account.
    course_user: bool = False
    # "invitation" (mailed link) or "link" (shared link, signed in).
    joined_via: str = "link"


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
            # The newest token wins, after a reissue too.
            select(Token).where(Token.course_id == course.id).order_by(Token.created_at)
        )).scalars().all()
    }
    invited = set((await db.execute(
        select(CourseInvitation.claimed_by_id).where(
            CourseInvitation.course_id == course.id, CourseInvitation.claimed_by_id.isnot(None)
        )
    )).scalars())
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
            course_user=bool(seat.user.is_course_user),
            joined_via="invitation" if seat.user_id in invited else "link",
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


@router.delete("/{course_id}", dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def delete_course_endpoint(
    request: Request,
    course_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a closed or ended course with its tokens, students and
    invitations. A running course must be closed first, so deleting is
    never the way its tokens stop working by surprise."""
    user = await lock_token_owner(request, user, db)
    course = await teacher_course(course_id, user, db, lock=True)
    if is_active(course):
        raise HTTPException(status_code=400, detail="Close the course before deleting it")
    deleted = await delete_course(db, course)
    await commit(db, "Failed to delete course")
    logger.info("user=%s action=delete_course course_id=%s tokens_deleted=%d", user.id, course_id, deleted)
    return {"message": "Course deleted", "tokens_deleted": deleted}


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


async def invitation_for_code(
    db: AsyncSession, code: str, lock: bool = False,
) -> tuple[CourseInvitation | None, Course | None]:
    if not is_join_code(code):
        return None, None
    invitation = (await db.execute(
        select(CourseInvitation).where(CourseInvitation.code_hash == invite_code_hash(code), open_invitations())
    )).scalar_one_or_none()
    if invitation is None:
        return None, None
    query = select(Course).where(Course.id == invitation.course_id)
    if lock:
        query = query.with_for_update()
    return invitation, (await db.execute(query)).scalar_one()


def join_problem(course: Course | None, reserved: int = 0) -> str | None:
    """Why a link cannot be used now, or None. reserved: seats held by
    open invitations, which a shared link must leave free."""
    if course is None:
        return "This link is not valid or was already used. Ask your teacher."
    if not is_active(course) or course.teacher_id is None:
        return "This course has ended or was closed."
    if course.seats_claimed + reserved >= course.max_seats:
        return "This course is full. Ask your teacher."
    return None


async def claim_seat(
    db: AsyncSession, course: Course, user: User, invitation: CourseInvitation | None = None,
) -> JoinedCourseResponse:
    """Give a locked user a seat on a locked course, with its token."""
    if await db.scalar(select(CourseSeat.id).where(
        CourseSeat.course_id == course.id, CourseSeat.user_id == user.id
    )):
        raise HTTPException(
            status_code=409,
            detail="You already joined this course. Your token is on your dashboard; if you lost it, ask your teacher.",
        )
    plain_token = generate_token(course=True)
    token = Token(
        user_id=user.id, course_id=course.id, token_hash=hash_token(plain_token),
        name=f"Course: {course.name}", expires_at=course.ends_at,
    )
    course.seats_claimed += 1
    if invitation is not None:
        invitation.claimed_at = utcnow()
        invitation.claimed_by_id = user.id
        invitation.code_hash = None
    db.add_all([CourseSeat(course_id=course.id, user_id=user.id), token])
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="You already joined this course")
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to join course")
    logger.info("user=%s action=join_course course_id=%s token_id=%s invitation_id=%s seat=%d/%d",
                user.id, course.id, token.id, invitation.id if invitation else "none",
                course.seats_claimed, course.max_seats)
    return JoinedCourseResponse(
        token_id=token.id, token=plain_token, expires_at=isoformat_utc(token.expires_at),
        course=CourseResponse.of(course),
    )


@router.post("/join/{code}", response_model=JoinedCourseResponse, dependencies=[Depends(require_courses_enabled)])
@limiter.limit(RATE_LIMITS.course_join, key_func=user_or_ip)
async def join_course(
    request: Request,
    code: Annotated[str, Path(max_length=128)],
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JoinedCourseResponse:
    """Join through the course's shared link."""
    user = await lock_token_owner(request, user, db)
    course = await course_for_code(db, code, lock=True)
    reserved = await open_invitation_count(db, course.id) if course else 0
    problem = join_problem(course, reserved)
    if problem:
        raise HTTPException(status_code=404 if course is None else 410, detail=problem)
    return await claim_seat(db, course, user)


@router.post("/invite/{code}", response_model=JoinedCourseResponse,
             dependencies=[Depends(require_courses_enabled)])
@limiter.limit(RATE_LIMITS.course_join, key_func=user_or_ip)
async def accept_invitation(
    request: Request,
    code: Annotated[str, Path(max_length=128)],
    db: AsyncSession = Depends(get_db),
) -> JoinedCourseResponse:
    """Show the token of a mailed invitation, once. No sign-in: the token
    belongs to the course user of the invited address (created on first
    use), and moves to the student's account if they later sign in with
    that verified address."""
    invitation, course = await invitation_for_code(db, code, lock=True)
    problem = join_problem(course, -1 if course else 0)
    if problem:
        raise HTTPException(status_code=404 if course is None else 410, detail=problem)
    owner = await course_user_for(db, invitation.email)
    if await db.scalar(select(Token.id).where(
        Token.course_id == course.id, Token.user_id == owner.id, Token.revoked_at.is_(None)
    )):
        raise HTTPException(status_code=409, detail="This address already has a token for this course")
    if not await db.scalar(select(CourseSeat.id).where(
        CourseSeat.course_id == course.id, CourseSeat.user_id == owner.id
    )):
        db.add(CourseSeat(course_id=course.id, user_id=owner.id))
    plain_token = generate_token(course=True)
    token = Token(
        user_id=owner.id, course_id=course.id, token_hash=hash_token(plain_token),
        name=f"Course: {course.name}", expires_at=course.ends_at,
    )
    course.seats_claimed += 1
    invitation.claimed_at = utcnow()
    invitation.claimed_by_id = owner.id
    invitation.code_hash = None
    invitation.link = None
    db.add(token)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Please try again")
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to issue the token")
    logger.info("action=claim_course_invitation course_id=%s invitation_id=%s token_id=%s seat=%d/%d",
                course.id, invitation.id, token.id, course.seats_claimed, course.max_seats)
    return JoinedCourseResponse(
        token_id=token.id, token=plain_token, expires_at=isoformat_utc(token.expires_at),
        course=CourseResponse.of(course),
    )


# Invitations mailed by the service.


def require_mail() -> None:
    if not get_config().smtp.enabled:
        raise HTTPException(status_code=400, detail="Mail is not configured on this service; share the course link instead")


class InvitationRequest(BaseModel):
    emails: list[str] = Field(..., min_length=1, max_length=1000)
    subject: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=20000)

    @field_validator("emails")
    @classmethod
    def valid_emails(cls, value: list[str]) -> list[str]:
        addresses = []
        for entry in value:
            try:
                address = email_address(entry)
            except ValueError:
                raise ValueError(f"Not an email address: {entry[:100]}") from None
            if address not in addresses:
                addresses.append(address)
        return addresses

    @field_validator("subject")
    @classmethod
    def valid_subject(cls, value: str) -> str:
        return invitation_text(value, multiline=False)

    @field_validator("body")
    @classmethod
    def valid_body(cls, value: str) -> str:
        value = invitation_text(value, multiline=True)
        if len(value) > get_config().courses.invitation_max_body_chars:
            raise ValueError(f"must be at most {get_config().courses.invitation_max_body_chars} characters")
        return value


class ResendRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=20000)

    _subject = field_validator("subject")(InvitationRequest.valid_subject.__func__)
    _body = field_validator("body")(InvitationRequest.valid_body.__func__)


class InvitationResponse(BaseModel):
    """What the teacher sees: never the token or the link."""
    id: str
    email: str
    # open (link not used yet), claimed (token shown), cancelled, or
    # deleted (the student's account was deleted afterwards)
    status: str
    sent_at: str
    send_count: int
    delivery_failed: bool
    claimed_at: str | None = None
    # The student's account once they signed in with JSC and this address.
    claimed_by_name: str | None = None
    # active, revoked, expired, or None before the token was shown
    token_status: str | None = None
    last_used_at: str | None = None
    use_count: int = 0

    @classmethod
    def of(cls, invitation: CourseInvitation, token: Token | None = None) -> "InvitationResponse":
        status = "claimed" if invitation.claimed_at else ("cancelled" if invitation.cancelled_at else "open")
        if status == "claimed" and invitation.claimed_by_id is None and token is None:
            status = "deleted"
        return cls(
            id=invitation.id, email=invitation.email, status=status,
            sent_at=isoformat_utc(invitation.sent_at), send_count=invitation.send_count,
            delivery_failed=invitation.delivery_failed_at is not None,
            claimed_at=isoformat_utc(invitation.claimed_at),
            claimed_by_name=invitation.claimed_by.name if invitation.claimed_by else None,
            token_status=seat_status(token, utcnow()) if token else None,
            last_used_at=isoformat_utc(token.last_used_at) if token else None,
            use_count=token.use_count if token else 0,
        )


async def invitation_tokens(db: AsyncSession, invitations: list[CourseInvitation]) -> dict[str, Token]:
    """The current token of each claimed invitation, whether still mailed
    to the address or moved to the student's account."""
    ids = [invitation.id for invitation in invitations]
    by_user = {invitation.claimed_by_id: invitation.id for invitation in invitations if invitation.claimed_by_id}
    if not ids:
        return {}
    course_ids = {invitation.course_id for invitation in invitations}
    tokens = (await db.execute(
        select(Token).where(
            Token.course_id.in_(course_ids),
            (Token.course_invitation_id.in_(ids)) | (Token.user_id.in_(list(by_user) or [""])),
        ).order_by(Token.created_at)
    )).scalars().all()
    result = {}
    for token in tokens:
        key = token.course_invitation_id or by_user.get(token.user_id)
        if key:
            result[key] = token
    return result


class InvitationResult(BaseModel):
    invited: list[InvitationResponse]
    # Addresses with an open or claimed invitation already.
    skipped: list[str]


def invite_url(code: str) -> str:
    return f"{get_config().app.api_url.rstrip('/')}/courses/invite/{code}"


def new_link(invitation: CourseInvitation) -> str:
    """A fresh code for the invitation; returns it. The link is kept only
    for administrators' testing, when configured."""
    code, invitation.code_hash = new_invite_code()
    invitation.link = invite_url(code) if get_config().courses.admin_can_view_invitation_links else None
    return code


def send_invitation(course: Course, teacher: User, invitation: CourseInvitation, code: str,
                    subject: str, body: str) -> None:
    text = invitation_message(course, teacher, body, invite_url(code))
    run_later(deliver_invitation(invitation.id, invitation.email, subject, text, teacher.email))


async def active_teacher_course(request: Request, course_id: str, user: User, db: AsyncSession):
    user = await lock_token_owner(request, user, db)
    if not user.is_teacher:
        raise HTTPException(status_code=403, detail="Only teachers can send invitations")
    course = await teacher_course(course_id, user, db, lock=True)
    if not is_active(course):
        raise HTTPException(status_code=400, detail="The course has ended or was closed")
    return user, course


@router.post("/{course_id}/invitations", response_model=InvitationResult,
             dependencies=[Depends(require_courses_enabled), Depends(require_mail)])
@limiter.limit(RATE_LIMITS.course_invite, key_func=user_or_ip)
async def invite_students(
    request: Request,
    course_id: ResourceId,
    body: InvitationRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvitationResult:
    """Mail each address its own single-use link. Each open invitation
    holds a seat, so a course never has more invitations than seats."""
    user, course = await active_teacher_course(request, course_id, user, db)
    known = set((await db.execute(
        select(CourseInvitation.email).where(
            CourseInvitation.course_id == course.id, CourseInvitation.cancelled_at.is_(None)
        )
    )).scalars())
    new = [address for address in body.emails if address not in known]
    free = course.max_seats - course.seats_claimed - await open_invitation_count(db, course.id)
    if len(new) > free:
        raise HTTPException(
            status_code=400,
            detail=f"Only {max(free, 0)} seat(s) left; invite fewer people or cancel open invitations",
        )
    created = []
    for address in new:
        invitation = CourseInvitation(course_id=course.id, email=address)
        code = new_link(invitation)
        db.add(invitation)
        created.append((invitation, code))
    await commit(db, "Failed to create invitations")
    for invitation, code in created:
        send_invitation(course, user, invitation, code, body.subject, body.body)
    logger.info("user=%s action=invite_course_students course_id=%s invited=%d skipped=%d",
                user.id, course.id, len(created), len(body.emails) - len(created))
    return InvitationResult(
        invited=[InvitationResponse.of(invitation) for invitation, _ in created],
        skipped=[address for address in body.emails if address in known],
    )


@router.get("/{course_id}/invitations", response_model=list[InvitationResponse],
            dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_invitations(
    request: Request,
    course_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    course = await teacher_course(course_id, user, db)
    return await invitation_listing(db, course)


async def invitation_listing(db: AsyncSession, course: Course) -> list[InvitationResponse]:
    invitations = (await db.execute(
        select(CourseInvitation).options(joinedload(CourseInvitation.claimed_by))
        .where(CourseInvitation.course_id == course.id).order_by(CourseInvitation.created_at)
    )).scalars().all()
    tokens = await invitation_tokens(db, invitations)
    return [InvitationResponse.of(invitation, tokens.get(invitation.id)) for invitation in invitations]


async def open_invitation(db: AsyncSession, course: Course, invitation_id: str) -> CourseInvitation:
    invitation = (await db.execute(
        select(CourseInvitation).where(
            CourseInvitation.id == invitation_id, CourseInvitation.course_id == course.id, open_invitations()
        ).with_for_update()
    )).scalar_one_or_none()
    if invitation is None:
        raise HTTPException(status_code=404, detail="No open invitation with this id")
    return invitation


@router.post("/{course_id}/invitations/{invitation_id}/resend", response_model=InvitationResponse,
             dependencies=[Depends(require_courses_enabled), Depends(require_mail)])
@limiter.limit(RATE_LIMITS.course_invite, key_func=user_or_ip)
async def resend_invitation(
    request: Request,
    course_id: ResourceId,
    invitation_id: ResourceId,
    body: ResendRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvitationResponse:
    """Mail a new link; the previous one stops working."""
    user, course = await active_teacher_course(request, course_id, user, db)
    invitation = await open_invitation(db, course, invitation_id)
    limit = get_config().courses.max_invitation_sends
    if limit and invitation.send_count >= limit:
        raise HTTPException(status_code=400, detail=f"An invitation is sent at most {limit} times")
    code = new_link(invitation)
    invitation.send_count += 1
    invitation.sent_at = utcnow()
    invitation.delivery_failed_at = None
    await commit(db, "Failed to resend invitation")
    send_invitation(course, user, invitation, code, body.subject, body.body)
    logger.info("user=%s action=resend_course_invitation course_id=%s invitation_id=%s",
                user.id, course.id, invitation.id)
    return InvitationResponse.of(invitation)


@router.delete("/{course_id}/invitations/{invitation_id}", dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def cancel_invitation(
    request: Request,
    course_id: ResourceId,
    invitation_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Disable an unclaimed invitation; its seat becomes free again."""
    user = await lock_token_owner(request, user, db)
    course = await teacher_course(course_id, user, db, lock=True)
    invitation = await open_invitation(db, course, invitation_id)
    invitation.cancelled_at = utcnow()
    invitation.code_hash = None
    invitation.link = None
    await commit(db, "Failed to cancel invitation")
    logger.info("user=%s action=cancel_course_invitation course_id=%s invitation_id=%s",
                user.id, course.id, invitation.id)
    return {"message": "Invitation cancelled; its seat is free again"}


async def claimed_invitation(db: AsyncSession, course: Course, invitation_id: str) -> CourseInvitation:
    invitation = (await db.execute(
        select(CourseInvitation).where(
            CourseInvitation.id == invitation_id, CourseInvitation.course_id == course.id,
            CourseInvitation.claimed_at.isnot(None),
        ).with_for_update()
    )).scalar_one_or_none()
    if invitation is None:
        raise HTTPException(status_code=404, detail="No used invitation with this id")
    return invitation


async def revoke_invitation_token(db: AsyncSession, course: Course, invitation: CourseInvitation) -> int:
    """Revoke the token an invitation gave, wherever it lives now."""
    owner = Token.course_invitation_id == invitation.id
    if invitation.claimed_by_id:
        owner = owner | (Token.user_id == invitation.claimed_by_id)
    result = await db.execute(
        update(Token).where(Token.course_id == course.id, owner, Token.revoked_at.is_(None))
        .values(revoked_at=utcnow()).execution_options(synchronize_session=False)
    )
    return result.rowcount


@router.post("/{course_id}/invitations/{invitation_id}/revoke", dependencies=[Depends(require_courses_enabled)])
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def revoke_invitation(
    request: Request,
    course_id: ResourceId,
    invitation_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke the token mailed to one student. The seat stays used."""
    user = await lock_token_owner(request, user, db)
    course = await teacher_course(course_id, user, db, lock=True)
    invitation = await claimed_invitation(db, course, invitation_id)
    revoked = await revoke_invitation_token(db, course, invitation)
    await commit(db, "Failed to revoke the token")
    logger.info("user=%s action=revoke_course_invitation_token course_id=%s invitation_id=%s count=%d",
                user.id, course.id, invitation.id, revoked)
    return {"message": "The student's token was revoked", "tokens_revoked": revoked}


@router.post("/{course_id}/invitations/{invitation_id}/reissue", response_model=InvitationResponse,
             dependencies=[Depends(require_courses_enabled), Depends(require_mail)])
@limiter.limit(RATE_LIMITS.course_invite, key_func=user_or_ip)
async def reissue_invitation(
    request: Request,
    course_id: ResourceId,
    invitation_id: ResourceId,
    body: ResendRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvitationResponse:
    """For a student who lost their token: revoke it and mail a new
    one-time link. The seat moves back to the invitation, so none is used
    up; it counts towards max_invitation_sends."""
    user, course = await active_teacher_course(request, course_id, user, db)
    invitation = await claimed_invitation(db, course, invitation_id)
    limit = get_config().courses.max_invitation_sends
    if limit and invitation.send_count >= limit:
        raise HTTPException(status_code=400, detail=f"An invitation is sent at most {limit} times")
    await revoke_invitation_token(db, course, invitation)
    course.seats_claimed -= 1
    invitation.claimed_at = None
    invitation.claimed_by_id = None
    code = new_link(invitation)
    invitation.send_count += 1
    invitation.sent_at = utcnow()
    invitation.delivery_failed_at = None
    await commit(db, "Failed to reissue the token")
    send_invitation(course, user, invitation, code, body.subject, body.body)
    logger.info("user=%s action=reissue_course_invitation course_id=%s invitation_id=%s",
                user.id, course.id, invitation.id)
    return InvitationResponse.of(invitation)
