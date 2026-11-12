import logging
from typing import Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, func, select
from pydantic import BaseModel, Field, field_validator
from app.database import get_db
from app.models import Application, ApplicationMember, ROLE_OWNER, Token, User
from app.auth import get_current_user, normalize_email
from app.api.tokens import (
    CreateTokenRequest, TokenResponse, TokenWithValueResponse, issue_token, lock_token_owner,
    TOKEN_READ_LIMIT, TOKEN_WRITE_LIMIT,
)
from app.config import get_config
from app.memberships import (
    active_owner_count, adopt_if_owned, application_query_for, notify_orphaned, verified_user_for,
)
from app.rate_limit import limiter, user_or_ip
from app.timeutil import isoformat_utc, utcnow
from app.validation import DisplayText, ResourceId, has_unsafe_characters

# Revoking, renewing, rotating and deleting an application token go through
# /tokens/{id}: every member of the application may manage its tokens.
router = APIRouter(prefix="/applications", tags=["applications"])
logger = logging.getLogger("token_generator.audit")

Role = Literal["owner", "member"]


class CreateApplicationRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=255), DisplayText]
    description: Annotated[str | None, Field(max_length=1000), DisplayText] = None


class ApplicationResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    created_at: str
    role: str

    @classmethod
    def of(cls, application: Application, membership: ApplicationMember) -> "ApplicationResponse":
        return cls(
            id=application.id,
            name=application.name,
            description=application.description,
            created_at=isoformat_utc(application.created_at),
            role=membership.role,
        )


class MemberRequest(BaseModel):
    email: Annotated[str, Field(min_length=3, max_length=255)]
    role: Role = "member"

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = normalize_email(value)
        local, at, domain = value.partition("@")
        if not (local and at and domain) or "@" in domain or has_unsafe_characters(value) or " " in value:
            raise ValueError("Enter an email address")
        return value


class RoleRequest(BaseModel):
    role: Role


class MemberResponse(BaseModel):
    """Only what the owners entered: whether an address belongs to an
    account, or has signed in yet, is not disclosed."""
    id: str
    email: str
    role: str
    you: bool

    @classmethod
    def of(cls, membership: ApplicationMember, user: User) -> "MemberResponse":
        return cls(id=membership.id, email=membership.email, role=membership.role,
                   you=membership.user_id == user.id)


async def membership_in(
    application_id: str, user: User, db: AsyncSession, owner: bool = False, lock: bool = False,
) -> tuple[Application, ApplicationMember]:
    query = application_query_for(user).where(Application.id == application_id)
    if lock:
        query = query.with_for_update()
    row = (await db.execute(query)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Application not found")
    application, membership = row
    if owner and membership.role != ROLE_OWNER:
        raise HTTPException(status_code=403, detail="Only the application's owners can do this")
    return application, membership


async def find_member(application: Application, member_id: str, db: AsyncSession) -> ApplicationMember:
    member = (await db.execute(
        select(ApplicationMember).where(
            ApplicationMember.id == member_id, ApplicationMember.application_id == application.id
        )
    )).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    return member


async def commit(db: AsyncSession, failure: str) -> None:
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail=failure)


@router.post("", response_model=ApplicationResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def create_application(
    request: Request,
    body: CreateApplicationRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ApplicationResponse:
    user = await lock_token_owner(request, user, db)
    limit = get_config().tokens.max_applications_per_user
    count = (await db.execute(
        select(func.count()).select_from(ApplicationMember).where(
            ApplicationMember.user_id == user.id, ApplicationMember.role == ROLE_OWNER
        )
    )).scalar_one()
    if count >= limit:
        raise HTTPException(
            status_code=400,
            detail=f"Application limit reached ({limit}). Delete or leave applications you no longer need.",
        )
    application = Application(name=body.name, description=body.description)
    membership = ApplicationMember(
        application=application, user_id=user.id, email=normalize_email(user.email), role=ROLE_OWNER
    )
    db.add_all([application, membership])
    await commit(db, "Failed to create application")
    logger.info("user=%s action=create_application application_id=%s", user.id, application.id)
    return ApplicationResponse.of(application, membership)


@router.get("", response_model=list[ApplicationResponse])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_applications(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(application_query_for(user).order_by(Application.name))).all()
    return [ApplicationResponse.of(application, membership) for application, membership in rows]


async def delete_application_and_tokens(application: Application, db: AsyncSession) -> int:
    # Explicit, so SQLite without foreign key enforcement agrees.
    result = await db.execute(delete(Token).where(Token.application_id == application.id))
    await db.delete(application)
    await commit(db, "Failed to delete application")
    return result.rowcount


@router.delete("/{application_id}")
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def delete_application(
    request: Request,
    application_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = await lock_token_owner(request, user, db)
    application, _ = await membership_in(application_id, user, db, owner=True, lock=True)
    deleted = await delete_application_and_tokens(application, db)
    logger.info("user=%s action=delete_application application_id=%s tokens_deleted=%d",
                user.id, application_id, deleted)
    return {"message": "Application and its tokens deleted", "tokens_deleted": deleted}


@router.post("/{application_id}/tokens", response_model=TokenWithValueResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def create_application_token(
    request: Request,
    application_id: ResourceId,
    body: CreateTokenRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenWithValueResponse:
    user = await lock_token_owner(request, user, db)
    application, _ = await membership_in(application_id, user, db, lock=True)
    return await issue_token(body, user, db, application_id=application.id)


@router.get("/{application_id}/tokens", response_model=list[TokenResponse])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_application_tokens(
    request: Request,
    application_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    application, _ = await membership_in(application_id, user, db)
    result = await db.execute(
        select(Token).where(Token.application_id == application.id).order_by(Token.created_at.desc())
    )
    return [TokenResponse.of(t) for t in result.scalars().all()]


@router.get("/{application_id}/members", response_model=list[MemberResponse])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_members(
    request: Request,
    application_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    application, _ = await membership_in(application_id, user, db)
    members = (await db.execute(
        select(ApplicationMember).where(ApplicationMember.application_id == application.id)
        .order_by(ApplicationMember.role.desc(), ApplicationMember.email)
    )).scalars().all()
    return [MemberResponse.of(m, user) for m in members]


@router.post("/{application_id}/members", response_model=MemberResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def add_member(
    request: Request,
    application_id: ResourceId,
    body: MemberRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MemberResponse:
    """Add someone by email, or change the role of an address already
    added. The response is the same whether or not the address has an
    account; one that has none (yet) joins on signing in."""
    user = await lock_token_owner(request, user, db)
    application, _ = await membership_in(application_id, user, db, owner=True, lock=True)
    member = (await db.execute(
        select(ApplicationMember).where(
            ApplicationMember.application_id == application.id, ApplicationMember.email == body.email
        )
    )).scalar_one_or_none()
    if member is None:
        account = await verified_user_for(db, body.email)
        if account is not None and await db.scalar(select(ApplicationMember.id).where(
            ApplicationMember.application_id == application.id, ApplicationMember.user_id == account.id
        )):
            # Already in under an earlier address; the invitation waits.
            account = None
        member = ApplicationMember(
            application_id=application.id, email=body.email, role=body.role,
            user_id=account.id if account else None,
        )
        db.add(member)
    elif member.role != body.role:
        await check_keeps_an_owner(db, member, body.role)
        member.role = body.role
    await db.flush()
    await adopt_if_owned(db, application)
    await commit(db, "Failed to add member")
    logger.info("user=%s action=add_application_member application_id=%s member_id=%s role=%s",
                user.id, application.id, member.id, member.role)
    return MemberResponse.of(member, user)


async def check_keeps_an_owner(db: AsyncSession, member: ApplicationMember, new_role: str) -> None:
    if (member.role == ROLE_OWNER and new_role != ROLE_OWNER and member.user_id is not None
            and not await active_owner_count(db, member.application_id, excluding=member.id)):
        raise HTTPException(
            status_code=400,
            detail="Make someone else an owner first, or leave the application instead",
        )


@router.patch("/{application_id}/members/{member_id}", response_model=MemberResponse)
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def change_role(
    request: Request,
    application_id: ResourceId,
    member_id: ResourceId,
    body: RoleRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MemberResponse:
    user = await lock_token_owner(request, user, db)
    application, _ = await membership_in(application_id, user, db, owner=True, lock=True)
    member = await find_member(application, member_id, db)
    await check_keeps_an_owner(db, member, body.role)
    member.role = body.role
    await db.flush()
    await adopt_if_owned(db, application)
    await commit(db, "Failed to change role")
    logger.info("user=%s action=change_application_role application_id=%s member_id=%s role=%s",
                user.id, application.id, member.id, member.role)
    return MemberResponse.of(member, user)


@router.delete("/{application_id}/members/{member_id}")
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def remove_member(
    request: Request,
    application_id: ResourceId,
    member_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Owners remove anyone; members may remove themselves (leave). When
    the last owner leaves, the application passes to the admins."""
    user = await lock_token_owner(request, user, db)
    application, membership = await membership_in(application_id, user, db, lock=True)
    leaving = membership.id == member_id
    if not leaving and membership.role != ROLE_OWNER:
        raise HTTPException(status_code=403, detail="Only the application's owners can do this")
    member = membership if leaving else await find_member(application, member_id, db)
    orphaned = (
        member.role == ROLE_OWNER and member.user_id is not None
        and not await active_owner_count(db, application.id, excluding=member.id)
    )
    await db.delete(member)
    if orphaned:
        application.orphaned_at = utcnow()
    await commit(db, "Failed to remove member")
    logger.info("user=%s action=remove_application_member application_id=%s member_id=%s left=%s",
                user.id, application.id, member_id, leaving)
    if orphaned:
        await notify_orphaned(db, [application])
    return {"message": "You left the application" if leaving else "Member removed", "orphaned": orphaned}
