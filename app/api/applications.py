import logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, func, select
from pydantic import BaseModel, Field
from app.database import get_db
from app.models import Application, Token, User
from app.auth import get_current_user
from app.api.tokens import (
    CreateTokenRequest, TokenResponse, TokenWithValueResponse, issue_token, lock_token_owner,
    TOKEN_READ_LIMIT, TOKEN_WRITE_LIMIT,
)
from app.config import get_config
from app.rate_limit import limiter, user_or_ip
from app.timeutil import isoformat_utc
from app.validation import DisplayText, ResourceId

# Revoking, renewing, rotating and deleting an application token go through
# /tokens/{id}: the owner of the application owns its tokens.
router = APIRouter(prefix="/applications", tags=["applications"])
logger = logging.getLogger("token_generator.audit")


class CreateApplicationRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=255), DisplayText]
    description: Annotated[str | None, Field(max_length=1000), DisplayText] = None


class ApplicationResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    created_at: str

    @classmethod
    def of(cls, application: Application) -> "ApplicationResponse":
        return cls(
            id=application.id,
            name=application.name,
            description=application.description,
            created_at=isoformat_utc(application.created_at),
        )


async def owned_application(application_id: str, user: User, db: AsyncSession) -> Application:
    result = await db.execute(
        select(Application).where(Application.id == application_id, Application.user_id == user.id)
    )
    application = result.scalar_one_or_none()
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return application


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
    count = (
        await db.execute(select(func.count()).select_from(Application).where(Application.user_id == user.id))
    ).scalar_one()
    if count >= limit:
        raise HTTPException(
            status_code=400,
            detail=f"Application limit reached ({limit}). Delete applications you no longer need.",
        )
    application = Application(user_id=user.id, name=body.name, description=body.description)
    db.add(application)
    try:
        await db.commit()
        await db.refresh(application)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create application")
    logger.info("user=%s action=create_application application_id=%s", user.id, application.id)
    return ApplicationResponse.of(application)


@router.get("", response_model=list[ApplicationResponse])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_applications(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Application).where(Application.user_id == user.id).order_by(Application.created_at.desc())
    )
    return [ApplicationResponse.of(a) for a in result.scalars().all()]


@router.delete("/{application_id}")
@limiter.limit(TOKEN_WRITE_LIMIT, key_func=user_or_ip)
async def delete_application(
    request: Request,
    application_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = await lock_token_owner(request, user, db)
    application = await owned_application(application_id, user, db)
    try:
        # Explicit, so SQLite without foreign key enforcement agrees.
        result = await db.execute(delete(Token).where(Token.application_id == application.id))
        await db.delete(application)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete application")
    logger.info("user=%s action=delete_application application_id=%s tokens_deleted=%d",
                user.id, application_id, result.rowcount)
    return {"message": "Application and its tokens deleted", "tokens_deleted": result.rowcount}


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
    application = await owned_application(application_id, user, db)
    return await issue_token(body, user, db, application_id=application.id)


@router.get("/{application_id}/tokens", response_model=list[TokenResponse])
@limiter.limit(TOKEN_READ_LIMIT, key_func=user_or_ip)
async def list_application_tokens(
    request: Request,
    application_id: ResourceId,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    application = await owned_application(application_id, user, db)
    result = await db.execute(
        select(Token).where(Token.application_id == application.id).order_by(Token.created_at.desc())
    )
    return [TokenResponse.of(t) for t in result.scalars().all()]
