"""Applications, application tokens, GET validation and /api/v1/user."""
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from app.api import admin as admin_api
from app.api.applications import (
    CreateApplicationRequest, MemberRequest, RoleRequest, add_member, change_role, create_application,
    create_application_token, delete_application, list_application_tokens, list_applications,
    list_members, remove_member,
)
from app.api.tokens import CreateTokenRequest, list_tokens, revoke_token, rotate_token
from app.api.validate import current_user, validate_token, validate_token_get
from app.auth import create_session_token
from app.memberships import claim_invitations
from app.models import Application, ApplicationMember, Token, User


def request(method: str = "POST") -> Request:
    return Request({"type": "http", "method": method, "path": "/", "headers": [],
                    "query_string": b"", "client": ("127.0.0.11", 0)})


async def make_application(db, user, name="Gateway"):
    return await create_application.__wrapped__(
        request(), CreateApplicationRequest(name=name, description="CI jobs"), user, db)


async def make_application_token(db, user, application_id):
    # Locking the account rolls back the session, expiring earlier objects.
    await db.refresh(user)
    return await create_application_token.__wrapped__(
        request(), application_id, CreateTokenRequest(name="deploy"), user, db)


@pytest.mark.asyncio
async def test_personal_token_validation_reports_user(test_db, test_user, test_token):
    for endpoint in (validate_token, validate_token_get):
        response = await endpoint.__wrapped__(request("GET"), test_token["plain_token"], test_db)
        assert response.valid and response.token_type == "personal"
        assert response.user.email == "test@example.com" and response.user.name == "Test User"
        assert response.application is None


@pytest.mark.asyncio
async def test_application_token_validation_reports_application(test_db, test_user):
    application = await make_application(test_db, test_user)
    issued = await make_application_token(test_db, test_user, application.id)
    assert issued.application_id == application.id

    response = await validate_token_get.__wrapped__(request("GET"), issued.token, test_db)
    assert response.token_type == "application"
    assert response.application.id == application.id and response.application.name == "Gateway"
    assert response.user_id == test_user.id

    me = await current_user.__wrapped__(request("GET"), issued.token, test_db)
    assert me.token_type == "application" and me.user.id == test_user.id


@pytest.mark.asyncio
async def test_current_user_requires_live_token(test_db, test_user, test_token):
    me = await current_user.__wrapped__(request("GET"), test_token["plain_token"], test_db)
    assert me.user.id == test_user.id and me.token_type == "personal"
    await revoke_token.__wrapped__(request(), test_token["token"].id, test_user, test_db)
    for bearer in (test_token["plain_token"], None):
        with pytest.raises(HTTPException) as exc:
            await current_user.__wrapped__(request("GET"), bearer, test_db)
        assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_applications_are_private_to_their_owner(test_db, test_user, test_admin):
    application = await make_application(test_db, test_user)
    await test_db.refresh(test_admin)
    assert [a.id for a in await list_applications.__wrapped__(request("GET"), test_admin, test_db)] == []
    for call in (
        lambda: make_application_token(test_db, test_admin, application.id),
        lambda: list_application_tokens.__wrapped__(request("GET"), application.id, test_admin, test_db),
        lambda: delete_application.__wrapped__(request(), application.id, test_admin, test_db),
    ):
        with pytest.raises(HTTPException) as exc:
            await call()
        assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_application_tokens_listed_and_managed_as_owner_tokens(test_db, test_user):
    application = await make_application(test_db, test_user)
    issued = await make_application_token(test_db, test_user, application.id)
    listed = await list_application_tokens.__wrapped__(request("GET"), application.id, test_user, test_db)
    assert [t.id for t in listed] == [issued.id]
    mine = await list_tokens.__wrapped__(request("GET"), test_user, test_db)
    assert mine[0].application_id == application.id

    await revoke_token.__wrapped__(request(), issued.id, test_user, test_db)
    with pytest.raises(HTTPException):
        await validate_token.__wrapped__(request(), issued.token, test_db)


@pytest.mark.asyncio
async def test_deleting_application_deletes_its_tokens(test_db, test_user, test_token):
    personal_id = test_token["token"].id
    application = await make_application(test_db, test_user)
    issued = await make_application_token(test_db, test_user, application.id)
    response = await delete_application.__wrapped__(request(), application.id, test_user, test_db)
    assert response["tokens_deleted"] == 1
    remaining = (await test_db.execute(select(Token.id))).scalars().all()
    assert remaining == [personal_id]
    with pytest.raises(HTTPException):
        await validate_token.__wrapped__(request(), issued.token, test_db)


@pytest.mark.asyncio
async def test_application_limit(test_db, test_user, monkeypatch):
    from app.config import get_config
    monkeypatch.setattr(get_config().tokens, "max_applications_per_user", 1)
    await make_application(test_db, test_user)
    with pytest.raises(HTTPException) as exc:
        await make_application(test_db, test_user, name="Second")
    assert exc.value.status_code == 400


def test_http_routes():
    from app import database
    from app.main import app

    async def seed():
        async with database.async_session_maker() as db:
            user = User(email="apps@example.com", name="Apps", unity_id=f"apps-{uuid.uuid4()}")
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return create_session_token(user)

    with TestClient(app) as client:
        client.cookies.set("access_token", client.portal.call(seed))
        client.cookies.set("csrf_token", "c")
        csrf = {"X-CSRF-Token": "c"}
        application = client.post("/applications", json={"name": "Bot"}, headers=csrf).json()
        issued = client.post(f"/applications/{application['id']}/tokens",
                             json={"name": "bot"}, headers=csrf).json()
        client.cookies.clear()

        bearer = {"Authorization": f"Bearer {issued['token']}"}
        validated = client.get("/api/v1/auth/validate", headers=bearer)
        assert validated.status_code == 200
        assert validated.json()["application"]["name"] == "Bot"
        assert client.post("/api/v1/auth/validate", headers=bearer).status_code == 200
        me = client.get("/api/v1/user", headers=bearer)
        assert me.status_code == 200 and me.json()["user"]["email"] == "apps@example.com"
        assert client.get("/api/v1/user").status_code == 401


def test_pages_show_applications():
    from app import database
    from app.main import app

    async def seed():
        async with database.async_session_maker() as db:
            user = User(email="pages@example.com", name="Pages", unity_id=f"pages-{uuid.uuid4()}",
                        is_admin=True)
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return create_session_token(user)

    with TestClient(app) as client:
        client.cookies.set("access_token", client.portal.call(seed))
        client.cookies.set("csrf_token", "c")
        csrf = {"X-CSRF-Token": "c"}
        application = client.post("/applications", json={"name": "Page Bot"}, headers=csrf).json()
        client.post(f"/applications/{application['id']}/tokens", json={"name": "page-bot"}, headers=csrf)

        dashboard = client.get("/dashboard").text
        assert f'<option value="{application["id"]}">Application: Page Bot</option>' in dashboard
        assert '<span class="app-badge">Page Bot</span>' in dashboard
        assert f'data-action="delete-application" data-id="{application["id"]}"' in dashboard

        assert "Page Bot" in client.get("/admin/tokens").text
        listed = client.get("/api/admin/tokens", params={"page_size": 100}).json()
        assert {"page-bot": "Page Bot"}.items() <= {t["name"]: t["application_name"] for t in listed}.items()


# Shared applications: owners, members, invitations and orphaned applications.


@pytest.fixture
def sent_mail(monkeypatch):
    sent = []
    monkeypatch.setattr("app.memberships.send_mail_later", lambda *message: sent.append(message))
    return sent


async def make_user(db, email, verified=True, admin=False):
    user = User(unity_id=f"subject-{uuid.uuid4()}", email=email, name=email.split("@")[0],
                email_verified=verified, is_admin=admin)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def add(db, owner, application_id, email, role="member"):
    await db.refresh(owner)
    return await add_member.__wrapped__(request(), application_id, MemberRequest(email=email, role=role), owner, db)


async def members_of(db, user, application_id):
    await db.refresh(user)
    return await list_members.__wrapped__(request("GET"), application_id, user, db)


async def status(call) -> int:
    with pytest.raises(HTTPException) as exc:
        await call
    return exc.value.status_code


@pytest.mark.asyncio
async def test_members_manage_tokens_but_not_people(test_db, test_user):
    application = await make_application(test_db, test_user)
    colleague = await make_user(test_db, "colleague@example.com")
    await add(test_db, test_user, application.id, "Colleague@Example.com ")

    issued = await make_application_token(test_db, colleague, application.id)
    await test_db.refresh(colleague)
    rotated = await rotate_token.__wrapped__(request(), issued.id, None, colleague, test_db)
    response = await validate_token.__wrapped__(request(), rotated.token, test_db)
    assert response.user.id == colleague.id and response.application.id == application.id
    await test_db.refresh(test_user)
    assert [t.id for t in await list_tokens.__wrapped__(request("GET"), test_user, test_db)] == [issued.id]
    await test_db.refresh(test_user)
    await revoke_token.__wrapped__(request(), issued.id, test_user, test_db)

    assert await status(add(test_db, colleague, application.id, "x@example.com")) == 403
    assert await status(delete_application.__wrapped__(request(), application.id, colleague, test_db)) == 403
    owner_row = next(m for m in await members_of(test_db, colleague, application.id) if m.role == "owner")
    assert await status(remove_member.__wrapped__(request(), application.id, owner_row.id, colleague, test_db)) == 403


@pytest.mark.asyncio
async def test_adding_does_not_reveal_accounts(test_db, test_user):
    application = await make_application(test_db, test_user)
    await make_user(test_db, "known@example.com")
    known = await add(test_db, test_user, application.id, "known@example.com")
    unknown = await add(test_db, test_user, application.id, "nobody@example.com")
    assert set(known.model_dump()) == set(unknown.model_dump()) == {"id", "email", "role", "you"}
    assert not known.you and not unknown.you
    again = await add(test_db, test_user, application.id, "NOBODY@example.com", role="owner")
    assert again.id == unknown.id and again.role == "owner"


@pytest.mark.asyncio
async def test_invitations_are_claimed_by_verified_email_only(test_db, test_user):
    application = await make_application(test_db, test_user)
    await add(test_db, test_user, application.id, "later@example.com")

    unverified = await make_user(test_db, "later@example.com", verified=False)
    await claim_invitations(test_db, unverified)
    assert await status(members_of(test_db, unverified, application.id)) == 404

    verified = await make_user(test_db, "Later@example.com")
    await claim_invitations(test_db, verified)
    assert any(m.you for m in await members_of(test_db, verified, application.id))


@pytest.mark.asyncio
async def test_last_owner_cannot_step_down_but_can_leave(test_db, test_user, test_admin, sent_mail):
    application = await make_application(test_db, test_user)
    colleague = await make_user(test_db, "colleague@example.com")
    await add(test_db, test_user, application.id, "colleague@example.com")
    issued = await make_application_token(test_db, test_user, application.id)
    me = next(m for m in await members_of(test_db, test_user, application.id) if m.you)

    assert await status(change_role.__wrapped__(
        request(), application.id, me.id, RoleRequest(role="member"), test_user, test_db)) == 400
    await test_db.refresh(test_user)
    left = await remove_member.__wrapped__(request(), application.id, me.id, test_user, test_db)
    assert left["orphaned"] is True
    assert sent_mail and "admin@example.com" in sent_mail[0][0] and "Gateway" in sent_mail[0][2]

    # The token outlives its creator's membership and still names them.
    response = await validate_token.__wrapped__(request(), issued.token, test_db)
    assert response.user.id == test_user.id
    assert await status(members_of(test_db, test_user, application.id)) == 404
    # The remaining member still manages tokens, but nobody manages people.
    await make_application_token(test_db, colleague, application.id)

    await test_db.refresh(test_admin)
    orphaned = await admin_api.list_orphaned_applications.__wrapped__(request("GET"), test_admin, test_db)
    assert [(a.id, a.members, a.tokens) for a in orphaned] == [(application.id, 1, 2)]
    await test_db.refresh(test_admin)
    await admin_api.take_over_application.__wrapped__(request(), application.id, test_admin, test_db)
    await test_db.refresh(test_admin)
    assert await admin_api.list_orphaned_applications.__wrapped__(request("GET"), test_admin, test_db) == []
    await add(test_db, test_admin, application.id, "colleague@example.com", role="owner")
    assert await status(admin_api.take_over_application.__wrapped__(
        request(), application.id, test_admin, test_db)) == 404


@pytest.mark.asyncio
async def test_owner_removing_another_owner_keeps_application(test_db, test_user, sent_mail):
    application = await make_application(test_db, test_user)
    await make_user(test_db, "second@example.com")
    second = await add(test_db, test_user, application.id, "second@example.com", role="owner")
    await test_db.refresh(test_user)
    removed = await remove_member.__wrapped__(request(), application.id, second.id, test_user, test_db)
    assert removed["orphaned"] is False and sent_mail == []


@pytest.mark.asyncio
async def test_deleting_the_last_owner_orphans_and_keeps_tokens(test_db, test_user, test_admin, sent_mail):
    application = await make_application(test_db, test_user)
    issued = await make_application_token(test_db, test_user, application.id)
    await test_db.refresh(test_admin)
    await test_db.refresh(test_admin)
    await admin_api.delete_user.__wrapped__(request("DELETE"), test_user.id, test_admin, test_db)
    test_db.expunge_all()

    response = await validate_token.__wrapped__(request(), issued.token, test_db)
    assert response.valid and response.user is None and response.user_id is None
    assert response.application.id == application.id
    assert (await test_db.get(Application, application.id)).orphaned_at is not None
    assert sent_mail

    deleted = await admin_api.delete_orphaned_application.__wrapped__(
        request("DELETE"), application.id, test_admin, test_db)
    assert deleted["tokens_deleted"] == 1
    assert (await test_db.execute(select(ApplicationMember))).scalars().all() == []


@pytest.mark.asyncio
async def test_application_tokens_have_their_own_limit(test_db, test_user, test_token, monkeypatch):
    from app.config import get_config
    monkeypatch.setattr(get_config().tokens, "max_tokens_per_user", 1)
    application = await make_application(test_db, test_user)
    await make_application_token(test_db, test_user, application.id)
    assert await status(make_application_token(test_db, test_user, application.id)) == 400
