"""Applications, application tokens, GET validation and /api/v1/user."""
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from app.api.applications import (
    CreateApplicationRequest, create_application, create_application_token, delete_application,
    list_application_tokens, list_applications,
)
from app.api.tokens import CreateTokenRequest, list_tokens, revoke_token
from app.api.validate import current_user, validate_token, validate_token_get
from app.auth import create_session_token
from app.models import Token, User


def request(method: str = "POST") -> Request:
    return Request({"type": "http", "method": method, "path": "/", "headers": [],
                    "query_string": b"", "client": ("127.0.0.11", 0)})


async def make_application(db, user, name="Gateway"):
    return await create_application.__wrapped__(
        request(), CreateApplicationRequest(name=name, description="CI jobs"), user, db)


async def make_application_token(db, user, application_id):
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
