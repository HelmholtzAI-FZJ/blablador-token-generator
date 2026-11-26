"""Admin user search: GET /api/admin/users?q=..."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.auth import create_session_token
from app.models import User


async def seed(users: list[dict]) -> str:
    from app import database
    async with database.async_session_maker() as db:
        admin = User(email=f"admin-{uuid.uuid4().hex[:6]}@example.org", name="Admin",
                     unity_id=f"admin-{uuid.uuid4()}", is_admin=True)
        db.add(admin)
        db.add_all(User(**fields) for fields in users)
        await db.commit()
        await db.refresh(admin)
        return create_session_token(admin)


@pytest.fixture
def admin_client():
    from app.main import app
    tag = uuid.uuid4().hex[:8]
    users = [
        {"email": f"ada.{tag}@uni.example", "name": "Ada Lovelace", "unity_id": f"sub-ada-{tag}"},
        {"email": f"alan.{tag}@uni.example", "name": "Alan Turing", "unity_id": f"sub-alan-{tag}"},
        {"email": f"grace.{tag}@navy.example", "name": f"Grace 100%_Hopper {tag}", "unity_id": None},
    ]
    with TestClient(app, client=("203.0.113.77", 50000)) as client:
        client.cookies.set("access_token", client.portal.call(lambda: seed(users)))
        yield client, tag


def search(client, q, **params):
    response = client.get("/api/admin/users", params={"q": q, "page_size": 100, **params})
    assert response.status_code == 200, response.text
    return response


def emails(response):
    return sorted(user["email"] for user in response.json())


def test_matches_part_of_email_ignoring_case(admin_client):
    client, tag = admin_client
    assert emails(search(client, f"ADA.{tag}")) == [f"ada.{tag}@uni.example"]
    assert emails(search(client, f"{tag}@uni")) == [f"ada.{tag}@uni.example", f"alan.{tag}@uni.example"]


def test_matches_name_and_oauth_subject(admin_client):
    client, tag = admin_client
    assert len(search(client, "lovelace").json()) >= 1
    assert emails(search(client, f"sub-alan-{tag}")) == [f"alan.{tag}@uni.example"]


def test_wildcards_are_literal(admin_client):
    client, tag = admin_client
    assert emails(search(client, f"100%_hopper {tag}")) == [f"grace.{tag}@navy.example"]
    # As LIKE patterns these would match Ada and Alan.
    assert search(client, f"a%.{tag}").json() == []
    assert search(client, f"a_a.{tag}").json() == []


def test_blank_query_lists_everyone(admin_client):
    client, tag = admin_client
    listed = emails(search(client, "   "))
    assert f"ada.{tag}@uni.example" in listed and f"grace.{tag}@navy.example" in listed


def test_no_match_and_paging(admin_client):
    client, tag = admin_client
    assert search(client, f"nobody-{tag}").json() == []
    first = search(client, f"{tag}@uni", page_size=1)
    assert len(first.json()) == 1 and first.headers["X-Has-More"] == "true"
    second = search(client, f"{tag}@uni", page_size=1, page=2)
    assert second.headers["X-Has-More"] == "false" and second.json() != first.json()


def test_query_length_is_limited(admin_client):
    client, _ = admin_client
    assert client.get("/api/admin/users", params={"q": "x" * 256}).status_code == 422


def test_search_needs_admin():
    from app.main import app
    with TestClient(app, client=("203.0.113.78", 50000)) as client:
        async def plain():
            from app import database
            async with database.async_session_maker() as db:
                user = User(email=f"p-{uuid.uuid4().hex[:6]}@x.org", name="P", unity_id=f"p-{uuid.uuid4()}")
                db.add(user)
                await db.commit()
                await db.refresh(user)
                return create_session_token(user)
        client.cookies.set("access_token", client.portal.call(plain))
        assert client.get("/api/admin/users", params={"q": "a"}).status_code == 403


def test_admin_page_has_search_box(admin_client):
    client, _ = admin_client
    page = client.get("/admin/tokens").text
    assert 'id="userSearchForm"' in page and 'id="userSearch"' in page
