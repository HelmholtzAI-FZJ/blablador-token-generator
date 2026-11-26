"""Admin applications view and dashboard tabs."""
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import create_session_token, generate_token, hash_token
from app.models import Application, ApplicationMember, ROLE_MEMBER, ROLE_OWNER, Token, User
from app.timeutil import utcnow


async def seed(tag: str) -> dict:
    from app import database
    async with database.async_session_maker() as db:
        admin = User(email=f"admin-{tag}@example.org", name="Admin", unity_id=f"admin-{tag}", is_admin=True)
        owner = User(email=f"owner-{tag}@example.org", name="Owner", unity_id=f"owner-{tag}")
        plain = User(email=f"plain-{tag}@example.org", name="Plain", unity_id=f"plain-{tag}")
        db.add_all([admin, owner, plain])
        await db.flush()
        alive = Application(name=f"Bot {tag}", description="nightly")
        orphan = Application(name=f"Zombie {tag}", orphaned_at=utcnow())
        db.add_all([alive, orphan])
        await db.flush()
        db.add_all([
            ApplicationMember(application_id=alive.id, user_id=owner.id, email=owner.email, role=ROLE_OWNER),
            ApplicationMember(application_id=alive.id, email=f"invitee-{tag}@example.org", role=ROLE_MEMBER),
            ApplicationMember(application_id=orphan.id, email=f"left-{tag}@example.org", role=ROLE_MEMBER),
        ])
        now = utcnow()
        for revoked, expires in ((None, now + timedelta(days=5)), (now, now + timedelta(days=5)),
                                 (None, now - timedelta(days=1))):
            db.add(Token(application_id=alive.id, created_by_id=owner.id, name="t",
                         token_hash=hash_token(generate_token()), revoked_at=revoked, expires_at=expires))
        await db.commit()
        return {"admin": create_session_token(admin), "plain": create_session_token(plain),
                "alive": alive.id, "orphan": orphan.id}


@pytest.fixture
def setup():
    from app.main import app
    tag = uuid.uuid4().hex[:8]
    with TestClient(app, client=("203.0.113.90", 50000)) as client:
        yield client, tag, client.portal.call(lambda: seed(tag))


def listed(client, session, **params):
    client.cookies.set("access_token", session)
    return client.get("/api/admin/applications", params={"page_size": 100, **params})


def test_admin_sees_every_application_with_counts(setup):
    client, tag, ids = setup
    response = listed(client, ids["admin"], q=tag)
    assert response.status_code == 200
    rows = response.json()
    assert [row["id"] for row in rows] == [ids["orphan"], ids["alive"]]
    zombie, bot = rows
    assert zombie["orphaned_at"] and zombie["owners"] == [] and zombie["members"] == 1
    assert bot["owners"] == [f"owner-{tag}@example.org"] and bot["members"] == 2
    assert bot["tokens"] == 3 and bot["active_tokens"] == 1
    assert bot["description"] == "nightly" and zombie["tokens"] == 0


def test_search_by_name_or_member_email(setup):
    client, tag, ids = setup
    assert [r["id"] for r in listed(client, ids["admin"], q=f"BOT {tag}").json()] == [ids["alive"]]
    assert [r["id"] for r in listed(client, ids["admin"], q=f"invitee-{tag}").json()] == [ids["alive"]]
    assert [r["id"] for r in listed(client, ids["admin"], q=f"left-{tag}@").json()] == [ids["orphan"]]
    assert listed(client, ids["admin"], q=f"%{tag}").json() == []


def test_paging(setup):
    client, tag, ids = setup
    first = listed(client, ids["admin"], q=tag, page_size=1)
    assert first.headers["X-Has-More"] == "true" and len(first.json()) == 1
    second = listed(client, ids["admin"], q=tag, page_size=1, page=2)
    assert second.headers["X-Has-More"] == "false" and second.json()[0]["id"] == ids["alive"]


def test_only_admins(setup):
    client, _, ids = setup
    assert listed(client, ids["plain"]).status_code == 403


def test_admin_page_has_applications_tab(setup):
    client, _, ids = setup
    client.cookies.set("access_token", ids["admin"])
    page = client.get("/admin/tokens").text
    assert 'data-tab="applications"' in page and 'id="applications-tab"' in page
    assert 'id="applicationSearchForm"' in page


def test_dashboard_has_tabs(setup):
    client, _, ids = setup
    client.cookies.set("access_token", ids["plain"])
    page = client.get("/dashboard").text
    assert 'data-tab="tokens"' in page and 'data-tab="applications"' in page
    assert 'id="tokens-tab" class="tab-content active"' in page
    assert 'id="applications-tab"' in page and 'id="applicationsCard"' in page
    assert 'data-tab="courses"' not in page
    tokens_tab = page.split('id="tokens-tab"', 1)[1].split('id="applications-tab"', 1)[0]
    assert "Create New Token" in tokens_tab and "API Usage" in tokens_tab
