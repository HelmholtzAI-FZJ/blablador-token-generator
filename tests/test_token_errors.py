"""Rejected bearer tokens get RFC 6750 answers with a reason code."""
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.auth import generate_token, hash_token
from app.models import Token, User
from app.timeutil import utcnow


@pytest.fixture
def client():
    from app.main import app
    with TestClient(app, client=("203.0.113.120", 50000)) as test_client:
        yield test_client


def seed_token(client, **token_fields) -> str:
    from app import database

    async def seed():
        async with database.async_session_maker() as db:
            user = User(email=f"e-{uuid.uuid4().hex[:6]}@x.org", name="E", unity_id=f"e-{uuid.uuid4()}")
            db.add(user)
            await db.flush()
            plain = generate_token()
            db.add(Token(user_id=user.id, token_hash=hash_token(plain), name="t", **token_fields))
            await db.commit()
            return plain
    return client.portal.call(seed)


ENDPOINTS = [("POST", "/api/v1/auth/validate"), ("GET", "/api/v1/auth/validate"), ("GET", "/api/v1/user")]


def rejected(client, token, method="POST", path="/api/v1/auth/validate"):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = client.request(method, path, headers=headers)
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/json")
    return response


@pytest.mark.parametrize("method, path", ENDPOINTS)
def test_malformed_token_explains_itself(client, method, path):
    good = generate_token()
    for bad in (good + "a", good[:-1], good + "3", "blablador-course-xyz", "nonsense"):
        response = rejected(client, bad, method, path)
        body = response.json()
        assert body["valid"] is False and body["error"] == "invalid_token" and body["reason"] == "malformed"
        assert "64 hexadecimal characters" in body["error_description"]
        assert "blablador-course-" in body["error_description"]
        assert body["detail"] == body["error_description"]
        assert response.headers["www-authenticate"].startswith('Bearer error="invalid_token", error_description="')


@pytest.mark.parametrize("method, path", ENDPOINTS)
def test_missing_token_is_an_invalid_request_without_error_in_challenge(client, method, path):
    response = rejected(client, None, method, path)
    body = response.json()
    assert body["error"] == "invalid_request" and body["reason"] == "missing_token"
    assert "Authorization: Bearer" in body["error_description"]
    assert response.headers["www-authenticate"] == "Bearer"


def test_unknown_revoked_and_expired_tokens_have_reasons(client):
    assert rejected(client, generate_token()).json()["reason"] == "unknown_or_revoked"
    # Well formed but issued by no one: unknown, not malformed.
    assert rejected(client, generate_token() + "33").json()["reason"] == "unknown_or_revoked"
    revoked = seed_token(client, revoked_at=utcnow())
    assert rejected(client, revoked).json()["reason"] == "unknown_or_revoked"
    expired = seed_token(client, expires_at=utcnow() - timedelta(days=1))
    body = rejected(client, expired).json()
    assert body["reason"] == "expired" and body["error_description"] == "Token has expired"


def test_valid_token_still_answers_200(client):
    plain = seed_token(client, expires_at=utcnow() + timedelta(days=1))
    response = client.post("/api/v1/auth/validate", headers={"Authorization": f"Bearer {plain}"})
    assert response.status_code == 200 and response.json()["valid"] is True


def test_challenge_never_contains_double_quotes():
    from app.api.validate import TokenRejected
    rejection = TokenRejected("malformed", 'say "hi"')
    assert rejection.headers["WWW-Authenticate"].count('"') == 4
    assert rejection.body()["error_description"] == 'say "hi"'


def test_html_pages_are_unaffected(client):
    response = client.get("/nonexistent-page", headers={"accept": "text/html"})
    assert response.status_code == 404 and "text/html" in response.headers["content-type"]


def test_course_rejections_have_reasons(client):
    from tests.test_courses import Session, course_body, join, code_of, run_sql  # noqa: F401
    from app.models import Course

    teacher = Session(client, teacher=True)
    course = teacher.post("/courses", json=course_body()).json()
    _, joined = join(client, course)
    client.portal.call(lambda: run_sql(update(Course).where(Course.id == course["id"]).values(
        starts_at=utcnow() + timedelta(days=1), ends_at=utcnow() + timedelta(days=2))))
    client.cookies.clear()
    assert rejected(client, joined["token"]).json()["reason"] == "course_not_started"
    client.portal.call(lambda: run_sql(update(Course).where(Course.id == course["id"]).values(
        starts_at=utcnow() - timedelta(days=2), ends_at=utcnow() - timedelta(days=1))))
    body = rejected(client, joined["token"]).json()
    assert body["reason"] in ("expired", "course_ended")
    client.portal.call(lambda: run_sql(update(Course).where(Course.id == course["id"]).values(
        ends_at=utcnow() + timedelta(days=1), suspended_at=utcnow())))
    assert rejected(client, joined["token"]).json()["reason"] == "course_closed"


def test_current_user_reports_email_at_the_top_level(client):
    plain = seed_token(client, expires_at=utcnow() + timedelta(days=1))
    body = client.get("/api/v1/user", headers={"Authorization": f"Bearer {plain}"}).json()
    assert body["email"] == body["user"]["email"] and body["email"].endswith("@x.org")
    assert list(body)[0] == "email"


def test_current_user_email_for_a_mailed_course_token(client):
    from tests.test_courses import Session, course_body, invite, drain, link_in, code_of, claim_signed_out
    from app.config import get_config

    teacher = Session(client, teacher=True)
    course = teacher.post("/courses", json=course_body()).json()
    sent = []

    async def fake_send(recipients, subject, body, reply_to=None):
        sent.append({"to": recipients, "subject": subject, "body": body})
        return True

    import app.mailer as mailer
    original, enabled = mailer.send_mail, get_config().smtp.enabled
    mailer.send_mail, get_config().smtp.enabled = fake_send, True
    try:
        address = f"top-{uuid.uuid4().hex[:6]}@uni.example"
        invite(teacher, course, [address])
        drain(client)
        token = claim_signed_out(client, code_of(link_in(sent[-1]))).json()["token"]
    finally:
        mailer.send_mail, get_config().smtp.enabled = original, enabled
    body = client.get("/api/v1/user", headers={"Authorization": f"Bearer {token}"}).json()
    assert body["email"] == address and body["token_type"] == "course"
