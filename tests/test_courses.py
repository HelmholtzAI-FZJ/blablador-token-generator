"""Courses: teachers, join links, seats, course tokens and their validation."""
import asyncio
import itertools
import uuid
from datetime import date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.api import courses as courses_api
from app.api.validate import is_possible_token, token_shape
from app.auth import create_session_token, generate_token, hash_token
from app.config import Config, get_config
from app.models import Course, CourseInvitation, CourseSeat, Token, User
from app.timeutil import utcnow

CSRF = {"X-CSRF-Token": "c"}


def today() -> date:
    return utcnow().date()


def course_body(**changes) -> dict:
    body = {
        "name": "Intro to LLMs",
        "starts_on": today().isoformat(),
        "ends_on": (today() + timedelta(days=13)).isoformat(),
        "max_seats": 3,
        "accept_terms": True,
    }
    body.update(changes)
    return body


async def seed_user(teacher=False, admin=False) -> tuple[str, str]:
    from app import database
    async with database.async_session_maker() as db:
        user = User(email=f"{uuid.uuid4().hex[:8]}@example.com", name="Person",
                    unity_id=f"subject-{uuid.uuid4()}", is_teacher=teacher, is_admin=admin,
                    email_verified=True)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user.id, create_session_token(user)


async def run_sql(statement) -> None:
    from app import database
    async with database.async_session_maker() as db:
        await db.execute(statement)
        await db.commit()


async def fetch(query):
    from app import database
    async with database.async_session_maker() as db:
        return (await db.execute(query)).scalars().all()


class Session:
    """A TestClient signed in as one user."""

    def __init__(self, client: TestClient, teacher=False, admin=False):
        self.client = client
        self.user_id, self.session = client.portal.call(lambda: seed_user(teacher, admin))

    def _cookies(self):
        self.client.cookies.clear()
        self.client.cookies.set("access_token", self.session)
        self.client.cookies.set("csrf_token", "c")

    def post(self, path, **kwargs):
        self._cookies()
        return self.client.post(path, headers=CSRF, **kwargs)

    def patch(self, path, **kwargs):
        self._cookies()
        return self.client.patch(path, headers=CSRF, **kwargs)

    def get(self, path, **kwargs):
        self._cookies()
        return self.client.get(path, **kwargs)

    def delete(self, path, **kwargs):
        self._cookies()
        return self.client.delete(path, headers=CSRF, **kwargs)


def code_of(join_url: str) -> str:
    return join_url.rsplit("/", 1)[1]


def validate(client: TestClient, token: str):
    client.cookies.clear()
    return client.post("/api/v1/auth/validate", headers={"Authorization": f"Bearer {token}"})


@pytest.fixture(scope="module", autouse=True)
def clean_database_afterwards():
    """Leave no courses or tokens behind for modules that count rows."""
    yield
    import os
    from app.database import build_engine
    from tests.conftest import drop_schema

    async def drop():
        engine = build_engine(os.environ["DATABASE_URL"])
        async with engine.begin() as conn:
            await drop_schema(conn)
        await engine.dispose()

    asyncio.run(drop())


_addresses = itertools.count(1)


def new_client() -> TestClient:
    """Each test gets its own client address, so its many requests do not
    use up the per-address budgets the rest of the suite relies on."""
    from app.main import app
    n = next(_addresses)
    return TestClient(app, client=(f"198.51.{100 + n // 250}.{n % 250 + 1}", 50000))


@pytest.fixture
def client():
    with new_client() as test_client:
        yield test_client


@pytest.fixture
def teacher(client):
    return Session(client, teacher=True)


@pytest.fixture
def course(teacher):
    response = teacher.post("/courses", json=course_body())
    assert response.status_code == 200, response.text
    return response.json()


def join(client, course) -> tuple[Session, dict]:
    student = Session(client)
    response = student.post(f"/courses/join/{code_of(course['join_url'])}")
    assert response.status_code == 200, response.text
    return student, response.json()


# Token format


def test_course_tokens_have_their_own_shape():
    token = generate_token(course=True)
    assert token.startswith("blablador-course-")
    assert token_shape(token) == "course"
    assert token_shape(generate_token()) == "personal"
    assert is_possible_token(token)
    for bad in ("blablador-course-", "blablador-course-abc", "blablador-course-zz", "blablador-courses-ab",
                "other-course-abcd"):
        assert token_shape(bad) is None, bad


def test_config_refuses_course_tokens_too_long_for_input():
    with pytest.raises(ValueError, match="Course tokens"):
        Config(tokens={"token_prefix": "p" * 10, "token_length_bytes": 120}, courses={"enabled": True})
    Config(tokens={"token_prefix": "p" * 10, "token_length_bytes": 120}, courses={"enabled": False})


# Creating courses


def test_teacher_creates_course_with_join_link(teacher, course):
    assert course["join_url"].startswith("http://testserver/courses/join/")
    assert len(code_of(course["join_url"])) == 2 * get_config().courses.join_code_bytes
    assert course["seats_claimed"] == 0 and course["max_seats"] == 3 and course["active"]
    assert course["starts_at"].startswith(today().isoformat())
    assert course["ends_at"].startswith((today() + timedelta(days=14)).isoformat())
    stored = teacher.client.portal.call(lambda: fetch(select(Course).where(Course.id == course["id"])))[0]
    assert stored.join_code_hash != code_of(course["join_url"])
    assert stored.terms_version == get_config().courses.terms_version
    assert [c["id"] for c in teacher.get("/courses").json()] == [course["id"]]
    assert "join_url" not in teacher.get(f"/courses/{course['id']}").json()


def test_only_teachers_create_courses(client):
    response = Session(client).post("/courses", json=course_body())
    assert response.status_code == 403


@pytest.mark.parametrize("changes, detail", [
    ({"accept_terms": False}, "Accept the course terms"),
    ({"max_seats": 61}, "at most 60 seats"),
    ({"ends_on": (date.today() + timedelta(days=21)).isoformat()}, "at most 21 days"),
    ({"ends_on": (date.today() - timedelta(days=1)).isoformat()}, "end on or after"),
    ({"starts_on": (date.today() - timedelta(days=5)).isoformat(),
      "ends_on": (date.today() - timedelta(days=2)).isoformat()}, "end in the future"),
    ({"starts_on": (date.today() + timedelta(days=181)).isoformat(),
      "ends_on": (date.today() + timedelta(days=182)).isoformat()}, "at most 180 days from today"),
])
def test_course_limits(teacher, changes, detail):
    response = teacher.post("/courses", json=course_body(**changes))
    assert response.status_code == 400 and detail in response.json()["detail"]


def test_longest_course_is_accepted(teacher):
    response = teacher.post("/courses", json=course_body(ends_on=(today() + timedelta(days=20)).isoformat()))
    assert response.status_code == 200


def test_one_active_course_per_teacher(teacher, course):
    again = teacher.post("/courses", json=course_body(name="Second"))
    assert again.status_code == 400 and "1 course(s) at a time" in again.json()["detail"]
    assert teacher.post(f"/courses/{course['id']}/close").status_code == 200
    assert teacher.post("/courses", json=course_body(name="Second")).status_code == 200


def test_ended_course_frees_the_teacher(teacher, course):
    teacher.client.portal.call(lambda: run_sql(
        update(Course).where(Course.id == course["id"])
        .values(starts_at=utcnow() - timedelta(days=10), ends_at=utcnow() - timedelta(days=1))
    ))
    assert teacher.post("/courses", json=course_body(name="Next")).status_code == 200


def test_concurrent_course_creation_respects_the_cap():
    from app import database

    with new_client() as client:
        teacher = Session(client, teacher=True)

        async def create_twice():
            async with database.async_session_maker() as first, database.async_session_maker() as second:
                user_one = await first.get(User, teacher.user_id)
                user_two = await second.get(User, teacher.user_id)
                body = courses_api.CreateCourseRequest(**course_body())
                results = await asyncio.gather(
                    courses_api.create_course.__wrapped__(_request(), body, user_one, first),
                    courses_api.create_course.__wrapped__(_request(), body, user_two, second),
                    return_exceptions=True,
                )
                return results

        results = client.portal.call(create_twice)
        assert sum(not isinstance(result, Exception) for result in results) == 1
        assert len(client.portal.call(lambda: fetch(select(Course).where(Course.teacher_id == teacher.user_id)))) == 1


def _request():
    from starlette.requests import Request
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [],
                    "query_string": b"", "client": ("127.0.0.12", 0)})


def test_other_teachers_cannot_see_or_manage_a_course(client, course):
    other = Session(client, teacher=True)
    assert other.get(f"/courses/{course['id']}").status_code == 404
    assert other.get(f"/courses/{course['id']}/seats").status_code == 404
    assert other.post(f"/courses/{course['id']}/close").status_code == 404
    assert other.post(f"/courses/{course['id']}/join-link").status_code == 404


# Joining


def test_student_joins_and_token_validates_as_course(client, teacher, course):
    student, joined = join(client, course)
    assert joined["token"].startswith("blablador-course-")
    assert joined["course"]["seats_claimed"] == 1
    assert joined["expires_at"] == course["ends_at"]

    response = validate(client, joined["token"])
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "course"
    assert body["user_id"] == student.user_id
    assert body["course"]["id"] == course["id"] and body["course"]["name"] == "Intro to LLMs"
    assert body["application"] is None

    me = client.get("/api/v1/user", headers={"Authorization": f"Bearer {joined['token']}"}).json()
    assert me["token_type"] == "course" and me["course"]["id"] == course["id"]

    seats = teacher.get(f"/courses/{course['id']}/seats").json()
    assert len(seats) == 1
    assert seats[0]["token_status"] == "active" and seats[0]["use_count"] == 2
    assert seats[0]["last_used_at"] is not None


def test_every_use_is_counted(client, teacher, course):
    _, joined = join(client, course)
    for _ in range(5):
        assert validate(client, joined["token"]).status_code == 200
    assert teacher.get(f"/courses/{course['id']}/seats").json()[0]["use_count"] == 5


def test_student_joins_once(client, course):
    student, _ = join(client, course)
    again = student.post(f"/courses/join/{code_of(course['join_url'])}")
    assert again.status_code == 409


def test_link_stops_working_when_full(client, teacher, course):
    for _ in range(3):
        join(client, course)
    late = Session(client).post(f"/courses/join/{code_of(course['join_url'])}")
    assert late.status_code == 410 and "full" in late.json()["detail"]
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 3


def test_deleted_seat_token_does_not_free_the_seat(client, teacher, course):
    student, joined = join(client, course)
    assert student.delete(f"/tokens/{joined['token_id']}/permanent").status_code == 200
    assert student.post(f"/courses/join/{code_of(course['join_url'])}").status_code == 409
    seats = teacher.get(f"/courses/{course['id']}/seats").json()
    assert seats[0]["token_status"] == "deleted"
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 1


def test_unknown_and_malformed_codes(client, course):
    student = Session(client)
    assert student.post(f"/courses/join/{'0' * 48}").status_code == 404
    assert student.post("/courses/join/not-a-code").status_code == 404
    assert student.post(f"/courses/join/{'a' * 200}").status_code == 422


def test_joining_requires_sign_in(client, course):
    client.cookies.clear()
    client.cookies.set("csrf_token", "c")
    assert client.post(f"/courses/join/{code_of(course['join_url'])}", headers=CSRF).status_code == 401


def test_join_requires_csrf(client, course):
    student = Session(client)
    student._cookies()
    assert client.post(f"/courses/join/{code_of(course['join_url'])}").status_code == 403


def test_concurrent_joins_never_exceed_seats(client, teacher):
    from app import database

    course = teacher.post("/courses", json=course_body(max_seats=2)).json()
    code = code_of(course["join_url"])
    students = [Session(client) for _ in range(5)]

    async def join_all():
        async def one(student):
            async with database.async_session_maker() as db:
                user = await db.get(User, student.user_id)
                try:
                    await courses_api.join_course.__wrapped__(_request(), code, user, db)
                    return True
                except Exception:
                    return False
        return await asyncio.gather(*(one(student) for student in students))

    results = client.portal.call(join_all)
    assert sum(results) == 2
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 2


# Validity window


def test_token_is_refused_before_the_course_starts(client, teacher):
    starts = today() + timedelta(days=3)
    course = teacher.post("/courses", json=course_body(
        starts_on=starts.isoformat(), ends_on=(starts + timedelta(days=2)).isoformat())).json()
    _, joined = join(client, course)
    response = validate(client, joined["token"])
    assert response.status_code == 401 and "not started" in response.json()["detail"]


def test_token_is_refused_after_the_course_ends(client, course):
    _, joined = join(client, course)
    client.portal.call(lambda: run_sql(
        update(Course).where(Course.id == course["id"]).values(ends_at=utcnow() - timedelta(minutes=1))
    ))
    assert validate(client, joined["token"]).status_code == 401


def test_course_marker_must_match_the_record(client):
    """A course-shaped value of a personal token, or the reverse, is refused."""
    student = Session(client)
    plain = generate_token(course=True)

    async def store():
        from app import database
        async with database.async_session_maker() as db:
            db.add(Token(user_id=student.user_id, token_hash=hash_token(plain), name="forged"))
            await db.commit()

    client.portal.call(store)
    assert validate(client, plain).status_code == 401


# Revocation


def test_teacher_revokes_one_student(client, teacher, course):
    student, joined = join(client, course)
    _, other = join(client, course)
    seat = teacher.get(f"/courses/{course['id']}/seats").json()[0]
    response = teacher.post(f"/courses/{course['id']}/seats/{seat['id']}/revoke")
    assert response.status_code == 200 and response.json()["tokens_revoked"] == 1
    assert validate(client, joined["token"]).status_code == 401
    assert validate(client, other["token"]).status_code == 200
    assert student.post(f"/courses/join/{code_of(course['join_url'])}").status_code == 409
    assert student.post(f"/tokens/{joined['token_id']}/rotate").status_code == 400


def test_close_revokes_everything_and_disables_link(client, teacher, course):
    tokens = [join(client, course)[1]["token"] for _ in range(2)]
    response = teacher.post(f"/courses/{course['id']}/close")
    assert response.status_code == 200 and response.json()["tokens_revoked"] == 2
    for token in tokens:
        assert validate(client, token).status_code == 401
    assert Session(client).post(f"/courses/join/{code_of(course['join_url'])}").status_code == 404
    state = teacher.get(f"/courses/{course['id']}").json()
    assert not state["active"] and state["suspended_reason"] == "closed_by_teacher"
    assert teacher.post(f"/courses/{course['id']}/join-link").status_code == 400


def test_new_link_replaces_old_and_keeps_seats(client, teacher, course):
    _, joined = join(client, course)
    fresh = teacher.post(f"/courses/{course['id']}/join-link").json()["join_url"]
    assert fresh != course["join_url"]
    assert Session(client).post(f"/courses/join/{code_of(course['join_url'])}").status_code == 404
    assert Session(client).post(f"/courses/join/{code_of(fresh)}").status_code == 200
    assert validate(client, joined["token"]).status_code == 200
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 2


# Student's own token


def test_course_token_cannot_be_renewed(client, course):
    student, joined = join(client, course)
    response = student.post(f"/tokens/{joined['token_id']}/renew", json={"expires_in_days": 300})
    assert response.status_code == 400


def test_course_token_cannot_be_rotated(client, course):
    student, joined = join(client, course)
    response = student.post(f"/tokens/{joined['token_id']}/rotate")
    assert response.status_code == 400 and "cannot be rotated" in response.json()["detail"]
    assert validate(client, joined["token"]).status_code == 200


def test_course_tokens_do_not_count_towards_personal_limit(client, course, monkeypatch):
    student, _ = join(client, course)
    monkeypatch.setattr(get_config().tokens, "max_tokens_per_user", 1)
    response = student.post("/tokens", json={"name": "mine", "expires_in_days": 5})
    assert response.status_code == 200


def test_teacher_cannot_manage_student_tokens(client, teacher, course):
    _, joined = join(client, course)
    assert teacher.delete(f"/tokens/{joined['token_id']}").status_code == 404


def test_dashboard_shows_course_badge_without_renew(client, course):
    student, joined = join(client, course)
    page = student.get("/dashboard").text
    assert "Course: Intro to LLMs" in page
    row = page.split(f'data-token-id="{joined["token_id"]}"', 1)[1].split("</tr>", 1)[0]
    assert "renew-token" not in row and "rotate-token" not in row and "revoke-token" in row


def test_dashboard_course_card_only_for_teachers(client, teacher):
    page = teacher.get("/dashboard").text
    assert 'id="coursesCard"' in page
    assert '<h2>My courses</h2>' in page and 'data-tab="courses">My courses<' in page
    assert 'id="courses-tab"' in page
    assert "/static/courses.js" in teacher.get("/dashboard").text
    assert 'id="coursesCard"' not in Session(client).get("/dashboard").text


# Join page


def test_join_page_resumes_after_sign_in(client, course):
    code = code_of(course["join_url"])
    client.cookies.clear()
    response = client.get(f"/courses/join/{code}", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/"
    resume = response.cookies.get("course_join")
    assert resume == f"join-{code}"

    from app.main import after_sign_in
    from starlette.requests import Request
    request = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                       "headers": [(b"cookie", f"course_join=join-{code}".encode())]})
    assert after_sign_in(request) == f"/courses/join/{code}"
    invite = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                      "headers": [(b"cookie", f"course_join=invite-{code}".encode())]})
    # Invitations need no sign-in, so there is nothing to resume.
    assert after_sign_in(invite) == "/dashboard"
    for value in (code, f"other-{code}", "invite-../evil"):
        odd = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                       "headers": [(b"cookie", f"course_join={value}".encode())]})
        assert after_sign_in(odd) == "/dashboard"
    bad = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                   "headers": [(b"cookie", b"course_join=../../evil")]})
    assert after_sign_in(bad) == "/dashboard"


def test_local_sign_in_follows_the_join_cookie(client, course):
    from app import database
    from app.auth import hash_password

    code = code_of(course["join_url"])
    email = f"local-{uuid.uuid4().hex[:6]}@example.com"
    password = "a sufficiently long passphrase 42"

    async def seed():
        async with database.async_session_maker() as db:
            db.add(User(email=email, name="Local", password_hash=hash_password(password), email_verified=True))
            await db.commit()

    client.portal.call(seed)
    client.cookies.clear()
    client.cookies.set("csrf_token", "c")
    client.cookies.set("course_join", f"join-{code}")
    response = client.post("/login/local", data={"email": email, "password": password, "csrf_token": "c"},
                           follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == f"/courses/join/{code}"


def test_join_page_shows_course_and_does_not_claim(client, teacher, course):
    student = Session(client)
    page = student.get(f"/courses/join/{code_of(course['join_url'])}", headers={"accept": "text/html"})
    assert page.status_code == 200
    assert "Intro to LLMs" in page.text and 'data-action="join-course"' in page.text
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 0


def test_join_page_explains_problems(client, teacher, course):
    student = Session(client)
    unknown = student.get(f"/courses/join/{'0' * 48}")
    assert unknown.status_code == 404 and "not valid" in unknown.text
    teacher.post(f"/courses/{course['id']}/close")
    closed = student.get(f"/courses/join/{code_of(course['join_url'])}")
    assert closed.status_code == 404 and 'data-action="join-course"' not in closed.text


def test_courses_disabled(client, teacher, monkeypatch):
    monkeypatch.setattr(get_config().courses, "enabled", False)
    assert teacher.post("/courses", json=course_body()).status_code == 404
    assert teacher.get("/courses").status_code == 404
    assert teacher.get(f"/courses/join/{'0' * 48}").status_code == 404
    assert 'id="coursesCard"' not in teacher.get("/dashboard").text


# Admin


def test_admin_grants_and_removes_teacher_role(client):
    admin = Session(client, admin=True)
    person = Session(client)
    assert person.post("/courses", json=course_body()).status_code == 403
    granted = admin.patch(f"/api/admin/users/{person.user_id}", json={"is_teacher": True})
    assert granted.status_code == 200 and granted.json()["is_teacher"] is True
    course = person.post("/courses", json=course_body())
    assert course.status_code == 200
    _, joined = join(client, course.json())

    removed = admin.patch(f"/api/admin/users/{person.user_id}", json={"is_teacher": False})
    assert removed.status_code == 200 and removed.json()["is_teacher"] is False
    assert validate(client, joined["token"]).status_code == 401
    state = person.get(f"/courses/{course.json()['id']}").json()
    assert state["suspended_reason"] == "teacher_role_removed"
    assert person.post("/courses", json=course_body()).status_code == 403


def test_non_admin_cannot_grant_teacher(client):
    person = Session(client)
    assert person.patch(f"/api/admin/users/{person.user_id}", json={"is_teacher": True}).status_code == 403


def test_admin_lists_and_suspends_courses(client, teacher, course):
    admin = Session(client, admin=True)
    _, joined = join(client, course)
    listed = admin.get("/api/admin/courses", params={"page_size": 100}).json()
    entry = next(c for c in listed if c["id"] == course["id"])
    assert entry["seats_claimed"] == 1 and entry["active"] and entry["terms_version"] == "1"
    assert admin.post(f"/api/admin/courses/{course['id']}/suspend").json()["tokens_revoked"] == 1
    assert validate(client, joined["token"]).status_code == 401
    assert teacher.get(f"/courses/{course['id']}").json()["suspended_reason"] == "suspended_by_admin"
    assert admin.post(f"/api/admin/courses/{uuid.uuid4()}/suspend").status_code == 404
    assert "Courses" in admin.get("/admin/tokens").text


def test_deleting_teacher_closes_course(client, teacher, course):
    admin = Session(client, admin=True)
    _, joined = join(client, course)
    assert admin.delete(f"/api/admin/users/{teacher.user_id}").status_code == 200
    assert validate(client, joined["token"]).status_code == 401
    stored = client.portal.call(lambda: fetch(select(Course).where(Course.id == course["id"])))[0]
    assert stored.teacher_id is None and stored.suspended_reason == "teacher_deleted"


def test_teacher_deleting_own_account_closes_course(client, teacher, course):
    _, joined = join(client, course)
    assert teacher.post("/account/delete").status_code == 200
    assert validate(client, joined["token"]).status_code == 401


def test_deleting_student_frees_nothing(client, teacher, course):
    student, _ = join(client, course)
    assert student.post("/account/delete").status_code == 200
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 1
    assert teacher.get(f"/courses/{course['id']}/seats").json() == []


# Purge


def test_purge_deletes_tokens_of_long_ended_courses(client, course):
    from app import database
    from app.courses import purge_ended_courses

    _, joined = join(client, course)
    fresh = Session(client, teacher=True).post("/courses", json=course_body(name="Still running")).json()
    _, kept = join(client, fresh)
    retention = get_config().courses.retention_days
    client.portal.call(lambda: run_sql(
        update(Course).where(Course.id == course["id"])
        .values(starts_at=utcnow() - timedelta(days=retention + 10),
                ends_at=utcnow() - timedelta(days=retention + 1))
    ))

    async def purge():
        async with database.async_session_maker() as db:
            return await purge_ended_courses(db)

    assert client.portal.call(purge) == 1
    remaining = client.portal.call(lambda: fetch(select(Token.id).where(Token.course_id.isnot(None))))
    assert joined["token_id"] not in remaining and kept["token_id"] in remaining
    assert client.portal.call(lambda: fetch(select(CourseSeat.id).where(CourseSeat.course_id == course["id"])))
    stored = client.portal.call(lambda: fetch(select(Course).where(Course.id == course["id"])))[0]
    assert stored.join_code_hash is None


def test_purge_command_is_registered(monkeypatch, capsys):
    from app import manage

    called = []

    async def fake_run(args):
        called.append(args.command)
        return "ok"

    monkeypatch.setattr(manage, "run", fake_run)
    monkeypatch.setattr("sys.argv", ["manage", "purge-course-tokens"])
    manage.main()
    assert called == ["purge-course-tokens"]


def test_stored_course_dates_are_naive_utc(teacher, course):
    stored = teacher.client.portal.call(lambda: fetch(select(Course).where(Course.id == course["id"])))[0]
    assert stored.starts_at == datetime.combine(today(), datetime.min.time())


# Invitations by email


@pytest.fixture
def mailbox(monkeypatch):
    """Mail enabled; messages recorded instead of sent."""
    sent = []
    monkeypatch.setattr(get_config().smtp, "enabled", True)

    async def fake_send(recipients, subject, body, reply_to=None):
        sent.append({"to": recipients, "subject": subject, "body": body, "reply_to": reply_to})
        return True

    monkeypatch.setattr("app.mailer.send_mail", fake_send)
    return sent


def drain(client):
    """Wait for background mail deliveries."""
    from app import mailer

    async def wait():
        while mailer._pending:
            await asyncio.gather(*list(mailer._pending))

    client.portal.call(wait)


def invite(teacher, course, emails, subject="Welcome", body="Hello class"):
    return teacher.post(f"/courses/{course['id']}/invitations",
                        json={"emails": emails, "subject": subject, "body": body})


def link_in(message) -> str:
    return next(line.strip() for line in message["body"].splitlines() if "/courses/invite/" in line)


def test_invitations_mail_one_personal_link_each(client, teacher, course, mailbox):
    response = invite(teacher, course, ["A@Example.org", "b@example.org", "a@example.org"])
    assert response.status_code == 200, response.text
    result = response.json()
    assert [i["email"] for i in result["invited"]] == ["a@example.org", "b@example.org"]
    drain(client)
    assert sorted(m["to"][0] for m in mailbox) == ["a@example.org", "b@example.org"]
    message = mailbox[0]
    assert message["subject"] == "Welcome"
    assert message["body"].startswith("Hello class")
    assert "Intro to LLMs" in message["body"] and today().isoformat() in message["body"]
    teacher_user = client.portal.call(lambda: fetch(select(User).where(User.id == teacher.user_id)))[0]
    assert message["reply_to"] == teacher_user.email
    assert f"on behalf of {teacher_user.name} <{teacher_user.email}>" in message["body"]
    links = {link_in(m) for m in mailbox}
    assert len(links) == 2 and all(link.startswith("http://testserver/courses/invite/") for link in links)
    stored = client.portal.call(lambda: fetch(select(CourseInvitation)))
    assert all(code_of(link) not in {i.code_hash for i in stored} for link in links)


def claim_signed_out(client, code):
    client.cookies.clear()
    client.cookies.set("csrf_token", "c")
    return client.post(f"/courses/invite/{code}", headers=CSRF)


def test_invitation_link_shows_token_once_without_sign_in(client, teacher, course, mailbox):
    invitation = invite(teacher, course, ["student@uni.example"]).json()["invited"][0]
    drain(client)
    code = code_of(link_in(mailbox[0]))
    claimed = claim_signed_out(client, code)
    assert claimed.status_code == 200, claimed.text
    token = claimed.json()["token"]
    assert token.startswith("blablador-course-")

    body = validate(client, token).json()
    assert body["valid"] and body["token_type"] == "course"
    assert body["user_id"] is None and body["user"] is None
    assert body["email"] == "student@uni.example"
    assert body["course"]["student_id"] == f"invitation:{invitation['id']}"
    assert body["course"]["student_email"] == "student@uni.example"

    assert claim_signed_out(client, code).status_code == 404
    listed = teacher.get(f"/courses/{course['id']}/invitations").json()[0]
    assert listed["status"] == "claimed" and listed["claimed_by_name"] is None
    assert listed["token_status"] == "active" and listed["use_count"] == 1 and listed["last_used_at"]
    assert "token" not in listed and "link" not in listed
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 1


def test_signed_in_visitor_does_not_get_the_mailed_token(client, teacher, course, mailbox):
    invite(teacher, course, ["student@uni.example"])
    drain(client)
    someone = Session(client)
    claimed = someone.post(f"/courses/invite/{code_of(link_in(mailbox[0]))}")
    assert claimed.status_code == 200
    assert validate(client, claimed.json()["token"]).json()["email"] == "student@uni.example"
    assert "Course: Intro to LLMs" not in someone.get("/dashboard").text


def test_claiming_needs_csrf(client, teacher, course, mailbox):
    invite(teacher, course, ["a@x.org"])
    drain(client)
    client.cookies.clear()
    assert client.post(f"/courses/invite/{code_of(link_in(mailbox[0]))}").status_code == 403


def test_invitations_hold_seats(client, teacher, course, mailbox):
    assert invite(teacher, course, ["a@x.org", "b@x.org"]).status_code == 200
    shared = Session(client).post(f"/courses/join/{code_of(course['join_url'])}")
    assert shared.status_code == 200
    full = Session(client).post(f"/courses/join/{code_of(course['join_url'])}")
    assert full.status_code == 410 and "full" in full.json()["detail"]
    too_many = invite(teacher, course, ["c@x.org"])
    assert too_many.status_code == 400 and "0 seat(s) left" in too_many.json()["detail"]
    drain(client)
    for message in mailbox:
        assert Session(client).post(f"/courses/invite/{code_of(link_in(message))}").status_code == 200
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 3


def test_more_addresses_than_seats_sends_nothing(client, teacher, course, mailbox):
    response = invite(teacher, course, [f"s{i}@x.org" for i in range(4)])
    assert response.status_code == 400 and "Only 3 seat(s) left" in response.json()["detail"]
    drain(client)
    assert mailbox == []


def test_already_invited_addresses_are_skipped(client, teacher, course, mailbox):
    invite(teacher, course, ["a@x.org"])
    again = invite(teacher, course, ["a@x.org", "b@x.org"]).json()
    assert again["skipped"] == ["a@x.org"] and [i["email"] for i in again["invited"]] == ["b@x.org"]


def test_cancel_frees_the_seat_and_kills_the_link(client, teacher, course, mailbox):
    invited = invite(teacher, course, ["a@x.org", "b@x.org", "c@x.org"]).json()["invited"]
    drain(client)
    first = invited[0]
    code = code_of(link_in(next(m for m in mailbox if m["to"] == [first["email"]])))
    assert teacher.delete(f"/courses/{course['id']}/invitations/{first['id']}").status_code == 200
    assert Session(client).post(f"/courses/invite/{code}").status_code == 404
    assert Session(client).post(f"/courses/join/{code_of(course['join_url'])}").status_code == 200
    assert teacher.delete(f"/courses/{course['id']}/invitations/{first['id']}").status_code == 404
    reinvited = invite(teacher, course, ["a@x.org"])
    assert reinvited.status_code == 400


def test_resend_replaces_the_link_with_a_limit(client, teacher, course, mailbox):
    invitation = invite(teacher, course, ["a@x.org"]).json()["invited"][0]
    drain(client)
    old = code_of(link_in(mailbox[0]))
    path = f"/courses/{course['id']}/invitations/{invitation['id']}/resend"
    resent = teacher.post(path, json={"subject": "Again", "body": "Reminder"})
    assert resent.status_code == 200 and resent.json()["send_count"] == 2
    drain(client)
    new = code_of(link_in(mailbox[1]))
    assert mailbox[1]["subject"] == "Again"
    assert Session(client).post(f"/courses/invite/{old}").status_code == 404
    assert teacher.post(path, json={"subject": "x", "body": "y"}).status_code == 200
    limited = teacher.post(path, json={"subject": "x", "body": "y"})
    assert limited.status_code == 400 and "at most 3 times" in limited.json()["detail"]
    drain(client)
    latest = code_of(link_in(mailbox[-1]))
    assert new != latest
    assert Session(client).post(f"/courses/invite/{latest}").status_code == 200


def test_failed_delivery_is_reported(client, teacher, course, mailbox, monkeypatch):
    async def failing(recipients, subject, body, reply_to=None):
        return False

    monkeypatch.setattr("app.mailer.send_mail", failing)
    invite(teacher, course, ["a@x.org"])
    drain(client)
    assert teacher.get(f"/courses/{course['id']}/invitations").json()[0]["delivery_failed"] is True


def test_closing_cancels_invitations(client, teacher, course, mailbox):
    invite(teacher, course, ["a@x.org"])
    drain(client)
    teacher.post(f"/courses/{course['id']}/close")
    assert Session(client).post(f"/courses/invite/{code_of(link_in(mailbox[0]))}").status_code == 404
    assert teacher.get(f"/courses/{course['id']}/invitations").json()[0]["status"] == "cancelled"
    assert invite(teacher, course, ["b@x.org"]).status_code == 400


@pytest.mark.parametrize("payload, field", [
    ({"subject": "Hi\r\nBcc: victim@x.org"}, "subject"),
    ({"body": "bad \u202e override"}, "body"),
    ({"body": "x" * 4001}, "body"),
    ({"emails": ["not-an-address"]}, "emails"),
    ({"emails": []}, "emails"),
])
def test_invitation_input_is_checked(client, teacher, course, mailbox, payload, field):
    body = {"emails": ["a@x.org"], "subject": "Hi", "body": "Hello"}
    body.update(payload)
    response = teacher.post(f"/courses/{course['id']}/invitations", json=body)
    assert response.status_code == 422
    assert any(field in str(error["loc"]) for error in response.json()["detail"])


def test_body_keeps_line_breaks(client, teacher, course, mailbox):
    invite(teacher, course, ["a@x.org"], body="Line one\r\nLine two\n\tindented")
    drain(client)
    assert mailbox[0]["body"].startswith("Line one\nLine two\n\tindented")


def test_only_the_teacher_of_an_active_course_invites(client, teacher, course, mailbox):
    assert invite(Session(client, teacher=True), course, ["a@x.org"]).status_code == 404
    assert invite(Session(client), course, ["a@x.org"]).status_code == 403
    admin = Session(client, admin=True)
    admin.patch(f"/api/admin/users/{teacher.user_id}", json={"is_teacher": False})
    assert invite(teacher, course, ["a@x.org"]).status_code == 403


def test_invitations_need_mail(client, teacher, course, monkeypatch):
    monkeypatch.setattr(get_config().smtp, "enabled", False)
    response = invite(teacher, course, ["a@x.org"])
    assert response.status_code == 400 and "Mail is not configured" in response.json()["detail"]
    assert "inviteForm" not in teacher.get("/dashboard").text


def test_dashboard_offers_invitations_with_configured_text(client, teacher, mailbox):
    page = teacher.get("/dashboard").text
    assert 'id="inviteForm"' in page
    assert get_config().courses.invitation_subject in page


def test_invitation_page_shows_course_without_claiming(client, teacher, course, mailbox):
    invite(teacher, course, ["a@x.org"])
    drain(client)
    code = code_of(link_in(mailbox[0]))
    page = Session(client).get(f"/courses/invite/{code}")
    assert page.status_code == 200 and f'data-path="/courses/invite/{code}"' in page.text
    assert teacher.get(f"/courses/{course['id']}/invitations").json()[0]["status"] == "open"
    client.cookies.clear()
    signed_out = client.get(f"/courses/invite/{code}", follow_redirects=False)
    assert signed_out.status_code == 200 and "Show my token" in signed_out.text
    assert "Go to your dashboard" not in signed_out.text


def test_purge_deletes_invited_addresses(client, teacher, course, mailbox):
    from app import database
    from app.courses import purge_ended_courses

    invite(teacher, course, ["a@x.org"])
    client.portal.call(lambda: run_sql(
        update(Course).where(Course.id == course["id"])
        .values(starts_at=utcnow() - timedelta(days=400), ends_at=utcnow() - timedelta(days=390))
    ))

    async def purge():
        async with database.async_session_maker() as db:
            await purge_ended_courses(db)

    client.portal.call(purge)
    assert client.portal.call(lambda: fetch(
        select(CourseInvitation).where(CourseInvitation.course_id == course["id"]))) == []


def test_mailer_sets_reply_to(monkeypatch):
    from app import mailer

    captured = {}

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, **kwargs):
            pass

        def login(self, *args):
            pass

        def send_message(self, message):
            captured["message"] = message

    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    mailer._send(["s@x.org"], "Subject", "Body", reply_to="teacher@x.org")
    assert captured["message"]["Reply-To"] == "teacher@x.org"
    mailer._send(["s@x.org"], "Subject", "Body")
    assert captured["message"]["Reply-To"] is None


# Deleting courses


def stored_rows(client, course_id):
    async def count():
        from app import database
        async with database.async_session_maker() as db:
            return [len((await db.execute(select(model).where(column == course_id))).scalars().all())
                    for model, column in ((Course, Course.id), (Token, Token.course_id),
                                          (CourseSeat, CourseSeat.course_id),
                                          (CourseInvitation, CourseInvitation.course_id))]
    return client.portal.call(count)


def test_teacher_deletes_closed_course_with_everything(client, teacher, course, mailbox):
    _, joined = join(client, course)
    invite(teacher, course, ["a@x.org"])
    refused = teacher.delete(f"/courses/{course['id']}")
    assert refused.status_code == 400 and "Close the course" in refused.json()["detail"]
    assert stored_rows(client, course["id"]) == [1, 1, 1, 1]

    teacher.post(f"/courses/{course['id']}/close")
    response = teacher.delete(f"/courses/{course['id']}")
    assert response.status_code == 200 and response.json()["tokens_deleted"] == 1
    assert stored_rows(client, course["id"]) == [0, 0, 0, 0]
    assert validate(client, joined["token"]).status_code == 401
    assert teacher.get(f"/courses/{course['id']}").status_code == 404
    assert teacher.delete(f"/courses/{course['id']}").status_code == 404


def test_teacher_deletes_ended_course(client, teacher, course):
    client.portal.call(lambda: run_sql(
        update(Course).where(Course.id == course["id"])
        .values(starts_at=utcnow() - timedelta(days=5), ends_at=utcnow() - timedelta(days=1))
    ))
    assert teacher.delete(f"/courses/{course['id']}").status_code == 200


def test_only_the_teacher_deletes_their_course(client, teacher, course):
    teacher.post(f"/courses/{course['id']}/close")
    assert Session(client, teacher=True).delete(f"/courses/{course['id']}").status_code == 404
    assert Session(client).delete(f"/courses/{course['id']}").status_code == 404
    assert stored_rows(client, course["id"])[0] == 1


def test_admin_deletes_running_course(client, teacher, course):
    admin = Session(client, admin=True)
    _, joined = join(client, course)
    response = admin.delete(f"/api/admin/courses/{course['id']}")
    assert response.status_code == 200 and response.json()["tokens_deleted"] == 1
    assert stored_rows(client, course["id"]) == [0, 0, 0, 0]
    assert validate(client, joined["token"]).status_code == 401
    assert admin.delete(f"/api/admin/courses/{course['id']}").status_code == 404
    assert teacher.post("/courses", json=course_body(name="Fresh start")).status_code == 200


def test_admin_course_deletion_needs_admin(client, teacher, course):
    assert teacher.delete(f"/api/admin/courses/{course['id']}").status_code == 403


def test_deleted_student_seat_does_not_block_course_deletion(client, teacher, course):
    student, _ = join(client, course)
    student.post("/account/delete")
    teacher.post(f"/courses/{course['id']}/close")
    assert teacher.delete(f"/courses/{course['id']}").status_code == 200


# Invitation footer


def test_footer_is_configurable(client, teacher, course, mailbox, monkeypatch):
    monkeypatch.setattr(get_config().courses, "invitation_footer",
                        "Kurs {course} ({start}–{end}) von {teacher_name}: {link}")
    invite(teacher, course, ["a@x.org"], body="Hallo {braces} stay literal")
    drain(client)
    body = mailbox[0]["body"]
    assert body.startswith("Hallo {braces} stay literal\n\nKurs Intro to LLMs (")
    assert f"{today().isoformat()}–{(today() + timedelta(days=13)).isoformat()}" in body
    assert "/courses/invite/" in body and "von Person:" in body


def test_course_name_with_braces_is_not_a_template(client, teacher, mailbox):
    course = teacher.post("/courses", json=course_body(name="Course {link} {0}")).json()
    invite(teacher, course, ["a@x.org"])
    drain(client)
    assert 'join "Course {link} {0}"' in mailbox[0]["body"]


def test_default_body_does_not_repeat_the_footer():
    courses = get_config().courses
    assert "works only once" not in courses.invitation_body
    assert "do not forward" in courses.invitation_footer


@pytest.mark.parametrize("footer, message", [
    ("No link here {course}", "must contain {link}"),
    ("{link} {teacher_password}", "unknown placeholders"),
    ("{link} {link.__class__}", "unknown placeholders"),
    ("{link} {}", "unknown placeholders"),
    ("{link} {unclosed", "not a valid template"),
])
def test_footer_is_validated(footer, message):
    with pytest.raises(ValueError, match=message):
        Config(courses={"invitation_footer": footer})


def test_every_placeholder_is_accepted():
    from app.config import INVITATION_FOOTER_FIELDS
    Config(courses={"invitation_footer": " ".join("{" + f + "}" for f in INVITATION_FOOTER_FIELDS)})



# Mailed tokens: upgrade on sign-in, revoke, reissue, admin links


def unique_address() -> str:
    return f"student-{uuid.uuid4().hex[:8]}@uni.example"


def mailed_token(client, teacher, course, mailbox, address):
    invitation = invite(teacher, course, [address]).json()["invited"][0]
    drain(client)
    message = next(m for m in reversed(mailbox) if m["to"] == [address.lower()])
    return invitation, claim_signed_out(client, code_of(link_in(message))).json()


async def seed_signed_in(email, verified=True):
    from app import database
    async with database.async_session_maker() as db:
        user = User(email=email, name="Student Person", unity_id=f"jsc-{uuid.uuid4()}", email_verified=verified)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user


def sign_in_claims(client, user):
    from app import database
    from app.courses import claim_course_tokens

    async def run():
        async with database.async_session_maker() as db:
            fresh = await db.get(User, user.id)
            return await claim_course_tokens(db, fresh)
    return client.portal.call(run)


def test_verified_sign_in_moves_the_token_to_the_account(client, teacher, course, mailbox):
    address = unique_address()
    invitation, claimed = mailed_token(client, teacher, course, mailbox, address.replace("student", "Student"))
    user = client.portal.call(lambda: seed_signed_in(address))
    assert sign_in_claims(client, user) == 1
    body = validate(client, claimed["token"]).json()
    assert body["valid"] and body["user_id"] == user.id and body["user"]["name"] == "Student Person"
    assert body["course"]["student_id"] == f"user:{user.id}" and body["course"]["student_email"] is None
    listed = teacher.get(f"/courses/{course['id']}/invitations").json()[0]
    assert listed["claimed_by_name"] == "Student Person" and listed["token_status"] == "active"
    assert listed["use_count"] == 1
    assert sign_in_claims(client, user) == 0
    seats = teacher.get(f"/courses/{course['id']}/seats").json()
    assert [seat["student_email"] for seat in seats] == [address]
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 1


def test_unverified_sign_in_does_not_take_the_token(client, teacher, course, mailbox):
    address = unique_address()
    _, claimed = mailed_token(client, teacher, course, mailbox, address)
    user = client.portal.call(lambda: seed_signed_in(address, verified=False))
    assert sign_in_claims(client, user) == 0
    assert validate(client, claimed["token"]).json()["user_id"] is None


def test_student_already_in_the_course_keeps_their_token(client, teacher, course, mailbox):
    address = unique_address()
    _, claimed = mailed_token(client, teacher, course, mailbox, address)
    user = client.portal.call(lambda: seed_signed_in(address))
    session = Session.__new__(Session)
    session.client, session.user_id, session.session = client, user.id, create_session_token(user)
    assert session.post(f"/courses/join/{code_of(course['join_url'])}").status_code == 200
    assert sign_in_claims(client, user) == 0
    assert validate(client, claimed["token"]).json()["user_id"] is None


def test_local_sign_in_runs_the_claim(client, teacher, course, mailbox):
    from app import database
    from app.auth import hash_password

    email = f"local-{uuid.uuid4().hex[:6]}@example.com"
    _, claimed = mailed_token(client, teacher, course, mailbox, email)
    password = "a sufficiently long passphrase 42"

    async def seed():
        async with database.async_session_maker() as db:
            db.add(User(email=email, name="Local Student", password_hash=hash_password(password)))
            await db.commit()

    client.portal.call(seed)
    client.cookies.clear()
    client.cookies.set("csrf_token", "c")
    client.post("/login/local", data={"email": email, "password": password, "csrf_token": "c"},
                follow_redirects=False)
    assert validate(client, claimed["token"]).json()["user"]["name"] == "Local Student"


def test_teacher_revokes_a_mailed_token(client, teacher, course, mailbox):
    invitation, claimed = mailed_token(client, teacher, course, mailbox, unique_address())
    path = f"/courses/{course['id']}/invitations/{invitation['id']}/revoke"
    assert teacher.post(path).json()["tokens_revoked"] == 1
    assert validate(client, claimed["token"]).status_code == 401
    listed = teacher.get(f"/courses/{course['id']}/invitations").json()[0]
    assert listed["token_status"] == "revoked"
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 1
    assert Session(client, teacher=True).post(path).status_code == 404


def test_revoke_follows_a_token_moved_to_an_account(client, teacher, course, mailbox):
    address = unique_address()
    invitation, claimed = mailed_token(client, teacher, course, mailbox, address)
    user = client.portal.call(lambda: seed_signed_in(address))
    sign_in_claims(client, user)
    teacher.post(f"/courses/{course['id']}/invitations/{invitation['id']}/revoke")
    assert validate(client, claimed["token"]).status_code == 401


def test_reissue_replaces_a_lost_token_without_a_new_seat(client, teacher, course, mailbox):
    invitation, claimed = mailed_token(client, teacher, course, mailbox, unique_address())
    path = f"/courses/{course['id']}/invitations/{invitation['id']}/reissue"
    reissued = teacher.post(path, json={"subject": "New token", "body": "Here again"})
    assert reissued.status_code == 200 and reissued.json()["status"] == "open"
    assert validate(client, claimed["token"]).status_code == 401
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 0
    drain(client)
    assert mailbox[-1]["subject"] == "New token"
    again = claim_signed_out(client, code_of(link_in(mailbox[-1])))
    assert again.status_code == 200 and validate(client, again.json()["token"]).status_code == 200
    assert teacher.get(f"/courses/{course['id']}").json()["seats_claimed"] == 1
    assert teacher.post(path, json={"subject": "x", "body": "y"}).json()["send_count"] == 3
    drain(client)
    claim_signed_out(client, code_of(link_in(mailbox[-1])))
    limited = teacher.post(path, json={"subject": "x", "body": "y"})
    assert limited.status_code == 400 and "at most 3 times" in limited.json()["detail"]


def test_reissue_needs_a_used_invitation(client, teacher, course, mailbox):
    invitation = invite(teacher, course, ["a@x.org"]).json()["invited"][0]
    path = f"/courses/{course['id']}/invitations/{invitation['id']}/reissue"
    assert teacher.post(path, json={"subject": "x", "body": "y"}).status_code == 404


def test_admin_sees_unused_links_only_when_enabled(client, teacher, course, mailbox, monkeypatch):
    admin = Session(client, admin=True)
    path = f"/api/admin/courses/{course['id']}/invitations"
    invite(teacher, course, ["off@x.org"])
    assert admin.get(path).json()[0]["link"] is None

    monkeypatch.setattr(get_config().courses, "admin_can_view_invitation_links", True)
    invite(teacher, course, ["on@x.org"])
    drain(client)
    listed = {entry["email"]: entry for entry in admin.get(path).json()}
    link = listed["on@x.org"]["link"]
    assert link == link_in(next(m for m in mailbox if m["to"] == ["on@x.org"]))
    assert listed["off@x.org"]["link"] is None
    assert "link" not in teacher.get(f"/courses/{course['id']}/invitations").json()[0]

    claim_signed_out(client, code_of(link))
    assert {e["email"]: e for e in admin.get(path).json()}["on@x.org"]["link"] is None
    assert teacher.get(path).status_code == 403


def test_closing_clears_kept_links(client, teacher, course, mailbox, monkeypatch):
    monkeypatch.setattr(get_config().courses, "admin_can_view_invitation_links", True)
    invite(teacher, course, ["a@x.org"])
    teacher.post(f"/courses/{course['id']}/close")
    stored = client.portal.call(lambda: fetch(select(CourseInvitation)))
    assert all(invitation.link is None for invitation in stored)


def test_mailed_token_footer_explains_no_sign_in(client, teacher, course, mailbox):
    invite(teacher, course, ["a@x.org"])
    drain(client)
    assert "no sign-in is needed" in mailbox[0]["body"]
