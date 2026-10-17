"""Operator commands: creating a local administrator and granting the role."""
import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import select

from app import database, manage
from app.auth import authenticate_local_user, create_session_token
from app.models import User
from app.tombstones import record_deletion
from tests.conftest import drop_schema

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "operator-chosen-passphrase"


def run(coroutine_function):
    """Each test runs on one event loop with its own engine (asyncpg
    connections cannot cross loops)."""
    async def wrapper():
        await database.init_db()
        try:
            return await coroutine_function()
        finally:
            async with database.engine.begin() as conn:
                await drop_schema(conn)
            await database.close_db()
    return asyncio.run(wrapper())


def test_create_local_admin_can_sign_in():
    async def scenario():
        user_id = await manage.create_local_admin(" Ops@Example.org ", "Operator", PASSWORD)
        async with database.async_session_maker() as db:
            user = await authenticate_local_user("ops@example.org", PASSWORD, db)
            assert user is not None and user.id == user_id and user.is_admin
            with pytest.raises(manage.CommandError, match="already exists"):
                await manage.create_local_admin("ops@example.org", "Again", PASSWORD)
    run(scenario)


@pytest.mark.parametrize("password, message", [
    ("short", "at least 15"),
    ("passwordpassword", "commonly used"),
])
def test_create_local_admin_enforces_password_policy(password, message):
    async def scenario():
        with pytest.raises(manage.CommandError, match=message):
            await manage.create_local_admin("weak@example.org", "Weak", password)
    run(scenario)


def test_create_local_admin_lifts_local_deletion_record():
    async def scenario():
        async with database.async_session_maker() as db:
            record_deletion(db, User(email="returning@example.org", name="Gone"))
            await db.commit()
        await manage.create_local_admin("returning@example.org", "Back", PASSWORD)
        async with database.async_session_maker() as db:
            assert await authenticate_local_user("returning@example.org", PASSWORD, db) is not None
    run(scenario)


def test_grant_admin_by_subject_ends_existing_sessions():
    async def scenario():
        async with database.async_session_maker() as db:
            user = User(email="oauth@example.org", name="OAuth", unity_id="subject-42")
            db.add(user)
            await db.commit()
            old_session = create_session_token(user)
        user_id = await manage.grant_admin(subject="subject-42")
        async with database.async_session_maker() as db:
            user = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
            assert user.is_admin and user.session_epoch == 1
        assert old_session
        with pytest.raises(manage.CommandError, match="No such account"):
            await manage.grant_admin(subject="never-signed-in")
    run(scenario)


def test_grant_admin_refuses_disabled_accounts():
    async def scenario():
        async with database.async_session_maker() as db:
            user = User(email="disabled@example.org", name="Disabled", unity_id="disabled-subject")
            db.add(user)
            record_deletion(db, user)
            await db.commit()
        with pytest.raises(manage.CommandError, match="disabled"):
            await manage.grant_admin(subject="disabled-subject")
    run(scenario)


def test_command_line(tmp_path):
    env = {**os.environ, "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path}/manage.db"}
    created = subprocess.run(
        [sys.executable, "-m", "app.manage", "create-local-admin", "--email", "cli@example.org",
         "--name", "CLI", "--password-stdin"],
        input=PASSWORD + "\n", cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert created.returncode == 0, created.stderr
    assert created.stdout.startswith("Created local administrator ")
    assert PASSWORD not in created.stdout + created.stderr
    assert "action=create_local_admin" in created.stderr
    missing = subprocess.run(
        [sys.executable, "-m", "app.manage", "grant-admin", "--subject", "nobody"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert missing.returncode == 1 and "No such account" in missing.stderr


def test_grant_admin_never_selects_by_missing_subject():
    async def scenario():
        async with database.async_session_maker() as db:
            db.add(User(email="local@example.org", name="Local", password_hash="x"))
            await db.commit()
        for kwargs in ({"user_id": ""}, {"subject": ""}, {}, {"user_id": "a", "subject": "b"}):
            with pytest.raises(manage.CommandError, match="exactly one"):
                await manage.grant_admin(**kwargs)
        async with database.async_session_maker() as db:
            local = (await db.execute(select(User).where(User.email == "local@example.org"))).scalar_one()
            assert local.is_admin is False
    run(scenario)


@pytest.mark.parametrize("email, name, message", [
    ("ops\u0000@example.org", "Operator", "email"),
    ("no-at-sign.example.org", "Operator", "email"),
    ("x" * 250 + "@example.org", "Operator", "email"),
    ("ops@example.org", "", "name"),
    ("ops@example.org", "n" * 256, "name"),
])
def test_create_local_admin_validates_like_the_admin_panel(email, name, message):
    async def scenario():
        with pytest.raises(manage.CommandError, match=message) as error:
            await manage.create_local_admin(email, name, PASSWORD)
        assert PASSWORD not in str(error.value)
    run(scenario)


def test_empty_command_line_values_are_rejected(tmp_path):
    env = {**os.environ, "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path}/empty.db"}
    result = subprocess.run([sys.executable, "-m", "app.manage", "grant-admin", "--user-id", ""],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 2 and "must not be empty" in result.stderr


def test_events_go_to_the_service_log_inside_its_container(tmp_path):
    main_process = tmp_path / "proc1"
    (main_process / "fd").mkdir(parents=True)
    (main_process / "fd" / "2").write_text("")
    (main_process / "cmdline").write_bytes(b"/opt/venv/bin/python\x00/opt/venv/bin/uvicorn\x00app.main:app\x00")
    stream = manage.container_log_stream(main_process)
    assert stream is not None
    stream.write("event\n")
    stream.close()
    assert (main_process / "fd" / "2").read_text() == "event\n"
    (main_process / "cmdline").write_bytes(b"/sbin/init\x00")
    assert manage.container_log_stream(main_process) is None
    assert manage.container_log_stream(tmp_path / "missing") is None
