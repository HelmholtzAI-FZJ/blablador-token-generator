"""Expiry reminders: thresholds, recipients, and one mail per threshold."""
import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest
from starlette.requests import Request

from app import database, notifications
from app.api.tokens import RenewTokenRequest, renew_token, rotate_token
from app.auth import hash_token
from app.config import get_config
from app.models import Application, ApplicationMember, ROLE_MEMBER, ROLE_OWNER, Token, User
from app.notifications import NotificationError, send_expiry_reminders, threshold_for
from app.timeutil import utcnow
from tests.conftest import drop_schema


def request() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [],
                    "query_string": b"", "client": ("127.0.0.11", 0)})


def run(scenario):
    async def wrapper():
        await database.init_db()
        try:
            return await scenario()
        finally:
            async with database.engine.begin() as conn:
                await drop_schema(conn)
            await database.close_db()
    return asyncio.run(wrapper())


def enable(monkeypatch):
    monkeypatch.setattr(get_config().notifications, "expiry_reminders", True)
    monkeypatch.setattr(get_config().smtp, "enabled", True)


def recorder(sent):
    async def fake(recipients, subject, body):
        sent.append({"recipients": recipients, "subject": subject, "body": body})
        return True
    return fake


async def add_user(db, email, name="Person"):
    user = User(unity_id=f"sub-{email}-{uuid4()}", email=email, name=name)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def add_token(db, *, user=None, application=None, created_by=None, days=20, name="deploy"):
    token = Token(
        user_id=user.id if user else None,
        application_id=application.id if application else None,
        created_by_id=created_by.id if created_by else None,
        token_hash=hash_token(f"{name}-{uuid4()}"),
        name=name,
        expires_at=None if days is None else utcnow() + timedelta(days=days),
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token


async def add_application(db, name="Pipeline"):
    application = Application(name=name)
    db.add(application)
    await db.commit()
    await db.refresh(application)
    return application


def test_thresholds_are_the_tightest_reached():
    assert threshold_for(20, [30, 7, 1]) == 30
    assert threshold_for(7, [30, 7, 1]) == 7
    assert threshold_for(6.9, [30, 7, 1]) == 7
    assert threshold_for(0.5, [30, 7, 1]) == 1
    assert threshold_for(30.1, [30, 7, 1]) is None
    assert threshold_for(5, [10]) == 10
    assert threshold_for(11, [10]) is None


def test_personal_token_is_mailed_once_per_threshold(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            user = await add_user(db, "A.Owner@Example.org")
            token = await add_token(db, user=user, days=20)

            first = await send_expiry_reminders(db)
            assert first.sent == 1 and first.scanned == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 30
            assert token.expiry_notified_at is not None
            assert sent[0]["recipients"] == ["a.owner@example.org"]

            again = await send_expiry_reminders(db)
            assert again.sent == 0

            token.expires_at = utcnow() + timedelta(days=5)
            await db.commit()
            second = await send_expiry_reminders(db)
            assert second.sent == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 7

            token.expires_at = utcnow() + timedelta(hours=12)
            await db.commit()
            third = await send_expiry_reminders(db)
            assert third.sent == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 1

            fourth = await send_expiry_reminders(db)
            assert fourth.sent == 0

    run(scenario)
    assert len(sent) == 3
    assert "in 1 day" in sent[-1]["subject"]


def test_renew_starts_a_new_warning_cycle(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            user = await add_user(db, "renew@example.org")
            token = await add_token(db, user=user, days=1)

            first = await send_expiry_reminders(db)
            assert first.sent == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 1

            await renew_token.__wrapped__(request(), token.id, None, user, db)
            await db.refresh(token)
            assert token.expiry_notified_days is None
            assert token.expiry_notified_at is None

            again = await send_expiry_reminders(db)
            assert again.sent == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 1

    run(scenario)
    assert len(sent) == 2


def test_rotate_keeps_the_warning_state_unless_the_expiry_changes(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            user = await add_user(db, "rotate@example.org")
            token = await add_token(db, user=user, days=1)

            assert (await send_expiry_reminders(db)).sent == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 1

            await rotate_token.__wrapped__(request(), token.id, None, user, db)
            await db.refresh(token)
            assert token.expiry_notified_days == 1
            assert (await send_expiry_reminders(db)).sent == 0

            await rotate_token.__wrapped__(
                request(), token.id, RenewTokenRequest(expires_in_days=20), user, db)
            await db.refresh(token)
            assert token.expiry_notified_days is None

            again = await send_expiry_reminders(db)
            assert again.sent == 1
            await db.refresh(token)
            assert token.expiry_notified_days == 30

    run(scenario)
    assert len(sent) == 2


def test_application_token_mails_signed_in_owners_and_creator(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            application = await add_application(db)
            owner = await add_user(db, "owner@example.org")
            creator = await add_user(db, "creator@example.org")
            member = await add_user(db, "member@example.org")
            db.add_all([
                ApplicationMember(application_id=application.id, user_id=owner.id,
                                  email=owner.email, role=ROLE_OWNER),
                ApplicationMember(application_id=application.id, user_id=member.id,
                                  email=member.email, role=ROLE_MEMBER),
                # An invitation nobody accepted is not mailed yet.
                ApplicationMember(application_id=application.id, user_id=None,
                                  email="invited@example.org", role=ROLE_OWNER),
            ])
            await db.commit()
            await add_token(db, application=application, created_by=creator, days=6)

            result = await send_expiry_reminders(db)
            assert result.sent == 1
            assert sent[0]["recipients"] == ["creator@example.org", "owner@example.org"]
            assert "Pipeline" in sent[0]["body"]

    run(scenario)


def test_token_without_recipient_is_skipped_and_not_recorded(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            application = await add_application(db, name="Orphan")
            token = await add_token(db, application=application, days=3)

            result = await send_expiry_reminders(db)
            assert result.sent == 0 and result.skipped == 1
            await db.refresh(token)
            assert token.expiry_notified_days is None

    run(scenario)
    assert sent == []


def test_dry_run_reports_without_sending(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            user = await add_user(db, "dry@example.org")
            token = await add_token(db, user=user, days=2)
            result = await send_expiry_reminders(db, dry_run=True)
            assert result.would_send == 1 and result.sent == 0
            await db.refresh(token)
            assert token.expiry_notified_days is None

    run(scenario)
    assert sent == []


def test_uninteresting_tokens_are_not_scanned(monkeypatch):
    enable(monkeypatch)
    sent = []
    monkeypatch.setattr(notifications, "send_mail", recorder(sent))

    async def scenario():
        async with database.async_session_maker() as db:
            user = await add_user(db, "quiet@example.org")
            far = await add_token(db, user=user, days=90)
            revoked = await add_token(db, user=user, days=3)
            revoked.revoked_at = utcnow()
            await db.commit()
            await add_token(db, user=user, days=None)
            await add_token(db, user=user, days=-1)

            result = await send_expiry_reminders(db)
            assert result.scanned == 0 and result.sent == 0
            await db.refresh(far)
            assert far.expiry_notified_days is None

    run(scenario)


def test_refuses_to_run_without_mail_or_consent(monkeypatch):
    async def scenario():
        async with database.async_session_maker() as db:
            monkeypatch.setattr(get_config().notifications, "expiry_reminders", False)
            monkeypatch.setattr(get_config().smtp, "enabled", True)
            with pytest.raises(NotificationError, match="expiry_reminders is false"):
                await send_expiry_reminders(db)

            monkeypatch.setattr(get_config().notifications, "expiry_reminders", True)
            monkeypatch.setattr(get_config().smtp, "enabled", False)
            with pytest.raises(NotificationError, match="smtp is not enabled"):
                await send_expiry_reminders(db)

    run(scenario)
