"""Expiry warnings for tokens that are about to expire.

Run by `python -m app.manage notify-expiring-tokens`, normally from a daily
CronJob: the service has no scheduler, and every worker would otherwise send
its own copy. One message per threshold and token; the threshold reached is
recorded on the token so the next run does not repeat it.

Only tokens whose owner can still be reached are mailed: an application token
goes to its owners who have signed in, plus its creator while that account
exists. A token with no reachable recipient is skipped and logged, never sent
to the administrators instead.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import ceil

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import normalize_email
from app.config import get_config
from app.mailer import send_mail
from app.models import Application, ApplicationMember, ROLE_OWNER, Token, User
from app.timeutil import utcnow

logger = logging.getLogger("token_generator.audit")


class NotificationError(Exception):
    pass


@dataclass
class ReminderResult:
    scanned: int = 0
    sent: int = 0
    would_send: int = 0
    skipped: int = 0
    failed: int = 0
    sent_to: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (f"scanned {self.scanned}, sent {self.sent}, would send {self.would_send}, "
                f"skipped {self.skipped}, failed {self.failed}")


def threshold_for(days_left: float, warning_days: list[int]) -> int | None:
    """The tightest configured threshold the token has reached, if any.

    With 30/7/1 days, a token 20 days from expiry reports 30 and one 12 hours
    from expiry reports 1. None means it is further out than every threshold.
    """
    for threshold in sorted(warning_days):
        if days_left <= threshold:
            return threshold
    return None


async def recipients_for(db: AsyncSession, token: Token) -> list[str]:
    emails: list[str] = []
    if token.user_id:
        user = await db.get(User, token.user_id)
        if user is not None:
            emails.append(user.email)
    else:
        owners = (await db.execute(
            select(User.email)
            .join(ApplicationMember, ApplicationMember.user_id == User.id)
            .where(
                ApplicationMember.application_id == token.application_id,
                ApplicationMember.role == ROLE_OWNER,
            )
        )).scalars().all()
        emails.extend(owners)
        if token.created_by_id:
            creator = await db.get(User, token.created_by_id)
            if creator is not None:
                emails.append(creator.email)
    return sorted({normalize_email(email) for email in emails if email})


async def pending_tokens(db: AsyncSession, now: datetime) -> list[Token]:
    config = get_config().notifications
    warning_days = sorted(config.warning_days)
    tightest = warning_days[0]
    query = (
        select(Token)
        .where(
            Token.expires_at.isnot(None),
            Token.revoked_at.is_(None),
            Token.expires_at > now,
            Token.expires_at <= now + timedelta(days=max(warning_days)),
            # Warned at the tightest threshold already: nothing left to say.
            or_(Token.expiry_notified_days.is_(None), Token.expiry_notified_days > tightest),
        )
        .order_by(Token.expires_at)
        .limit(config.batch_size)
    )
    return list((await db.execute(query)).scalars().all())


async def _message(db: AsyncSession, token: Token, days_left: float) -> tuple[str, str]:
    app_config = get_config()
    remaining = max(1, ceil(days_left))
    application = (
        await db.get(Application, token.application_id) if token.application_id else None
    )
    plural = "s" if remaining != 1 else ""
    subject = f"{app_config.app.name}: token \"{token.name}\" expires in {remaining} day{plural}"
    described = (f'The Blablador token "{token.name}" of application "{application.name}"'
                 if application is not None else f'The Blablador token "{token.name}"')
    expires_at = token.expires_at
    date = f"{expires_at.day} {expires_at.strftime('%B %Y')} at {expires_at.strftime('%H:%M')} UTC"
    body = (
        "Dear user,\n\n"
        f"{described} will expire in {remaining} day{plural}, on {date}.\n\n"
        "To keep using it, renew it here:\n"
        f"{app_config.app.api_url.rstrip('/')}/dashboard\n\n"
        "Kind regards,\n"
        "Blablador Team\n"
    )
    return subject, body


async def send_expiry_reminders(db: AsyncSession, *, dry_run: bool = False) -> ReminderResult:
    config = get_config()
    if not config.notifications.expiry_reminders:
        raise NotificationError("notifications.expiry_reminders is false; enable it first")
    if not config.smtp.enabled:
        raise NotificationError("smtp is not enabled, so no reminder could be sent")

    now = utcnow()
    result = ReminderResult()
    for candidate in await pending_tokens(db, now):
        result.scanned += 1
        # A second job (or an operator) may be handling this token right now.
        token = (await db.execute(
            select(Token).where(Token.id == candidate.id).with_for_update(skip_locked=True)
        )).scalar_one_or_none()
        if token is None:
            continue
        days_left = (token.expires_at - now).total_seconds() / 86400
        threshold = threshold_for(days_left, config.notifications.warning_days)
        if threshold is None or (
            token.expiry_notified_days is not None and token.expiry_notified_days <= threshold
        ):
            continue
        recipients = await recipients_for(db, token)
        if not recipients:
            result.skipped += 1
            logger.warning("action=expiry_reminder_skipped token_id=%s reason=no_recipients", token.id)
            continue
        if dry_run:
            result.would_send += 1
            continue
        subject, body = await _message(db, token, days_left)
        if not await send_mail(recipients, subject, body):
            result.failed += 1
            continue
        token.expiry_notified_days = threshold
        token.expiry_notified_at = now
        await db.commit()
        result.sent += 1
        result.sent_to.append(token.id)
        logger.info("action=expiry_reminder_sent token_id=%s threshold_days=%s recipients=%s",
                    token.id, threshold, len(recipients))
    return result
