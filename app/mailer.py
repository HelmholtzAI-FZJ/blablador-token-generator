"""Outgoing mail (smtp settings). Sending never fails the request that
triggered it: failures are logged and the message is dropped."""
import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import get_config

logger = logging.getLogger("token_generator.audit")

# Sends in flight, kept referenced until done.
_pending: set[asyncio.Task] = set()


def _send(recipients: list[str], subject: str, body: str) -> None:
    smtp = get_config().smtp
    message = EmailMessage()
    message["From"] = smtp.from_address
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    if smtp.use_tls:
        client = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=smtp.timeout_seconds, context=context)
    else:
        client = smtplib.SMTP(smtp.host, smtp.port, timeout=smtp.timeout_seconds)
    with client:
        if smtp.starttls:
            client.starttls(context=context)
        if smtp.username:
            client.login(smtp.username, smtp.password)
        client.send_message(message)


async def send_mail(recipients: list[str], subject: str, body: str) -> bool:
    """Send one message; False when mail is disabled or sending failed."""
    if not get_config().smtp.enabled or not recipients:
        return False
    try:
        await asyncio.to_thread(_send, recipients, subject, body)
    except Exception as exc:
        logger.error("action=mail_failed recipients=%d error_type=%s", len(recipients), type(exc).__name__)
        return False
    logger.info("action=mail_sent recipients=%d", len(recipients))
    return True


def send_mail_later(recipients: list[str], subject: str, body: str) -> None:
    """Send in the background, so a slow mail server does not hold up a response."""
    task = asyncio.get_running_loop().create_task(send_mail(recipients, subject, body))
    _pending.add(task)
    task.add_done_callback(_pending.discard)
