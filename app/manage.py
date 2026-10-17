"""Operator commands, run where the service's configuration is available
(for example with kubectl exec in an application pod).

    python -m app.manage create-local-admin --email admin@example.org --name "Admin"
    python -m app.manage grant-admin --subject <OAuth subject>
    python -m app.manage grant-admin --user-id <user id>

create-local-admin reads the password from the terminal, or from standard
input with --password-stdin. Both commands write an audit event; inside the
service's container it also goes to the container log, where exec'd
commands' own output does not.
"""
import argparse
import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path
from typing import TextIO

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from app import database
from app.api.admin import CreateUserRequest
from app.auth import hash_password_async, invalidate_sessions, validate_password_strength
from app.config import get_config
from app.logging_config import APP_LOGGER, configure_logging
from app.models import User
from app.tombstones import is_user_deleted, lift_deletions_for_email
from app.validation import has_unsafe_characters

logger = logging.getLogger("token_generator.audit")


class CommandError(Exception):
    pass


async def create_local_admin(email: str, name: str, password: str) -> str:
    # The same checks as creating a local account in the admin panel.
    try:
        validate_password_strength(password)
        request = CreateUserRequest(email=email.strip(), name=name, password=password, is_admin=True)
    except ValidationError as error:
        raise CommandError("; ".join(
            f"{item['loc'][-1]}: {item['msg']}" for item in error.errors(include_input=False, include_url=False)
        )) from None
    except HTTPException as error:
        raise CommandError(error.detail) from None
    email, name = request.email, request.name
    password_hash = await hash_password_async(password)
    async with database.async_session_maker() as db:
        existing = await db.execute(select(User).where(User.email == email, User.unity_id.is_(None)))
        if existing.scalar_one_or_none() is not None:
            raise CommandError("A local account with this email already exists")
        await lift_deletions_for_email(db, email)
        user = User(email=email, name=name, password_hash=password_hash, is_admin=True, unity_id=None)
        db.add(user)
        await db.commit()
        logger.info("actor=cli action=create_local_admin user_id=%s", user.id)
        return user.id


async def grant_admin(*, user_id: str | None = None, subject: str | None = None) -> str:
    # Never let an empty value select by "unity_id IS NULL" (local accounts).
    if bool(user_id) == bool(subject):
        raise CommandError("Give exactly one non-empty --user-id or --subject")
    async with database.async_session_maker() as db:
        condition = User.id == user_id if user_id else User.unity_id == subject
        user = (await db.execute(select(User).where(condition).with_for_update())).scalar_one_or_none()
        if user is None:
            raise CommandError("No such account; OAuth users must have signed in once")
        if await is_user_deleted(db, user):
            raise CommandError("This account is disabled; restore it first")
        if not user.is_admin:
            user.is_admin = True
            # Like a role change in the admin UI: existing sessions end.
            await invalidate_sessions(user, db)
            await db.commit()
            logger.info("actor=cli action=grant_admin user_id=%s", user.id)
        return user.id


def container_log_stream(main_process: Path = Path("/proc/1")) -> TextIO | None:
    """The service's own stderr, if this runs inside its container.

    Output of kubectl/docker exec goes to the operator's terminal only;
    the container log (and with it central logging) is the stderr of the
    container's main process.
    """
    if os.getpid() == 1:
        return None
    try:
        command = (main_process / "cmdline").read_bytes()
        if b"uvicorn" not in command or b"app.main:app" not in command:
            return None
        return open(main_process / "fd" / "2", "a", buffering=1)
    except OSError:
        return None


def copy_events_to_container_log() -> None:
    stream = container_log_stream()
    if stream is not None:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logging.getLogger(APP_LOGGER).addHandler(handler)


def read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    password = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != password:
        raise CommandError("Passwords do not match")
    return password


async def run(args: argparse.Namespace) -> str:
    await database.init_db()
    try:
        if args.command == "create-local-admin":
            if not get_config().local.enabled:
                print("Note: local.enabled is false, so this account cannot sign in yet.", file=sys.stderr)
            user_id = await create_local_admin(args.email, args.name, read_password(args.password_stdin))
            return f"Created local administrator {user_id}"
        user_id = await grant_admin(user_id=args.user_id, subject=args.subject)
        return f"Account {user_id} is an administrator"
    finally:
        await database.close_db()


def non_empty(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    if has_unsafe_characters(value):
        raise argparse.ArgumentTypeError("must not contain control characters")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.manage", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-local-admin", help="create a local (password) administrator")
    create.add_argument("--email", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    grant = commands.add_parser("grant-admin", help="make an existing account an administrator")
    target = grant.add_mutually_exclusive_group(required=True)
    target.add_argument("--user-id", type=non_empty)
    target.add_argument("--subject", type=non_empty, help="OAuth subject of an account that has signed in")
    args = parser.parse_args()
    configure_logging(get_config().app.log_level)
    copy_events_to_container_log()
    try:
        print(asyncio.run(run(args)))
    except CommandError as error:
        parser.exit(status=1, message=f"Error: {error}\n")


if __name__ == "__main__":
    main()
