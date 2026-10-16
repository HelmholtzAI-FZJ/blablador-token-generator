"""Operator commands, run where the service's configuration is available
(for example with kubectl exec in an application pod).

    python -m app.manage create-local-admin --email admin@example.org --name "Admin"
    python -m app.manage grant-admin --subject <OAuth subject>
    python -m app.manage grant-admin --user-id <user id>

create-local-admin reads the password from the terminal, or from standard
input with --password-stdin. Both commands are written to the audit log.
"""
import argparse
import asyncio
import getpass
import logging
import sys

from fastapi import HTTPException
from sqlalchemy import select

from app import database
from app.auth import hash_password_async, invalidate_sessions, normalize_email, validate_password_strength
from app.config import get_config
from app.logging_config import configure_logging
from app.models import User
from app.tombstones import is_user_deleted, lift_deletions_for_email

logger = logging.getLogger("token_generator.audit")


class CommandError(Exception):
    pass


async def create_local_admin(email: str, name: str, password: str) -> str:
    email = normalize_email(email)
    if email.count("@") != 1 or not all(email.split("@")) or any(c.isspace() for c in email):
        raise CommandError("Invalid email address")
    try:
        validate_password_strength(password)
    except HTTPException as error:
        raise CommandError(error.detail) from None
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


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.manage", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-local-admin", help="create a local (password) administrator")
    create.add_argument("--email", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    grant = commands.add_parser("grant-admin", help="make an existing account an administrator")
    target = grant.add_mutually_exclusive_group(required=True)
    target.add_argument("--user-id")
    target.add_argument("--subject", help="OAuth subject of an account that has signed in")
    args = parser.parse_args()
    configure_logging(get_config().app.log_level)
    try:
        print(asyncio.run(run(args)))
    except CommandError as error:
        parser.exit(status=1, message=f"Error: {error}\n")


if __name__ == "__main__":
    main()
