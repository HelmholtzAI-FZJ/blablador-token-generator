import argparse
import asyncio
import ssl

from app.config import get_config
from app.database import (
    MIGRATION_STATEMENT_TIMEOUT_SECONDS, build_engine, migrate_token_owner_index,
)


async def apply_migration() -> None:
    config = get_config()
    connect_args = {}
    if config.database.url.startswith("postgresql") and config.database.ssl_ca_file:
        connect_args["ssl"] = ssl.create_default_context(cafile=config.database.ssl_ca_file)
    engine = build_engine(config.database.url, migration=True,
                          hide_parameters=True, connect_args=connect_args)
    try:
        await migrate_token_owner_index(engine)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add ix_tokens_user_id to an existing token service database."
    )
    parser.add_argument("--apply", action="store_true", help="Apply the reviewed index migration")
    args = parser.parse_args()
    if not args.apply:
        parser.exit(message=(
            "Plan: create ix_tokens_user_id on tokens(user_id); PostgreSQL uses CONCURRENTLY. "
            f"Migration statements are limited to {MIGRATION_STATEMENT_TIMEOUT_SECONDS} seconds; "
            "configured connection and lock deadlines still apply. "
            "No rows or credentials change. Run with --apply using the intended migration "
            "database credentials after reviewing the target configuration.\n"
        ))
    try:
        asyncio.run(apply_migration())
    except Exception:
        parser.exit(status=1, message=(
            "Index migration failed. Check database availability, migration role permissions "
            "and existing index validity; configuration values were not printed.\n"
        ))
    print("Token owner index migration completed.")


if __name__ == "__main__":
    main()
