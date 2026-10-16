"""Index tokens by owner.

Token listing, quota checks and account deletion filter by user_id.
Databases adopted at 0001 may also lack the revocation expiry index, which
was added shortly before migrations existed.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Build without blocking token writes. An interrupted concurrent
        # build leaves an invalid index behind, which is dropped and rebuilt.
        with op.get_context().autocommit_block():
            for index, table, column in (("ix_tokens_user_id", "tokens", "user_id"),
                                         ("ix_revoked_jwts_expires_at", "revoked_jwts", "expires_at")):
                invalid = bind.scalar(sa.text(
                    "SELECT NOT indisvalid FROM pg_index WHERE indexrelid = to_regclass(:index)"
                ), {"index": index})
                if invalid:
                    op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {index}")
                op.execute(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {index} ON {table} ({column})")
    else:
        op.create_index("ix_tokens_user_id", "tokens", ["user_id"], if_not_exists=True)
        op.create_index("ix_revoked_jwts_expires_at", "revoked_jwts", ["expires_at"], if_not_exists=True)

    # IF NOT EXISTS keeps a same-named index with another definition.
    indexes = {index["name"]: index for index in sa.inspect(bind).get_indexes("tokens")}
    owner = indexes.get("ix_tokens_user_id")
    if owner is None or owner["column_names"] != ["user_id"] or owner["unique"]:
        raise RuntimeError("Existing ix_tokens_user_id has an unexpected definition; review it before migrating")


def downgrade() -> None:
    op.drop_index("ix_tokens_user_id", table_name="tokens")
