"""Initial schema, as created by releases before migrations existed.

Databases created by those releases (October 2026) are adopted at this
revision without running it; see app.migrate.

Revision ID: 0001
Revises:
Create Date: 2026-10-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("unity_id", sa.String(255), nullable=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("session_epoch", sa.Integer(), nullable=False),
    )
    op.create_index("ix_users_unity_id", "users", ["unity_id"], unique=True)
    op.create_index("ix_users_email", "users", ["email"])
    # Local accounts sign in by email; OAuth accounts are identified by subject.
    op.create_index(
        "uq_users_local_email", "users", ["email"], unique=True,
        sqlite_where=sa.text("unity_id IS NULL"),
        postgresql_where=sa.text("unity_id IS NULL"),
    )

    op.create_table(
        "tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_tokens_token_hash", "tokens", ["token_hash"], unique=True)

    op.create_table(
        "revoked_jwts",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_revoked_jwts_user_id", "revoked_jwts", ["user_id"])
    op.create_index("ix_revoked_jwts_expires_at", "revoked_jwts", ["expires_at"])

    op.create_table(
        "deleted_users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("unity_id_hash", sa.String(64), nullable=True),
        sa.Column("email_hash", sa.String(64), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_deleted_users_unity_id_hash", "deleted_users", ["unity_id_hash"])
    op.create_index("ix_deleted_users_email_hash", "deleted_users", ["email_hash"])


def downgrade() -> None:
    for table in ("deleted_users", "revoked_jwts", "tokens", "users"):
        op.drop_table(table)
