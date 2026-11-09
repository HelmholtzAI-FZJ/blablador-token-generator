"""Applications and application-owned tokens.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-09
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "applications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1000), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_applications_user_id", "applications", ["user_id"])
    with op.batch_alter_table("tokens") as batch:
        batch.add_column(sa.Column("application_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_tokens_application_id", "applications", ["application_id"], ["id"], ondelete="CASCADE"
        )
        batch.create_index("ix_tokens_application_id", ["application_id"])


def downgrade() -> None:
    with op.batch_alter_table("tokens") as batch:
        batch.drop_index("ix_tokens_application_id")
        batch.drop_constraint("fk_tokens_application_id", type_="foreignkey")
        batch.drop_column("application_id")
    op.drop_table("applications")
