"""Course users: accounts created by using a mailed course invitation.

They own their course tokens, cannot sign in and never get a password or a
role. Compatible with 1.3.x instances during a rolling upgrade: the column
has a server default and those instances never read it.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-27
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column(
            "is_course_user", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("is_course_user")
