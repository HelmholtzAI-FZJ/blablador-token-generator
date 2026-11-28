"""Course tokens mailed to invited addresses; links kept for admins.

A token may now belong to a course invitation instead of a user or an
application: students who get their token by mail need no account. The
owner check becomes "exactly one of user, application, invitation".

Compatible with 1.3.x instances during a rolling upgrade: they reject course
tokens as malformed and never create invitation tokens.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-26
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

OWNER_CHECK = (
    "(CASE WHEN user_id IS NULL THEN 0 ELSE 1 END)"
    " + (CASE WHEN application_id IS NULL THEN 0 ELSE 1 END)"
    " + (CASE WHEN course_invitation_id IS NULL THEN 0 ELSE 1 END) = 1"
)


def upgrade() -> None:
    with op.batch_alter_table("course_invitations") as batch:
        batch.add_column(sa.Column("link", sa.String(512), nullable=True))
    with op.batch_alter_table("tokens") as batch:
        batch.add_column(sa.Column("course_invitation_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_tokens_course_invitation_id", "course_invitations", ["course_invitation_id"], ["id"],
            ondelete="CASCADE",
        )
        batch.create_index("ix_tokens_course_invitation_id", ["course_invitation_id"])
        batch.drop_constraint("ck_tokens_owner", type_="check")
        batch.create_check_constraint("ck_tokens_owner", OWNER_CHECK)


def downgrade() -> None:
    op.execute("DELETE FROM tokens WHERE course_invitation_id IS NOT NULL")
    with op.batch_alter_table("tokens") as batch:
        batch.drop_constraint("ck_tokens_owner", type_="check")
        batch.create_check_constraint("ck_tokens_owner", "(user_id IS NULL) <> (application_id IS NULL)")
        batch.drop_index("ix_tokens_course_invitation_id")
        batch.drop_constraint("fk_tokens_course_invitation_id", type_="foreignkey")
        batch.drop_column("course_invitation_id")
    with op.batch_alter_table("course_invitations") as batch:
        batch.drop_column("link")
