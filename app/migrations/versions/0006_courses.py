"""Courses: teachers, courses, seats and course tokens.

Compatible with 1.3.x instances during a rolling upgrade: every new column is
nullable or has a server default, and those instances reject course tokens
(blablador-course-...) as malformed, so they fail closed.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-26
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column(
            "is_teacher", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ))

    op.create_table(
        "courses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("teacher_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("starts_at", sa.DateTime(), nullable=False),
        sa.Column("ends_at", sa.DateTime(), nullable=False),
        sa.Column("max_seats", sa.Integer(), nullable=False),
        sa.Column("seats_claimed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("join_code_hash", sa.String(64), nullable=True, unique=True),
        sa.Column("terms_version", sa.String(32), nullable=False),
        sa.Column("terms_accepted_at", sa.DateTime(), nullable=False),
        sa.Column("suspended_at", sa.DateTime(), nullable=True),
        sa.Column("suspended_reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("seats_claimed >= 0 AND seats_claimed <= max_seats", name="ck_courses_seats"),
        sa.CheckConstraint("ends_at > starts_at", name="ck_courses_dates"),
    )
    op.create_index("ix_courses_teacher_id", "courses", ["teacher_id"])
    op.create_index("ix_courses_ends_at", "courses", ["ends_at"])

    op.create_table(
        "course_seats",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("course_id", sa.String(36), sa.ForeignKey("courses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("course_id", "user_id", name="uq_course_seats_user"),
    )
    op.create_index("ix_course_seats_course_id", "course_seats", ["course_id"])
    op.create_index("ix_course_seats_user_id", "course_seats", ["user_id"])

    with op.batch_alter_table("tokens") as batch:
        batch.add_column(sa.Column("course_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("use_count", sa.Integer(), nullable=False, server_default=sa.text("0")))
        batch.create_foreign_key("fk_tokens_course_id", "courses", ["course_id"], ["id"], ondelete="CASCADE")
        batch.create_index("ix_tokens_course_id", ["course_id"])


def downgrade() -> None:
    op.execute("DELETE FROM tokens WHERE course_id IS NOT NULL")
    with op.batch_alter_table("tokens") as batch:
        batch.drop_index("ix_tokens_course_id")
        batch.drop_constraint("fk_tokens_course_id", type_="foreignkey")
        batch.drop_column("use_count")
        batch.drop_column("course_id")
    op.drop_table("course_seats")
    op.drop_table("courses")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("is_teacher")
