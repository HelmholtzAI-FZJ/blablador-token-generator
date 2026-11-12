"""Shared applications: owners, members and invitations.

Applications lose their single owner column: their current owners become
"owner" members. Application tokens no longer belong to the person who
created them (user_id) but record them in created_by_id, so they survive
that person leaving. Applications whose last owner left are marked
orphaned for an admin to take over.

Not compatible with 1.1.0 instances reading applications during a rolling
upgrade; applications were not in use yet.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-12
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column(
            "email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ))

    op.create_table(
        "application_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("application_id", sa.String(36),
                  sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("application_id", "email", name="uq_application_members_email"),
        sa.UniqueConstraint("application_id", "user_id", name="uq_application_members_user"),
        sa.CheckConstraint("role IN ('owner', 'member')", name="ck_application_members_role"),
    )
    op.create_index("ix_application_members_application_id", "application_members", ["application_id"])
    op.create_index("ix_application_members_user_id", "application_members", ["user_id"])
    op.create_index("ix_application_members_email", "application_members", ["email"])
    # The application's id doubles as its first membership's id.
    op.execute(
        "INSERT INTO application_members (id, application_id, user_id, email, role, created_at) "
        "SELECT a.id, a.id, a.user_id, LOWER(TRIM(u.email)), 'owner', a.created_at "
        "FROM applications a JOIN users u ON u.id = a.user_id"
    )

    with op.batch_alter_table("applications") as batch:
        batch.add_column(sa.Column("orphaned_at", sa.DateTime(), nullable=True))
        batch.create_index("ix_applications_orphaned_at", ["orphaned_at"])
        batch.drop_index("ix_applications_user_id")
        batch.drop_column("user_id")

    with op.batch_alter_table("tokens") as batch:
        batch.add_column(sa.Column("created_by_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_tokens_created_by_id", "users", ["created_by_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_tokens_created_by_id", ["created_by_id"])
        batch.alter_column("user_id", existing_type=sa.String(36), nullable=True)
    op.execute(
        "UPDATE tokens SET created_by_id = user_id, user_id = NULL WHERE application_id IS NOT NULL"
    )
    with op.batch_alter_table("tokens") as batch:
        batch.create_check_constraint("ck_tokens_owner", "(user_id IS NULL) <> (application_id IS NULL)")


def downgrade() -> None:
    # Orphaned applications have no owner to return to and are dropped.
    op.execute(
        "DELETE FROM applications WHERE NOT EXISTS (SELECT 1 FROM application_members m "
        "WHERE m.application_id = applications.id AND m.role = 'owner' AND m.user_id IS NOT NULL)"
    )
    with op.batch_alter_table("tokens") as batch:
        batch.drop_constraint("ck_tokens_owner", type_="check")
    op.execute(
        "UPDATE tokens SET user_id = COALESCE(created_by_id, (SELECT MIN(m.user_id) FROM application_members m "
        "WHERE m.application_id = tokens.application_id AND m.role = 'owner')) "
        "WHERE application_id IS NOT NULL"
    )
    op.execute("DELETE FROM tokens WHERE user_id IS NULL")
    with op.batch_alter_table("tokens") as batch:
        batch.alter_column("user_id", existing_type=sa.String(36), nullable=False)
        batch.drop_index("ix_tokens_created_by_id")
        batch.drop_constraint("fk_tokens_created_by_id", type_="foreignkey")
        batch.drop_column("created_by_id")

    with op.batch_alter_table("applications") as batch:
        batch.add_column(sa.Column("user_id", sa.String(36), nullable=True))
    op.execute(
        "UPDATE applications SET user_id = (SELECT MIN(m.user_id) FROM application_members m "
        "WHERE m.application_id = applications.id AND m.role = 'owner')"
    )
    with op.batch_alter_table("applications") as batch:
        batch.alter_column("user_id", existing_type=sa.String(36), nullable=False)
        batch.create_foreign_key("fk_applications_user_id", "users", ["user_id"], ["id"], ondelete="CASCADE")
        batch.create_index("ix_applications_user_id", ["user_id"])
        batch.drop_index("ix_applications_orphaned_at")
        batch.drop_column("orphaned_at")

    op.drop_table("application_members")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("email_verified")
