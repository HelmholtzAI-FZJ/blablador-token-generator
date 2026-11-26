"""Give tokens of used invitations a course user.

Before course users existed, using a mailed invitation left its token owned
by the invitation. Such a token now goes to the address's password account
if there is one, else to its course user (created here), with a seat in the
course, as using an invitation does today.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-27
"""
import uuid

from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    db = op.get_bind()
    rows = db.execute(sa.text(
        "SELECT t.id, t.course_id, i.id, i.email FROM tokens t "
        "JOIN course_invitations i ON i.id = t.course_invitation_id"
    )).all()
    for token_id, course_id, invitation_id, email in rows:
        address = email.strip().lower()
        user_id = db.execute(sa.text(
            "SELECT id FROM users WHERE lower(email) = :email AND unity_id IS NULL"
        ), {"email": address}).scalar()
        if user_id is None:
            user_id = str(uuid.uuid4())
            db.execute(sa.text(
                "INSERT INTO users (id, email, name, is_admin, email_verified, created_at, session_epoch, "
                "is_teacher, is_course_user) VALUES (:id, :email, :email, false, false, CURRENT_TIMESTAMP, 0, "
                "false, true)"
            ), {"id": user_id, "email": address})
        if db.execute(sa.text(
            "SELECT 1 FROM course_seats WHERE course_id = :course AND user_id = :user"
        ), {"course": course_id, "user": user_id}).scalar() is None:
            db.execute(sa.text(
                "INSERT INTO course_seats (id, course_id, user_id, claimed_at) "
                "SELECT :id, :course, :user, COALESCE(claimed_at, CURRENT_TIMESTAMP) "
                "FROM course_invitations WHERE id = :invitation"
            ), {"id": str(uuid.uuid4()), "course": course_id, "user": user_id, "invitation": invitation_id})
        db.execute(sa.text(
            "UPDATE tokens SET user_id = :user, course_invitation_id = NULL WHERE id = :token"
        ), {"user": user_id, "token": token_id})
        db.execute(sa.text(
            "UPDATE course_invitations SET claimed_by_id = :user WHERE id = :invitation AND claimed_by_id IS NULL"
        ), {"user": user_id, "invitation": invitation_id})


def downgrade() -> None:
    # Tokens keep their owner; the earlier schema accepts user-owned tokens.
    pass
