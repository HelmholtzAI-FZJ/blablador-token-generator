"""Expiry warning bookkeeping.

Tokens remember the tightest warning already mailed, so the daily job sends
one message per configured threshold (30, 7 and 1 days by default) instead of
one per day. Null on every existing row: the first run treats them as never
warned, which is correct and sends at most one message per threshold.

Compatible with 1.2.0 instances during a rolling upgrade: the columns are
nullable and nothing reads them until the notification job runs.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("tokens") as batch:
        batch.add_column(sa.Column("expiry_notified_days", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("expiry_notified_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("tokens") as batch:
        batch.drop_column("expiry_notified_at")
        batch.drop_column("expiry_notified_days")
