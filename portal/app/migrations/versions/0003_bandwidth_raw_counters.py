"""add raw_rx/raw_tx to bandwidth_usage for monthly delta tracking

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-08

"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "bandwidth_usage",
        sa.Column("raw_rx", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "bandwidth_usage",
        sa.Column("raw_tx", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("bandwidth_usage", "raw_rx")
    op.drop_column("bandwidth_usage", "raw_tx")
