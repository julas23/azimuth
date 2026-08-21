"""add private_key to vpn_peers

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-08

"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vpn_peers",
        sa.Column("private_key", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vpn_peers", "private_key")
