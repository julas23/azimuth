"""add config_stale to vpn_peers

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-09
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vpn_peers",
        sa.Column("config_stale", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("vpn_peers", "config_stale")
