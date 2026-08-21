"""add email verification to users

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("email_verification_token", sa.String(64), nullable=True))
    op.alter_column("users", "is_active", server_default="false")

    # Usuários existentes já são considerados verificados
    op.execute(text("UPDATE users SET email_verified_at = NOW() WHERE email_verified_at IS NULL"))


def downgrade() -> None:
    op.drop_column("users", "email_verification_token")
    op.drop_column("users", "email_verified_at")
    op.alter_column("users", "is_active", server_default="true")
