"""initial schema + plan seeds

Revision ID: 0001
Revises:
Create Date: 2026-06-08

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "plans",
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(50), nullable=False),
        sa.Column("stripe_price_id", sa.String(255), nullable=False),
        sa.Column("subnet", postgresql.CIDR(), nullable=False),
        sa.Column("gateway", postgresql.INET(), nullable=False),
        sa.Column("bandwidth_mbps", sa.Integer(), nullable=False),
        sa.Column("quota_gb", sa.Integer(), nullable=False),
        sa.Column("price_cents", sa.Integer(), nullable=False),
        sa.Column("custom_domains_limit", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("stripe_customer_id", sa.String(255), unique=True, nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "vpn_peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("plan_id", sa.String(20), sa.ForeignKey("plans.id"), nullable=False),
        sa.Column("public_key", sa.String(255), nullable=False, unique=True),
        sa.Column("ip_address", postgresql.INET(), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_vpn_peers_ip_active",
        "vpn_peers",
        ["ip_address"],
        postgresql_where=sa.text("is_active = true"),
    )

    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vpn_peers.id"), nullable=True),
        sa.Column("plan_id", sa.String(20), sa.ForeignKey("plans.id"), nullable=False),
        sa.Column("stripe_subscription_id", sa.String(255), nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "bandwidth_usage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vpn_peers.id"), nullable=False),
        sa.Column("period", sa.String(7), nullable=False),
        sa.Column("bytes_rx", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_tx", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "last_updated",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("quota_notified_80", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("quota_notified_100", sa.Boolean(), nullable=False, server_default="false"),
        sa.UniqueConstraint("peer_id", "period"),
    )

    op.create_table(
        "webhook_events",
        sa.Column("stripe_event_id", sa.String(255), primary_key=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="ok"),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("details", postgresql.JSON(), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "custom_domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vpn_peers.id"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("peer_id", "domain"),
    )

    # Seed plans
    op.execute("""
        INSERT INTO plans (id, name, stripe_price_id, subnet, gateway,
                           bandwidth_mbps, quota_gb, price_cents, custom_domains_limit)
        VALUES
          ('basic',    'Basic',    'price_placeholder_basic',
           '10.50.0.0/16',  '10.50.0.1',  10,  50,  2990, 0),
          ('standard', 'Standard', 'price_placeholder_standard',
           '10.100.0.0/16', '10.100.0.1', 25, 200,  5990, 1),
          ('full',     'Full',     'price_placeholder_full',
           '10.200.0.0/16', '10.200.0.1', 50,   0,  9990, 5)
    """)


def downgrade() -> None:
    op.drop_table("custom_domains")
    op.drop_table("audit_log")
    op.drop_table("webhook_events")
    op.drop_table("bandwidth_usage")
    op.drop_table("subscriptions")
    op.drop_index("ix_vpn_peers_ip_active", "vpn_peers")
    op.drop_table("vpn_peers")
    op.drop_index("ix_users_email", "users")
    op.drop_table("users")
    op.drop_table("plans")
