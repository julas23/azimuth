import uuid
from sqlalchemy import String, Boolean, DateTime, ForeignKey, func, Index
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


class VpnPeer(Base):
    __tablename__ = "vpn_peers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    plan_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("plans.id"), nullable=False
    )
    public_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    private_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(INET, unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    config_stale: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, server_default="false")
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="peers")
    plan: Mapped["Plan"] = relationship(back_populates="peers")
    bandwidth: Mapped[list["BandwidthUsage"]] = relationship(back_populates="peer")
    custom_domains: Mapped[list["CustomDomain"]] = relationship(back_populates="peer")

    __table_args__ = (
        Index("ix_vpn_peers_ip_active", "ip_address", postgresql_where="is_active = true"),
    )
