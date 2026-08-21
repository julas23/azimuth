import uuid
from sqlalchemy import String, Boolean, BigInteger, DateTime, ForeignKey, func, UniqueConstraint, JSON
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


class BandwidthUsage(Base):
    __tablename__ = "bandwidth_usage"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vpn_peers.id"), nullable=False
    )
    period: Mapped[str] = mapped_column(String(7), nullable=False)   # YYYY-MM
    bytes_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    # Último valor bruto do contador wg (acumulado desde criação do peer).
    # bytes_rx/tx armazenam o delta mensal; raw_* rastreiam o ponto de referência.
    raw_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    raw_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    last_updated: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    quota_notified_80: Mapped[bool] = mapped_column(Boolean, default=False)
    quota_notified_100: Mapped[bool] = mapped_column(Boolean, default=False)

    peer: Mapped["VpnPeer"] = relationship(back_populates="bandwidth")

    __table_args__ = (UniqueConstraint("peer_id", "period"),)


class WebhookEvent(Base):
    """Tabela de idempotência para webhooks Stripe."""
    __tablename__ = "webhook_events"

    stripe_event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    processed_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    status: Mapped[str] = mapped_column(String(20), default="ok")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CustomDomain(Base):
    __tablename__ = "custom_domains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vpn_peers.id"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    peer: Mapped["VpnPeer"] = relationship(back_populates="custom_domains")

    __table_args__ = (UniqueConstraint("peer_id", "domain"),)
