import uuid
from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_verification_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Reset feito pelo admin: senha atual é temporária e precisa ser trocada
    # no primeiro acesso. password_reset_at marca o início do prazo (TTL em
    # services/temp_password.py).
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_reset_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_login: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    peers: Mapped[list["VpnPeer"]] = relationship(back_populates="user")
    subscriptions: Mapped[list["Subscription"]] = relationship(back_populates="user")
