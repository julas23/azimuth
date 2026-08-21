from sqlalchemy import String, Integer
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


class Plan(Base):
    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)   # 'basic','standard','full'
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    stripe_price_id: Mapped[str] = mapped_column(String(255), nullable=False)
    subnet: Mapped[str] = mapped_column(CIDR, nullable=False)        # ex: 10.50.0.0/16
    gateway: Mapped[str] = mapped_column(INET, nullable=False)       # ex: 10.50.0.1
    bandwidth_mbps: Mapped[int] = mapped_column(Integer, nullable=False)
    quota_gb: Mapped[int] = mapped_column(Integer, nullable=False)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    custom_domains_limit: Mapped[int] = mapped_column(Integer, default=0)

    peers: Mapped[list["VpnPeer"]] = relationship(back_populates="plan")
