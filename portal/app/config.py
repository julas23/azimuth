from pydantic_settings import BaseSettings
from pydantic import field_validator
import ipaddress


class Settings(BaseSettings):
    # Banco
    DATABASE_URL: str

    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Stripe
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""

    # Bridge e WireGuard
    BRIDGE_SOCKET: str = "/run/vpn-bridge/bridge.sock"
    SERVER_PUBLIC_IP: str = "0.0.0.0"
    WG_SERVER_PORT: int = 51820
    WG_SERVER_PUBLIC_KEY: str = ""

    # SMTP
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_TLS: bool = True

    # App
    APP_ENV: str = "production"
    APP_BASE_URL: str = "http://localhost:8000"

    @field_validator("SERVER_PUBLIC_IP")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"SERVER_PUBLIC_IP inválido: {v}")
        return v

    class Config:
        env_file = ".env"


settings = Settings()
