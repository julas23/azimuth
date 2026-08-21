import asyncio
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.user import User
from schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from services import mailer, temp_password

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── helpers ──────────────────────────────────────────────────────────────────

def _hash(password: str) -> str:
    return pwd_context.hash(password)


def _verify(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _create_token(sub: str, kind: str, expire_delta: timedelta) -> str:
    payload = {
        "sub": sub,
        "kind": kind,
        "exp": datetime.now(timezone.utc) + expire_delta,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def _make_tokens(user_id: str) -> TokenResponse:
    access = _create_token(
        user_id, "access",
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh = _create_token(
        user_id, "refresh",
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


async def _get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    token = (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token ausente")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("kind") != "access":
            raise JWTError
        user_id: str = payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or user.email_verified_at is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado")
    if user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Troca de senha obrigatória — defina uma nova senha em /account/password",
        )
    return user


# ── endpoints ────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    exists = await db.execute(select(User).where(User.email == body.email))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="E-mail já cadastrado")

    # Mesma regra do registro HTML (routers/pages.py): com SMTP configurado a
    # conta nasce pendente e recebe o link; sem SMTP nasce verificada, senão os
    # tokens devolvidos aqui seriam inúteis (as rotas exigem email_verified_at).
    smtp_ok = mailer.is_configured()
    token = secrets.token_urlsafe(32) if smtp_ok else None
    user = User(
        email=body.email,
        password_hash=_hash(body.password),
        name=body.name,
        email_verification_token=token,
        email_verified_at=None if smtp_ok else datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    if smtp_ok:
        verify_url = f"{settings.APP_BASE_URL}/verify-email?token={token}"
        asyncio.create_task(
            mailer.send_verification_email(body.email, body.name, verify_url)
        )

    return _make_tokens(str(user.id))


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if user is None or not _verify(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")
    if user.email_verified_at is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="E-mail não verificado")
    if user.must_change_password:
        # Não há endpoint JSON de troca de senha — a troca é feita no painel web.
        if temp_password.is_expired(user.password_reset_at):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Senha temporária expirada — solicite um novo reset ao administrador",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Troca de senha obrigatória — defina uma nova senha em /account/password",
        )

    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_login=datetime.now(timezone.utc))
    )
    await db.commit()
    return _make_tokens(str(user.id))


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        payload = jwt.decode(body.refresh_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("kind") != "refresh":
            raise JWTError
        user_id: str = payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or user.email_verified_at is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado")
    return _make_tokens(str(user.id))


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(_get_current_user)) -> User:
    return current_user
