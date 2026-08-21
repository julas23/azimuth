"""
Shared auth dependency that accepts both:
  • Authorization: Bearer <token>  (JSON API clients)
  • access_token cookie            (browser / HTML pages)
"""
from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.user import User


class MustChangePassword(Exception):
    """Autenticado com senha temporária emitida pelo admin.

    Tratada por um handler em main.py, que redireciona as páginas HTML para
    /account/password. As rotas JSON respondem 403 direto (ver abaixo).
    """


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    # 1. Authorization header (API clients)
    token = (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    # 2. Cookie fallback (browser)
    if not token:
        token = request.cookies.get("access_token", "")

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
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado")
    if user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Troca de senha obrigatória — defina uma nova senha em /account/password",
        )
    return user
