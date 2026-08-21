"""
Senhas temporárias emitidas pelo admin no reset de senha.

A senha é aleatória por usuário, exibida uma única vez ao admin e nunca
persistida em claro — só o hash bcrypt vai para users.password_hash.
"""
import secrets
from datetime import datetime, timedelta, timezone

# Alfabeto sem caracteres ambíguos (0/O, 1/l/I): enquanto o SMTP não está
# configurado a senha é ditada por telefone/WhatsApp.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
_GROUPS = 3
_GROUP_LEN = 4

# Prazo para o usuário usar a senha temporária. Depois disso o login é
# recusado e o admin precisa emitir outra.
TTL_HOURS = 48


def generate() -> str:
    """Senha em grupos separados por '-' (ex: Kf7m-Qp3x-Rt9w).

    12 caracteres do alfabeto de 56 símbolos ≈ 69 bits de entropia, num
    formato fácil de ditar e de conferir.
    """
    groups = [
        "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN))
        for _ in range(_GROUPS)
    ]
    return "-".join(groups)


def is_expired(reset_at: datetime | None) -> bool:
    if reset_at is None:
        return False
    return datetime.now(timezone.utc) - reset_at > timedelta(hours=TTL_HOURS)
