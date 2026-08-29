"""Onde cada coisa mora.

Tudo passa por aqui para que a suite de testes possa redirecionar o sistema
inteiro para um diretorio descartavel (FWADMIN_SYSROOT) e exercitar o apply
de verdade sem encostar no firewall.
"""

from __future__ import annotations

import os
from pathlib import Path

SYSROOT = Path(os.environ.get("FWADMIN_SYSROOT", "/"))
"""Prefixo de todos os caminhos do sistema. '/' em producao."""


def sys_path(absolute: str) -> Path:
    """Aplica o sysroot a um caminho absoluto do sistema."""
    return SYSROOT / absolute.lstrip("/")


CODE = Path(os.environ.get("FWADMIN_CODE", "/opt/fwadmin"))
"""Onde o pacote fwadmin esta instalado."""

ETC = sys_path("/etc/fwadmin")
VAR = sys_path("/var/lib/fwadmin")
RUN = sys_path("/run/fwadmin")

CONFIG = ETC / "config.yaml"
"""Config viva — o que esta aplicado agora."""

PENDING = ETC / "config.pending.yaml"
"""Config proposta pela UI, aguardando apply."""

SECRETS = ETC / "secrets.yaml"
"""Senhas (PPPoE etc). Modo 0600, nunca versionado."""

NOTE = ETC / "apply-note"
"""Mensagem do proximo commit, deixada pela UI.

Existe para o sudoers nao precisar de curinga: se a mensagem viesse como
argumento, a regra teria de terminar em '*' — e curinga no sudoers casa
atraves de argumentos, que e' justamente como se escapa de um sudoers
restrito. Assim todas as regras ficam com comando exato.
"""

BACKUPS = VAR / "backups"
STAGING = VAR / "staging"
STATE = VAR / "state.json"
DB = VAR / "fwadmin.db"

OWNED = VAR / "owned.json"
"""Selo de posse: o sha256 de cada arquivo no instante em que ele virou oficial.

Mora em /var e nao em /etc de proposito. O selo e' observacao do motor sobre o
sistema, nao configuracao: se ele fosse versionado junto da config, um `git
checkout` no historico devolveria um selo que nunca correspondeu ao /etc vivo.
"""

DRIFT = VAR / "drift"
"""Copias de arquivos editados a mao, guardadas antes de serem sobrescritos."""

REVERT_UNIT = "fwadmin-revert"
"""Unidade transiente do systemd que desfaz um apply nao confirmado."""


def sandboxed() -> bool:
    return SYSROOT != Path("/")
