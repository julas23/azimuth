"""Agentes no navegador: catalogo, niveis de acesso e os arquivos de cada um.

O desenho esta no AGENTES.md. Quanto poder o agente tem e' escolha do
usuario: este modulo so traduz o nivel escolhido em arquivos de sistema. Quem
os escreve, como root, e' o 'fwctl agente'; o painel so le o estado.

Cada agente tem um usuario Linux proprio (az-<nome>). Com um usuario so para
todos, um agente de leitura poderia escrever um .bashrc que um agente com root
executaria, e o nivel de um vazaria para o outro.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from fwadmin import paths

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,15}$")

HOME = "/var/lib/azimuth-agente"
LOGS = "/var/log/azimuth-agente"
ETC = "/etc/azimuth-agente"
RUN = "/run/azimuth-agente"
UNIT = "azimuth-agente@{}.service"
DROPIN = "/etc/systemd/system/azimuth-agente@{}.service.d/nivel.conf"
SUDOERS = "/etc/sudoers.d/azimuth-agente-{}"

STATE = paths.VAR / "agentes.json"
"""{nome: {kind, nivel, criado}}. Escrito pelo fwctl, lido pelo painel."""

REQUEST = paths.VAR / "agente-pedido.json"
"""O pedido do painel ao 'fwctl agente', por arquivo, como o do fail2ban."""

PANEL_USER = "netadm"


@dataclass(frozen=True)
class Kind:
    title: str
    packages: tuple[str, ...]
    """Pacotes do Debian que o agente precisa (instalados pelo fwctl, como root)."""

    install: str
    """Como instalar o CLI no diretorio do usuario, se faltar. Roda na propria
    sessao, para o usuario ver o progresso no navegador."""

    command: str
    """O que a sessao abre. Vazio = so o shell."""

    note: str


CATALOG: dict[str, Kind] = {
    "claude-code": Kind(
        title="Claude Code",
        packages=("nodejs", "npm"),
        install="npm install -g @anthropic-ai/claude-code",
        command="claude",
        note="o agente da Anthropic; o login (conta Claude ou chave da API) acontece no próprio terminal",
    ),
    "shell": Kind(
        title="Shell livre",
        packages=(),
        install="",
        command="",
        note="um terminal no ambiente do agente, para instalar e rodar o agente que você quiser",
    ),
}

LEVELS: dict[str, str] = {
    "isolado": "só o próprio ambiente; não enxerga nada do firewall",
    "leitura": "lê os logs do sistema (journal) e o que é legível na máquina; não enxerga senhas nem chaves",
    "motor": "muda a configuração e os serviços pelo motor, com validação, prova e rollback",
    "root": "tudo, na máquina inteira (sudo sem senha)",
}
DEFAULT_LEVEL = "leitura"
UNAVAILABLE = {"motor": "chega com o comando azimuth, na próxima entrega"}
"""Niveis que ainda nao funcionam, com o motivo que a tela mostra."""


def user_of(nome: str) -> str:
    return f"az-{nome}"


def home_of(nome: str) -> str:
    return f"{HOME}/{nome}"


def socket_of(nome: str) -> str:
    return f"{RUN}/{nome}/tmux.sock"


def load_state() -> dict[str, dict]:
    try:
        data = json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def env_file(nome: str, kind: str) -> str:
    """O que a sessao precisa saber do agente. Valores so do catalogo."""
    k = CATALOG[kind]
    return (
        f"# gerado pelo fwctl agente — agente '{nome}' ({k.title})\n"
        f"AGENTE_NOME={nome}\n"
        f"AGENTE_KIND={kind}\n"
        f"AGENTE_CMD='{k.command}'\n"
        f"AGENTE_INSTALA='{k.install}'\n"
        f"AGENTE_PAINEL={PANEL_USER}\n"
    )


def dropin(nome: str, level: str) -> str:
    """O nivel em forma de unidade do systemd.

    Abaixo de root, o agente roda com o sistema so para leitura, sem ganhar
    privilegio (NoNewPrivileges desliga o sudo) e sem enxergar onde moram as
    senhas e chaves do firewall. Root tira tudo isso: e' o que o usuario pediu.
    """
    head = f"# gerado pelo fwctl agente — nivel '{level}' do agente '{nome}'\n[Service]\n"
    if level == "root":
        return head + "# root: sem restricao, por escolha do usuario\n"
    lines = [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "PrivateTmp=yes",
        f"ReadWritePaths={home_of(nome)} {LOGS}/{nome}",
        "InaccessiblePaths=-/etc/fwadmin -/var/lib/fwadmin -/etc/wireguard -/etc/ppp -/root -/run/fwadmin",
    ]
    if level in ("leitura", "motor"):
        lines.append("SupplementaryGroups=systemd-journal")
    return head + "\n".join(lines) + "\n"


def sudoers(nome: str) -> str:
    return (
        f"# gerado pelo fwctl agente — nivel root do agente '{nome}', escolhido pelo usuario\n"
        f"{user_of(nome)} ALL=(ALL) NOPASSWD: ALL\n"
    )
