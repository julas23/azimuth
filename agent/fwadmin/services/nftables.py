"""Firewall, NAT e isolamento entre zonas.

O motor e' dono so da tabela 'inet azimuth', num arquivo proprio carregado
pela unidade azimuth-nftables.service. O /etc/nftables.conf e' do
administrador e nunca e' escrito: o que o modelo nao representa (NETMAP,
tabela do fail2ban) continua la, funcionando.
"""

from __future__ import annotations

import re

from fwadmin import paths, status
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule

FILE = "azimuth.nft"
PATH = "/etc/nftables.d/azimuth.nft"
UNIT = "azimuth-nftables.service"

TABELAS = ("table inet azimuth",)

POLICY_RE = re.compile(
    r"chain input \{\s*\n\s*type filter hook input [^;]*; policy (\w+);"
)


def _own_table(ruleset: str) -> str:
    """So o trecho da tabela do motor: a politica de input das outras tabelas
    nao e' dele, e nao pode reprovar nem aprovar o apply."""
    start = ruleset.find("table inet azimuth {")
    if start < 0:
        return ""
    end = ruleset.find("\ntable ", start + 1)
    return ruleset[start:] if end < 0 else ruleset[start:end]


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH}


def units(cfg: Config) -> frozenset[str]:
    return frozenset({UNIT})


def _reload() -> Reload:
    """Pela unidade, e nao 'nft -f' direto: so unidade ativa e' reiniciada
    junto com o nftables.service (PartOf), e o primeiro apply e' o que a ativa."""
    if paths.sandboxed():
        return Reload("firewall (nft -f)", ["nft", "-f", str(paths.sys_path(PATH))])
    return Reload("firewall (tabela inet azimuth)", ["systemctl", "restart", UNIT])


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    return [_reload()] if FILE in changed else []


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    return [_reload()] if FILE in files else []


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """As tabelas proprias estao no ruleset vivo, com a politica declarada.

    'nft -f' devolver zero nao e' evidencia: ele devolve zero tambem quando o
    arquivo carrega e a tabela que importa foi apagada por outro processo
    entre o carregamento e agora.
    """
    if FILE not in changed:
        return None

    esperado = "tabelas proprias no ruleset e politica de input declarada"
    ruleset = status.nft_ruleset()
    if not ruleset or ruleset.startswith("nft indisponivel"):
        return Prova.inconclusiva("nftables", esperado, "nao consegui ler o ruleset")

    faltando = [t for t in TABELAS if t not in ruleset]
    if faltando:
        return Prova.falhou("nftables", esperado, f"ausente do ruleset: {', '.join(faltando)}")

    declarada = cfg.firewall.input_policy.value
    achada = POLICY_RE.search(_own_table(ruleset))
    if achada and achada.group(1) != declarada:
        return Prova.falhou(
            "nftables", esperado, f"politica de input e' '{achada.group(1)}', declarada '{declarada}'"
        )

    observado = f"{', '.join(TABELAS)} presentes"
    if achada:
        observado += f"; input policy {achada.group(1)}"
    return Prova.passou("nftables", esperado, observado)


SERVICE = ServiceModule(
    name="nftables",
    order=10,
    section="firewall",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validator=("nft", "-c", "-f"),
)
