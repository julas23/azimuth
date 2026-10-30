"""Firewall, NAT e isolamento entre zonas.

O motor e' dono da tabela 'inet azimuth', num arquivo proprio carregado pela
unidade azimuth-nftables.service. O /etc/nftables.conf e' do administrador
ate ser absorvido (firewall.absorbed_tables): dai o motor tambem o escreve,
so com o que o modelo nao representa (NETMAP, snat por mapa). A tabela do
fail2ban nao mora em arquivo nenhum e nunca e' tocada.
"""

from __future__ import annotations

import re

from fwadmin import paths, status
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule

FILE = "azimuth.nft"
PATH = "/etc/nftables.d/azimuth.nft"
UNIT = "azimuth-nftables.service"

ADMIN = "nftables.conf"
ADMIN_PATH = "/etc/nftables.conf"

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
    out = {FILE: PATH}
    if cfg.firewall.absorbed_tables:
        out[ADMIN] = ADMIN_PATH
    return out


def units(cfg: Config) -> frozenset[str]:
    return frozenset({UNIT})


def _reload() -> Reload:
    """Pela unidade, e nao 'nft -f' direto: so unidade ativa e' reiniciada
    junto com o nftables.service (PartOf), e o primeiro apply e' o que a ativa."""
    if paths.sandboxed():
        return Reload("firewall (nft -f)", ["nft", "-f", str(paths.sys_path(PATH))])
    return Reload("firewall (tabela inet azimuth)", ["systemctl", "restart", UNIT])


def _reload_admin() -> Reload:
    """'nft -f' do arquivo, que e' o ExecReload do nftables.service. Nunca o
    restart: o ExecStop dele e' 'flush ruleset', que levaria junto a tabela do
    motor e a do fail2ban."""
    return Reload("firewall (/etc/nftables.conf)", ["nft", "-f", str(paths.sys_path(ADMIN_PATH))])


def _ours(files: list[str]) -> list[Reload]:
    out = [_reload_admin()] if ADMIN in files else []
    return out + ([_reload()] if FILE in files else [])


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    return _ours(changed)


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    return _ours(files)


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """As tabelas proprias estao no ruleset vivo, com a politica declarada.

    'nft -f' devolver zero nao e' evidencia: ele devolve zero tambem quando o
    arquivo carrega e a tabela que importa foi apagada por outro processo
    entre o carregamento e agora.
    """
    if FILE not in changed and ADMIN not in changed:
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

    # Absorvido, tabela sem nada que sobrou tem de ter saido do ruleset: se
    # ficou, o arquivo antigo ainda vale e o forward dele ainda derruba.
    vazias = {t for t in cfg.firewall.absorbed_tables} - {c.table for c in cfg.firewall.admin_chains}
    ficaram = [t for t in sorted(vazias) if f"table {t} {{" in ruleset]
    if ficaram:
        return Prova.falhou("nftables", esperado, f"absorvida e ainda no ruleset: {', '.join(ficaram)}")

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
