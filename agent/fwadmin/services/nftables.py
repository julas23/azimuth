"""Firewall, NAT e isolamento entre zonas."""

from __future__ import annotations

import re

from fwadmin import paths, status
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule

FILE = "nftables.conf"
PATH = "/etc/nftables.conf"

TABELAS = ("table inet filter", "table ip nat")

POLICY_RE = re.compile(
    r"chain input \{\s*\n\s*type filter hook input [^;]*; policy (\w+);"
)


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH}


def units(cfg: Config) -> frozenset[str]:
    return frozenset({"nftables.service"})


def _reload() -> Reload:
    return Reload("firewall (nft -f)", ["nft", "-f", str(paths.sys_path(PATH))])


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
    achada = POLICY_RE.search(ruleset)
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
