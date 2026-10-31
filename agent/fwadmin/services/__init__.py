"""O registro de servicos.

Antes deste modulo, acrescentar um servico tocava sete pontos: o modelo, o
template, o dicionario de alvos, o de validadores, um 'if' novo na cadeia de
recargas, uma sonda no status.py que ninguem chamava, e a tela. Agora e' um
arquivo em services/ e uma linha aqui.

O motor nao sabe nada sobre servico nenhum em particular: ele pergunta ao
registro o que renderizar, o que validar, o que recarregar e o que provar.
"""

from __future__ import annotations

from pathlib import Path

from fwadmin import paths
from fwadmin.command import Result, run
from fwadmin.models import Config
from fwadmin.services import apps, ddns, dnsmasq, docker, failover, interfaces, nftables, pppoe, unbound, wireguard
from fwadmin.services.base import Prova, Reload, ServiceModule

REGISTRY: tuple[ServiceModule, ...] = tuple(
    sorted(
        (
            nftables.SERVICE,
            unbound.SERVICE,
            dnsmasq.SERVICE,
            interfaces.SERVICE,
            pppoe.SERVICE,
            wireguard.SERVICE,
            failover.SERVICE,
            ddns.SERVICE,
            docker.SERVICE,
            apps.SERVICE,
        ),
        key=lambda s: s.order,
    )
)

__all__ = [
    "REGISTRY",
    "Prova",
    "Reload",
    "ServiceModule",
    "executables",
    "owner",
    "provas",
    "quiet",
    "reloads",
    "rollback_reloads",
    "targets",
    "units",
    "template_for",
    "context_for",
    "validate_syntax",
]


def targets(cfg: Config) -> dict[str, str]:
    """Todos os arquivos gerenciados: {nome_do_render: caminho_no_sistema}.

    Derivado do config a cada chamada, nunca acumulado num global. O mapa
    anterior era de modulo e crescia com 'setdefault' a cada peer de PPPoE
    renderizado — um peer removido continuava no mapa pelo resto da vida do
    processo, e o render seguinte procurava um template que nao existe.
    """
    out: dict[str, str] = {}
    for service in REGISTRY:
        out.update(service.targets(cfg))
    return out


def units(cfg: Config) -> dict[str, str]:
    """Unidades do systemd reivindicadas: {unidade: nome_do_servico}.

    Duas unidades nunca sao do mesmo dono por acidente — se dois modulos
    reivindicarem a mesma, o ultimo do REGISTRY ganha, e o inventario mostra
    um dono so. E' aceitavel porque a ordem do REGISTRY e' declarada.
    """
    out: dict[str, str] = {}
    for service in REGISTRY:
        for unit in service.units(cfg):
            out[unit] = service.name
    return out


def owner(name: str, cfg: Config) -> ServiceModule | None:
    """Qual servico e' dono de um arquivo renderizado."""
    for service in REGISTRY:
        if name in service.targets(cfg):
            return service
    return None


def executables(cfg: Config) -> set[str]:
    out: set[str] = set()
    for service in REGISTRY:
        out |= set(service.executable)
    return out


def template_for(name: str, cfg: Config) -> str:
    service = owner(name, cfg)
    return service.template(name) if service else f"{name}.j2"


def context_for(name: str, cfg: Config) -> dict:
    service = owner(name, cfg)
    return service.context(cfg, name) if service else {}


def validate_syntax(staging: Path, names: list[str], cfg: Config) -> list[Result]:
    """Passa cada arquivo gerado pela ferramenta nativa do servico dele.

    Servico com 'validate' proprio e' chamado uma vez, com todos os nomes dele
    que estao na rodada.
    """
    results = []
    custom: dict[str, list[str]] = {}
    for name in names:
        service = owner(name, cfg)
        if service is None:
            continue
        if service.validate is not None:
            custom.setdefault(service.name, []).append(name)
        elif service.validator is not None:
            results.append(run(*service.validator, str(staging / name), mutating=False))
    for service in REGISTRY:
        if service.name in custom:
            results.extend(service.validate(staging, custom[service.name], cfg))
    return results


def quiet(cfg: Config, changed: list[str]) -> list[str]:
    """Unidades a pausar durante a prova, dos servicos mexidos nesta rodada."""
    out: list[str] = []
    for service in REGISTRY:
        if set(service.targets(cfg)) & set(changed):
            out.extend(sorted(service.quiet))
    return out


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    """As recargas do apply, na ordem declarada pelos modulos."""
    out: list[Reload] = []
    for service in REGISTRY:
        out.extend(service.reloads(cfg, previous, changed))
    return out


def rollback_reloads(cfg: Config | None, files: list[str]) -> list[Reload]:
    """As recargas do caminho de volta, na mesma ordem."""
    out: list[Reload] = []
    for service in REGISTRY:
        out.extend(service.rollback(cfg, files))
    return out


def provas(cfg: Config, previous: Config | None, changed: list[str]) -> list[Prova]:
    """A prova de funcao de cada servico mexido.

    Em sandbox nada e' observado: as recargas nao rodaram, entao perguntar ao
    sistema vivo mediria a maquina de quem esta testando. A prova aparece
    como inconclusiva, para o exercicio mostrar que a fase existe.
    """
    out: list[Prova] = []
    for service in REGISTRY:
        if service.probe is None:
            continue
        mine = set(service.targets(cfg))
        if service.secret_targets is not None:
            mine |= set(service.secret_targets(cfg))
        if not mine & set(changed):
            continue
        if paths.sandboxed():
            out.append(
                Prova.inconclusiva(service.name, "prova de funcao", "sandbox: nao observado")
            )
            continue
        prova = service.probe(cfg, previous, changed)
        if prova is not None:
            out.append(prova)
    return out
