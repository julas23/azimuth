"""Interfaces de rede: enderecos, gateway e o /etc/network/interfaces."""

from __future__ import annotations

from fwadmin import status
from fwadmin.models import Config, IfRole, IPv4Mode
from fwadmin.services.base import Prova, Reload, ServiceModule, until

FILE = "interfaces"
PATH = "/etc/network/interfaces"


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH}


def _bounce(device: str) -> Reload:
    return Reload(
        f"interface {device}",
        ["sh", "-c", f"ifdown {device} || true; ifup {device}"],
        disruptive=True,
    )


def changed_devices(cfg: Config, previous: Config) -> list[str]:
    """Devices cuja configuracao de camada 3 mudou de fato."""
    old = {i.device: i.ipv4.model_dump() for i in previous.interfaces}
    return [i.device for i in cfg.interfaces if old.get(i.device) != i.ipv4.model_dump()]


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    if FILE not in changed or previous is None:
        return []
    return [_bounce(d) for d in changed_devices(cfg, previous)]


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    """No caminho de volta nao ha diff em que confiar: resobe tudo que serve."""
    if FILE not in files or cfg is None:
        return []
    return [_bounce(i.device) for i in cfg.interfaces if i.role is not IfRole.unused]


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """As interfaces mexidas voltaram com link e, em modo estatico, endereco.

    So o que mudou e' verificado. Provar o que nao foi tocado faria uma WAN
    reserva ja desconectada derrubar um apply que so mexeu em DNS.
    """
    if FILE not in changed or previous is None:
        return None

    mexidos = set(changed_devices(cfg, previous))
    alvos = [
        i
        for i in cfg.interfaces
        if i.device in mexidos
        and i.role is not IfRole.unused
        and i.ipv4.mode is not IPv4Mode.pppoe  # ppp0 e' prova do modulo pppoe
    ]
    if not alvos:
        return None

    esperado = "link e endereco nas interfaces mexidas: " + ", ".join(i.device for i in alvos)

    def olhar() -> Prova:
        vivos = status.links()
        if not vivos:
            return Prova.inconclusiva(
                "interfaces", esperado, "nao consegui ler o estado das interfaces"
            )
        quebrados = []
        vistos = []
        for iface in alvos:
            estado = vivos.get(iface.device)
            if estado is None:
                quebrados.append(f"{iface.device}: ausente")
            elif not estado.up:
                quebrados.append(f"{iface.device}: down")
            elif iface.ipv4.mode is not IPv4Mode.manual and not estado.address:
                quebrados.append(f"{iface.device}: sem endereco")
            else:
                vistos.append(f"{iface.device} {estado.address or 'up'}")
        if quebrados:
            return Prova.falhou("interfaces", esperado, "; ".join(quebrados))
        return Prova.passou("interfaces", esperado, "; ".join(vistos))

    return until(20, olhar)


SERVICE = ServiceModule(
    name="interfaces",
    order=30,
    section="interfaces",
    targets=targets,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validator=("ifquery", "-l", "-a", "-i"),
)
