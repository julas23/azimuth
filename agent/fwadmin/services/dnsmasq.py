"""DNS local, DHCP, reservas por MAC e registros da LAN."""

from __future__ import annotations

from fwadmin import status
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule, until

FILE = "dnsmasq.conf"
PATH = "/etc/dnsmasq.conf"


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH}


def _reload() -> Reload:
    # reload do dnsmasq so rele /etc/hosts e leases; mudanca de conf exige restart
    return Reload("dnsmasq", ["systemctl", "restart", "dnsmasq"])


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    return [_reload()] if FILE in changed else []


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    return [_reload()] if FILE in files else []


def _servers(cfg: Config) -> list[str]:
    """Onde perguntar. O IP da LAN primeiro, porque 'interface=' com
    bind-interfaces faz o dnsmasq nao atender no loopback."""
    alvos = []
    try:
        endereco = cfg.lan.ipv4.address
    except Exception:  # noqa: BLE001 — LAN sem endereco estatico
        endereco = None
    if endereco:
        alvos.append(endereco.split("/")[0])
    alvos.append("127.0.0.1")
    return alvos


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """Um nome da LAN resolve de verdade, perguntando ao resolvedor local."""
    if FILE not in changed:
        return None

    registros = [h for h in cfg.hosts if h.dns]
    if not registros:
        return Prova.inconclusiva(
            "dnsmasq", "um nome da LAN resolvendo", "nao ha registro local para consultar"
        )

    nome = registros[0].fqdn(cfg.dns.domain)
    esperado = f"{nome} resolvendo no resolvedor local"
    servidores = _servers(cfg)

    def olhar() -> Prova:
        for servidor in servidores:
            if status.dns_answers(nome, servidor):
                return Prova.passou("dnsmasq", esperado, f"respondido por {servidor}")
        return Prova.falhou("dnsmasq", esperado, f"sem resposta de {', '.join(servidores)}")

    return until(10, olhar)


SERVICE = ServiceModule(
    name="dnsmasq",
    order=20,
    section="dns, dhcp, hosts",
    targets=targets,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validator=("dnsmasq", "--test", "-C"),
)
