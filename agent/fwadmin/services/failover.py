"""O script de failover entre WANs, disparado por timer."""

from __future__ import annotations

from fwadmin.models import Config
from fwadmin.services.base import Reload, ServiceModule

FILE = "wan-failover.sh"
PATH = "/usr/local/bin/wan-failover.sh"


def targets(cfg: Config) -> dict[str, str]:
    # Sem failover, o motor nao tem script nem timer: numa maquina adotada em
    # que o pppd e' dono da rota, o timer nem existe, e rearmar o que nao
    # existe faria o primeiro apply falhar na recarga.
    return {FILE: PATH} if cfg.routing.failover.enabled else {}


def units(cfg: Config) -> frozenset[str]:
    # A unidade e' do proprio appliance, e nao um daemon de terceiro: quem
    # roda o script e' o timer que o instalador criou.
    return frozenset({"fwadmin-failover.timer"}) if cfg.routing.failover.enabled else frozenset()


def _rearm() -> Reload:
    # o script e' lido a cada disparo do timer; nada a recarregar de fato
    return Reload(
        "failover (rearmar timer)",
        ["sh", "-c", "systemctl enable fwadmin-failover.timer && systemctl restart fwadmin-failover.timer"],
    )


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    return [_rearm()] if FILE in changed else []


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    return [_rearm()] if FILE in files else []


SERVICE = ServiceModule(
    name="failover",
    order=50,
    section="routing.failover",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=None,  # o proprio timer prova a cada disparo; nada a verificar no apply
    executable=frozenset({FILE}),
)
