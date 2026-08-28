"""O script de failover entre WANs, disparado por timer."""

from __future__ import annotations

from fwadmin.models import Config
from fwadmin.services.base import Reload, ServiceModule

FILE = "wan-failover.sh"
PATH = "/usr/local/bin/wan-failover.sh"


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH}


def _rearm() -> Reload:
    # o script e' lido a cada disparo do timer; nada a recarregar de fato
    return Reload("failover (rearmar timer)", ["systemctl", "restart", "fwadmin-failover.timer"])


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    return [_rearm()] if FILE in changed else []


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    return [_rearm()] if FILE in files else []


SERVICE = ServiceModule(
    name="failover",
    order=50,
    section="routing.failover",
    targets=targets,
    reloads=reloads,
    rollback=rollback,
    probe=None,  # o proprio timer prova a cada disparo; nada a verificar no apply
    executable=frozenset({FILE}),
)
