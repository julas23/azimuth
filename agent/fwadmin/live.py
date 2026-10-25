"""O sistema vivo visto pelo painel: a fotografia do `fwctl observe` passada
pelo importador.

E' a fonte de dados do modo somente leitura. O painel mostra o que esta
rodando, e as duas listas do importador dizem o que o motor faria diferente
se assumisse a maquina: o dry-run antes de existir qualquer acao.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from pydantic import ValidationError

from fwadmin import importer, observe, paths
from fwadmin.models import Config

TTL = 20
"""Segundos que uma fotografia vale antes de pedir outra ao fwctl."""


@dataclass
class Snapshot:
    cfg: Config | None = None
    findings: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    error: str = ""
    """Por que nao ha modelo: fotografia ausente ou config que o modelo recusa."""

    taken_at: float = 0.0
    missing: list[str] = field(default_factory=list)
    wireguard: dict[str, Any] = field(default_factory=dict)
    fail2ban: dict[str, Any] | None = None
    unbound_stats: dict[str, str] | None = None
    unbound: dict[str, Any] = field(default_factory=dict)
    tunnels: list[str] = field(default_factory=list)
    """Todos os .conf do WireGuard, inclusive os que ficam fora do modelo."""

    policies: dict[str, str] = field(default_factory=dict)
    """Politica viva de input e forward do 'inet filter'. O modelo so tem
    'drop'; isto e' o que a maquina faz de fato, para o painel nao mostrar
    fechado o que esta aberto."""

    @property
    def age(self) -> int:
        return int(time.time() - self.taken_at) if self.taken_at else -1


_cache: Snapshot | None = None


def snapshot(runner: Callable[..., tuple[bool, str]], force: bool = False) -> Snapshot:
    """A fotografia mais recente, renovada se tiver mais de TTL segundos.

    `runner` e' a ponte do painel para o fwctl (sudo, lista fechada). No
    sandbox dos testes nao ha root nem sudo: a coleta roda no proprio processo,
    lendo o /etc de mentira.
    """
    global _cache
    if force or _age() > TTL:
        if paths.sandboxed():
            observe.collect()
        else:
            ok, output = runner("observe", timeout=30)
            if not ok and not observe.RUNTIME.exists():
                return Snapshot(error=f"o fwctl observe falhou: {output}")

    taken_at = _taken_at()
    if _cache is None or _cache.taken_at != taken_at:
        _cache = _load(taken_at)
    return _cache


def _taken_at() -> float:
    try:
        return float(json.loads(observe.RUNTIME.read_text())["taken_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0.0


def _age() -> float:
    taken = _taken_at()
    return time.time() - taken if taken else float("inf")


def _load(taken_at: float) -> Snapshot:
    if not taken_at:
        return Snapshot(error="ainda nao ha fotografia do sistema vivo")
    runtime = json.loads(observe.RUNTIME.read_text())
    snap = Snapshot(
        taken_at=taken_at,
        missing=runtime.get("missing", []),
        wireguard=runtime.get("wireguard") or {},
        fail2ban=runtime.get("fail2ban"),
        unbound_stats=runtime.get("unbound"),
        unbound=parse_unbound(observe.LIVE / "unbound"),
        tunnels=sorted(p.stem for p in (observe.LIVE / "wireguard").glob("*.conf")),
    )
    try:
        nft = importer.parse_nft((observe.LIVE / "nftables.conf").read_text())
        snap.policies = {
            chain: body["policy"] or "accept"
            for (table, chain), body in nft["chains"].items()
            if table == "inet filter" and chain in ("input", "forward")
        }
    except OSError:
        pass
    try:
        snap.cfg, snap.findings, snap.changes = importer.run(observe.LIVE)
    except ValidationError as exc:
        snap.error = "o modelo recusa a config viva: " + "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
    except (OSError, KeyError, IndexError, ValueError) as exc:
        snap.error = f"o importador nao conseguiu ler a config viva: {type(exc).__name__}: {exc}"
    return snap


# ---------------------------------------------------------------------------
# unbound — so leitura, o modelo ainda nao tem DNS recursivo
# ---------------------------------------------------------------------------

UNBOUND_LINE = re.compile(r"^\s*([a-z0-9-]+):\s*(.*?)\s*$")


def parse_unbound(root: Path) -> dict[str, Any]:
    """Junta unbound.conf e conf.d num dicionario por secao.

    {'server': {'interface': ['127.0.0.1@5335'], ...},
     'forward-zone': [{'name': ['.'], 'forward-addr': [...]}], ...}
    Secoes que se repetem (forward-zone, stub-zone) viram lista.
    """
    files = [root / "unbound.conf", *sorted((root / "unbound.conf.d").glob("*.conf"))]
    out: dict[str, Any] = {"server": {}, "forward-zone": [], "stub-zone": []}
    section: dict[str, list[str]] | None = None
    for path in files:
        try:
            text = path.read_text()
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0]
            m = UNBOUND_LINE.match(line)
            if not m:
                continue
            key, value = m.group(1), m.group(2).strip('"')
            if not value:
                if key in ("forward-zone", "stub-zone"):
                    section = {}
                    out[key].append(section)
                else:
                    section = out.setdefault(key, {})
                continue
            if section is not None:
                section.setdefault(key, []).append(value)
    return out
