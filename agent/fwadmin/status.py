"""Leitura do estado real do sistema — nada aqui muda nada.

Serve ao dashboard e ao diagnostico. Todas as funcoes degradam para um valor
vazio em vez de levantar excecao: um painel de firewall precisa abrir mesmo
com metade do sistema em pane.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from fwadmin import paths
from fwadmin.models import Config, IPv4Mode


def _run(*args: str, timeout: int = 10) -> str:
    if shutil.which(args[0]) is None:
        return ""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout


# ---------------------------------------------------------------------------
# interfaces e rotas
# ---------------------------------------------------------------------------


@dataclass
class LinkState:
    device: str = ""
    up: bool = False
    address: str = ""
    rx_bytes: int = 0
    tx_bytes: int = 0
    errors: int = 0


def links() -> dict[str, LinkState]:
    """Estado de camada 2/3 de cada interface, via 'ip -j'."""
    raw = _run("ip", "-j", "-s", "addr", "show")
    if not raw:
        return {}
    out: dict[str, LinkState] = {}
    try:
        for item in json.loads(raw):
            addrs = [a["local"] for a in item.get("addr_info", []) if a.get("family") == "inet"]
            stats = item.get("stats64", {})
            out[item["ifname"]] = LinkState(
                device=item["ifname"],
                up=item.get("operstate") in ("UP", "UNKNOWN"),
                address=addrs[0] if addrs else "",
                rx_bytes=stats.get("rx", {}).get("bytes", 0),
                tx_bytes=stats.get("tx", {}).get("bytes", 0),
                errors=stats.get("rx", {}).get("errors", 0)
                + stats.get("tx", {}).get("errors", 0),
            )
    except (json.JSONDecodeError, KeyError, TypeError):
        return {}
    return out


def default_route() -> tuple[str, str]:
    """(device, gateway) da rota default vigente."""
    raw = _run("ip", "-j", "route", "show", "default")
    try:
        routes = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return "", ""
    if not routes:
        return "", ""
    best = min(routes, key=lambda r: r.get("metric", 0))
    return best.get("dev", ""), best.get("gateway", "")


def failover_state() -> str:
    """'primary' | 'backup' | '' — escrito pelo wan-failover.sh."""
    state = paths.RUN / "wan-state"
    try:
        return state.read_text().strip()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# WANs, do ponto de vista do modelo
# ---------------------------------------------------------------------------


@dataclass
class WanStatus:
    name: str
    description: str
    device: str
    up: bool = False
    address: str = ""
    active: bool = False
    """True se a rota default sai por esta WAN agora."""

    primary: bool = False
    errors: int = 0


def wans(cfg: Config) -> list[WanStatus]:
    state = links()
    active_dev, _ = default_route()
    out = []
    for wan in cfg.wans:
        device = wan.ppp_device
        link = state.get(device, LinkState(device=device))
        out.append(
            WanStatus(
                name=wan.name,
                description=wan.description,
                device=device,
                up=link.up,
                address=link.address,
                active=device == active_dev,
                primary=wan.name == cfg.routing.primary,
                errors=link.errors,
            )
        )
    return out


# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------


@dataclass
class Lease:
    expires: float
    mac: str
    ip: str
    hostname: str
    reserved: bool = False

    @property
    def expires_in(self) -> str:
        delta = int(self.expires - time.time())
        if delta <= 0:
            return "expirado"
        if delta < 3600:
            return f"{delta // 60}min"
        return f"{delta // 3600}h"


LEASE_FILES = ("/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases")


def leases(cfg: Config | None = None) -> list[Lease]:
    """Leases ativos do dnsmasq, marcando quais vem de reserva."""
    reserved = {r.mac for r in cfg.dhcp.reservations} if cfg else set()
    for candidate in LEASE_FILES:
        path = paths.sys_path(candidate)
        if not path.exists():
            continue
        out = []
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            out.append(
                Lease(
                    expires=float(parts[0]),
                    mac=parts[1].lower(),
                    ip=parts[2],
                    hostname=parts[3] if parts[3] != "*" else "",
                    reserved=parts[1].lower() in reserved,
                )
            )
        return sorted(out, key=lambda leased: tuple(int(o) for o in leased.ip.split(".")))
    return []


# ---------------------------------------------------------------------------
# servicos e sistema
# ---------------------------------------------------------------------------


@dataclass
class ServiceState:
    unit: str
    active: str = "unknown"
    enabled: str = "unknown"

    @property
    def ok(self) -> bool:
        return self.active == "active"


WATCHED = ("dnsmasq", "nftables", "fwadmin", "fwadmin-failover.timer", "fail2ban", "nginx")


def services() -> list[ServiceState]:
    out = []
    for unit in WATCHED:
        out.append(
            ServiceState(
                unit=unit,
                active=_run("systemctl", "is-active", unit).strip() or "unknown",
                enabled=_run("systemctl", "is-enabled", unit).strip() or "unknown",
            )
        )
    return out


@dataclass
class SystemInfo:
    hostname: str = ""
    uptime: str = ""
    load: str = ""
    memory: str = ""
    disk: str = ""
    kernel: str = ""


def system() -> SystemInfo:
    info = SystemInfo()
    try:
        info.hostname = Path("/etc/hostname").read_text().strip()
    except OSError:
        pass

    try:
        seconds = float(Path("/proc/uptime").read_text().split()[0])
        days, rest = divmod(int(seconds), 86400)
        hours, minutes = divmod(rest // 60, 60)
        info.uptime = f"{days}d {hours}h {minutes}min" if days else f"{hours}h {minutes}min"
    except (OSError, ValueError):
        pass

    try:
        info.load = " ".join(Path("/proc/loadavg").read_text().split()[:3])
    except OSError:
        pass

    try:
        meminfo = dict(
            (parts[0].rstrip(":"), int(parts[1]))
            for line in Path("/proc/meminfo").read_text().splitlines()
            if len(parts := line.split()) >= 2
        )
        total = meminfo["MemTotal"] / 1048576
        used = (meminfo["MemTotal"] - meminfo["MemAvailable"]) / 1048576
        info.memory = f"{used:.1f} / {total:.1f} GB"
    except (OSError, KeyError, ValueError):
        pass

    try:
        usage = shutil.disk_usage("/")
        info.disk = f"{usage.used / 1e9:.0f} / {usage.total / 1e9:.0f} GB"
    except OSError:
        pass

    info.kernel = _run("uname", "-r").strip()
    return info


# ---------------------------------------------------------------------------
# diagnostico
# ---------------------------------------------------------------------------

HOSTSPEC = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$")


@dataclass
class Probe:
    ok: bool
    output: str
    command: str = ""


def _valid_target(target: str) -> bool:
    """So aceita hostname/IP. Fecha a porta para injecao de argumento."""
    return bool(HOSTSPEC.match(target)) and not target.startswith("-")


def ping(target: str, iface: str = "", count: int = 4) -> Probe:
    if not _valid_target(target):
        return Probe(False, f"alvo invalido: {target!r}")
    argv = ["ping", "-c", str(min(count, 10)), "-W", "2"]
    if iface:
        if not _valid_target(iface):
            return Probe(False, f"interface invalida: {iface!r}")
        argv += ["-I", iface]
    argv.append(target)
    output = _run(*argv, timeout=30)
    return Probe(bool(output), output or "sem resposta", " ".join(argv))


def traceroute(target: str) -> Probe:
    if not _valid_target(target):
        return Probe(False, f"alvo invalido: {target!r}")
    argv = ["traceroute", "-w", "2", "-q", "1", "-m", "20", target]
    output = _run(*argv, timeout=60)
    return Probe(bool(output), output or "traceroute indisponivel", " ".join(argv))


def dns_lookup(name: str) -> Probe:
    if not _valid_target(name):
        return Probe(False, f"nome invalido: {name!r}")
    argv = ["dig", "+short", "+time=2", "@127.0.0.1", name]
    output = _run(*argv, timeout=15)
    return Probe(bool(output.strip()), output or "sem resposta do resolvedor local", " ".join(argv))


def dns_answers(name: str, server: str = "127.0.0.1", timeout: float = 2.0) -> bool:
    """Pergunta um registro A direto ao resolvedor e diz se ele respondeu.

    Consulta crua de proposito: 'dig' vem do dnsutils, que nem toda instalacao
    tem, e uma prova de funcao que depende de pacote opcional vira prova
    inconclusiva justamente na caixa mais magra. Sao trinta linhas de UDP
    contra uma dependencia a mais na ISO.
    """
    if not _valid_target(name):
        return False
    query = struct.pack(">HHHHHH", 0x4157, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna" if not label.isascii() else "ascii")
        if not 0 < len(encoded) < 64:
            return False
        query += bytes([len(encoded)]) + encoded
    query += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(1232)
    except OSError:
        return False
    finally:
        sock.close()

    if len(data) < 12 or data[:2] != query[:2]:
        return False
    rcode = data[3] & 0x0F
    answers = struct.unpack(">H", data[6:8])[0]
    return rcode == 0 and answers > 0


def journal(unit: str = "", lines: int = 100) -> str:
    argv = ["journalctl", "-n", str(min(lines, 500)), "--no-pager", "-o", "short-iso"]
    if unit:
        if not _valid_target(unit):
            return f"unidade invalida: {unit!r}"
        argv += ["-u", unit]
    return _run(*argv, timeout=20) or "journal indisponivel"


def nft_ruleset() -> str:
    return _run("nft", "list", "ruleset", timeout=15) or "nft indisponivel (precisa de root)"


def routes() -> str:
    return _run("ip", "route", "show") or ""
