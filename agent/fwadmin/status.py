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
    reserved = {r.mac for r in cfg.dhcp.reservations if r.enabled} if cfg else set()
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
class UnitInfo:
    """O que a tela de Servicos sabe de um servico da stack."""

    unit: str
    package: str
    installed: bool = False
    version: str = ""
    active: str = "inactive"
    """ActiveState do systemd: active, inactive, failed, activating,
    deactivating, reloading."""

    sub: str = ""
    enabled: str = ""
    since: float = 0.0
    memory: int = 0
    can_reload: bool = False

    @property
    def running(self) -> bool:
        return self.active in ("active", "reloading")

    @property
    def busy(self) -> bool:
        """No meio de uma transicao: nenhum botao vale ate ela terminar."""
        return self.active in ("activating", "deactivating", "reloading")

    @property
    def stopped(self) -> bool:
        return self.active in ("inactive", "failed")


def unit_info(unit: str, package: str) -> UnitInfo:
    """Estado da unidade pelo 'systemctl show' e do pacote pelo dpkg.

    Os dois funcionam sem privilegio. Unidade que o systemd nao conhece e
    pacote ausente contam como 'nao instalado' — e' o que habilita o botao
    de instalar.
    """
    info = UnitInfo(unit=unit, package=package)
    raw = _run(
        "systemctl", "show", unit,
        "-p", "LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestamp,"
        "CanReload,MemoryCurrent",
        "--timestamp=unix",
    )
    props = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    pkg = _run("dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", package).split()
    info.installed = bool(pkg) and pkg[0] == "installed" and props.get("LoadState") != "not-found"
    info.version = pkg[1] if len(pkg) > 1 else ""
    info.active = props.get("ActiveState", "inactive") or "inactive"
    info.sub = props.get("SubState", "")
    info.enabled = props.get("UnitFileState", "")
    info.can_reload = props.get("CanReload") == "yes"
    stamp = props.get("ActiveEnterTimestamp", "").lstrip("@")
    info.since = float(stamp) if stamp.isdigit() else 0.0
    memory = props.get("MemoryCurrent", "")
    info.memory = int(memory) if memory.isdigit() else 0
    return info


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


@dataclass
class WGState:
    """O que se ve de um tunel vivo. Nunca guarda material de chave."""

    up: bool = False
    listen_port: int = 0
    peers: int = 0
    handshakes: int = 0
    """Peers que ja fecharam handshake alguma vez."""

    last_handshake: int = -1
    """Segundos desde o handshake mais recente. -1 = nenhum peer conectou."""

    has_key: bool = False
    """O dispositivo tem chave privada. So o fato; a chave nunca sai daqui."""


def wireguard(device: str) -> WGState | None:
    """Le 'wg show <dev> dump'. None = nao deu para observar.

    A PRIMEIRA COLUNA do dump e' a chave privada do dispositivo. Ela e' lida e
    descartada aqui, e nada dela sai desta funcao — nem para prova, nem para
    log, nem para tela.
    """
    if not _valid_target(device):
        return None
    raw = _run("wg", "show", device, "dump")
    if not raw.strip():
        return None

    linhas = [linha.split("\t") for linha in raw.strip().splitlines()]
    cabeca = linhas[0]
    estado = WGState(up=True)
    estado.has_key = bool(cabeca[0]) and cabeca[0] != "(none)"
    if len(cabeca) >= 3 and cabeca[2].isdigit():
        estado.listen_port = int(cabeca[2])

    agora = int(time.time())
    for peer in linhas[1:]:
        if len(peer) < 5:
            continue
        estado.peers += 1
        quando = int(peer[4]) if peer[4].isdigit() else 0
        if quando:
            estado.handshakes += 1
            idade = max(0, agora - quando)
            if estado.last_handshake < 0 or idade < estado.last_handshake:
                estado.last_handshake = idade
    return estado


@dataclass(frozen=True)
class DnsReply:
    rcode: int
    """0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN."""
    answers: int
    authentic: bool
    """Flag AD: o resolvedor validou a resposta por DNSSEC."""
    txt: tuple[str, ...] = ()


QTYPES = {"A": 1, "TXT": 16}


def _skip_name(data: bytes, i: int) -> int:
    """Pula um nome no pacote, inclusive comprimido. Devolve o indice seguinte."""
    while i < len(data):
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n
    raise ValueError("nome truncado")


def dns_query(
    name: str, server: str = "127.0.0.1", port: int = 53, qtype: str = "A", timeout: float = 2.0
) -> DnsReply | None:
    """Uma consulta DNS crua, por UDP. None = ninguem respondeu.

    Consulta crua de proposito: 'dig' vem do dnsutils, que nem toda instalacao
    tem, e uma prova de funcao que depende de pacote opcional vira prova
    inconclusiva justamente na caixa mais magra. Sao poucas linhas de UDP
    contra uma dependencia a mais na ISO.
    """
    if not _valid_target(name):
        return None
    # RD + AD, e um registro EDNS com o bit DO: sem EDNS a resposta para em
    # 512 bytes e um TXT maior volta truncado, vazio; sem DO, quem fica no
    # meio (o dnsmasq) nao repassa a flag de validacao.
    query = struct.pack(">HHHHHH", 0x4157, 0x0120, 1, 0, 0, 1)
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna" if not label.isascii() else "ascii")
        if not 0 < len(encoded) < 64:
            return None
        query += bytes([len(encoded)]) + encoded
    query += b"\x00" + struct.pack(">HH", QTYPES[qtype], 1)
    query += b"\x00" + struct.pack(">HHIH", 41, 1232, 0x8000, 0)  # OPT, DO

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, port))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()

    if len(data) < 12 or data[:2] != query[:2]:
        return None
    flags, qd, an = struct.unpack(">HHH", data[2:8])
    txt: list[str] = []
    try:
        i = 12
        for _ in range(qd):
            i = _skip_name(data, i) + 4
        for _ in range(an):
            i = _skip_name(data, i)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i : i + 10])
            i += 10
            if rtype == 16:
                j, end, parts = i, i + rdlen, []
                while j < end:
                    n = data[j]
                    parts.append(data[j + 1 : j + 1 + n].decode("utf-8", "replace"))
                    j += 1 + n
                txt.append("".join(parts))
            i += rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return DnsReply(rcode=flags & 0x0F, answers=an, authentic=bool(flags & 0x0020), txt=tuple(txt))


def dns_answers(name: str, server: str = "127.0.0.1", timeout: float = 2.0) -> bool:
    """Pergunta um registro A direto ao resolvedor e diz se ele respondeu."""
    reply = dns_query(name, server, timeout=timeout)
    return reply is not None and reply.rcode == 0 and reply.answers > 0


# ---------------------------------------------------------------------------
# discos — o que a pagina de Storage mostra (STORAGE.md)
# ---------------------------------------------------------------------------

SYSTEM_MOUNTS = {"/", "/boot", "/boot/efi", "/usr", "/var", "[SWAP]"}


@dataclass
class Disk:
    path: str
    by_id: str
    """Nome em /dev/disk/by-id: modelo + serie. E' por ele que o modulo
    identifica disco, porque /dev/sdX muda de um boot para outro."""

    model: str
    serial: str
    size: int
    rotational: bool
    transport: str
    removable: bool
    role: str
    """'sistema', 'em uso' ou 'livre'."""

    parts: list[dict[str, str]] = field(default_factory=list)


def disks() -> list[Disk]:
    """Discos inteiros, com o papel de cada um. Sem privilegio: o lsblk le o sysfs."""
    raw = _run(
        "lsblk", "-J", "-b", "-o",
        "NAME,PATH,SIZE,TYPE,MODEL,SERIAL,ROTA,TRAN,FSTYPE,MOUNTPOINTS,ID-LINK,RM",
    )
    try:
        devices = json.loads(raw).get("blockdevices", []) if raw else []
    except ValueError:
        return []

    def walk(node: dict) -> list[dict]:
        out = [node]
        for child in node.get("children") or []:
            out += walk(child)
        return out

    out = []
    for dev in devices:
        if dev.get("type") != "disk" or str(dev.get("name", "")).startswith(("zram", "ram")):
            continue
        nodes = walk(dev)
        mounts = {m for n in nodes for m in (n.get("mountpoints") or []) if m}
        parts = [
            {"name": n.get("name", ""), "fstype": n.get("fstype") or "", "mount": ", ".join(m for m in (n.get("mountpoints") or []) if m)}
            for n in nodes[1:]
        ]
        if mounts & SYSTEM_MOUNTS:
            role = "sistema"
        elif mounts or any(n.get("fstype") for n in nodes) or parts:
            role = "em uso"
        else:
            role = "livre"
        out.append(
            Disk(
                path=dev.get("path", ""),
                by_id=dev.get("id-link") or "",
                model=(dev.get("model") or "").strip(),
                serial=(dev.get("serial") or "").strip(),
                size=int(dev.get("size") or 0),
                rotational=bool(dev.get("rota")),
                transport=dev.get("tran") or "",
                removable=bool(dev.get("rm")),
                role=role,
                parts=parts,
            )
        )
    return out


def storage_layout(n_free: int, separate_system: bool) -> tuple[str, str]:
    """(titulo, explicacao) do layout que o STORAGE.md escolhe para estes discos."""
    if n_free == 0:
        if separate_system:
            return ("só o disco do sistema", "Sem disco livre para dados. Com um disco a mais, os dados vão para ele, em volume próprio; com dois, em espelho.")
        return ("nenhum disco", "Nenhum disco encontrado.")
    if n_free == 1:
        return ("linear no disco de dados", "Os dados ficam num disco só, sem redundância. Um segundo disco entra depois sem reformatar nada e vira espelho, com o volume em uso.")
    if n_free == 2:
        return ("espelho: matriz + cópia", "Toda escrita vai para os dois discos; as leituras saem da matriz. Se a matriz morre, a cópia assume sem perder nada e sem parar o serviço.")
    return (
        f"espelho em dois, {n_free - 2} de reserva",
        "O espelho usa dois discos; os outros ficam de reserva e entram sozinhos se um do espelho falhar.",
    )


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
