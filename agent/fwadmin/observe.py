"""Fotografia do sistema vivo, para o painel em modo somente leitura.

Roda como root, chamado por `fwctl observe`. Copia os arquivos de config que
o importador sabe ler para /run/fwadmin/live, no formato achatado dele, e
grava em runtime.json o que so se ve com o servico rodando (handshakes do
WireGuard, banidos do fail2ban, contadores do unbound).

Nenhum segredo sai daqui. Nas linhas de chave do WireGuard e de senha do PPP
o valor vira '<oculto>' na copia — a chave fica, porque o importador precisa
saber que o segredo mora naquele arquivo —, e a coluna de chave privada do
'wg show dump' e' descartada na leitura. O painel, que roda sem privilegio,
so ve o resultado.
"""

from __future__ import annotations

import grp
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from fwadmin import paths

LIVE = paths.RUN / "live"
RUNTIME = LIVE / "runtime.json"

GROUP = "netadm"
"""Grupo do processo web: le a fotografia, nao escreve nela."""

FILES = {
    "interfaces": "/etc/network/interfaces",
    "dnsmasq.conf": "/etc/dnsmasq.conf",
    "nftables.conf": "/etc/nftables.conf",
    "unbound/unbound.conf": "/etc/unbound/unbound.conf",
}

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

WG_SECRET = re.compile(r"^(\s*(?:PrivateKey|PresharedKey)\s*=).*$", re.IGNORECASE)
PPP_SECRET = re.compile(r"^(\s*password\b).*$", re.IGNORECASE)
HIDDEN = "<oculto>"

UNBOUND_STATS = (
    "total.num.queries",
    "total.num.cachehits",
    "total.num.cachemiss",
    "total.num.prefetch",
    "total.recursion.time.avg",
    "time.up",
)


def _run(*args: str, timeout: int = 10) -> str:
    if shutil.which(args[0]) is None:
        return ""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _strip(text: str, secret: re.Pattern[str]) -> str:
    """Troca o valor do segredo por '<oculto>', linha a linha."""
    return "".join(
        secret.sub(lambda m: f"{m.group(1)} {HIDDEN}", line.rstrip("\n")) + "\n"
        for line in text.splitlines()
    )


# ---------------------------------------------------------------------------
# arquivos
# ---------------------------------------------------------------------------


def _copy_files(dest: Path) -> list[str]:
    """Copia o que existir. Devolve os caminhos que nao deu para ler."""
    missing = []

    def put(name: str, text: str) -> None:
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    for name, source in FILES.items():
        try:
            put(name, paths.sys_path(source).read_text())
        except OSError:
            missing.append(source)

    peers = paths.sys_path("/etc/ppp/peers")
    # Link simbolico (provider -> vivo, no Debian) e' o mesmo peer com outro
    # nome; copiar os dois faria o importador ver dois links discados.
    for peer in sorted(peers.glob("*")) if peers.is_dir() else []:
        if peer.is_file() and not peer.is_symlink() and SAFE_NAME.match(peer.name):
            put(f"ppp-peers-{peer.name}", _strip(peer.read_text(), PPP_SECRET))

    wg = paths.sys_path("/etc/wireguard")
    for conf in sorted(wg.glob("*.conf")) if wg.is_dir() else []:
        if SAFE_NAME.match(conf.name):
            put(f"wireguard/{conf.name}", _strip(conf.read_text(), WG_SECRET))

    extra = paths.sys_path("/etc/unbound/unbound.conf.d")
    for conf in sorted(extra.glob("*.conf")) if extra.is_dir() else []:
        if SAFE_NAME.match(conf.name):
            put(f"unbound/unbound.conf.d/{conf.name}", conf.read_text())

    return missing


# ---------------------------------------------------------------------------
# estado de execucao
# ---------------------------------------------------------------------------


def wireguard_dump() -> dict[str, Any]:
    """'wg show all dump' sem material de chave privada.

    Linha de interface: dev, CHAVE PRIVADA, chave publica, porta, fwmark.
    Linha de peer: dev, chave publica, PSK, endpoint, allowed-ips, handshake,
    rx, tx, keepalive. As colunas secretas nem chegam a ser guardadas.
    """
    out: dict[str, Any] = {}
    for line in _run("wg", "show", "all", "dump").splitlines():
        cols = line.split("\t")
        if len(cols) == 5:
            out[cols[0]] = {"public_key": cols[2], "listen_port": cols[3], "peers": []}
        elif len(cols) == 9 and cols[0] in out:
            out[cols[0]]["peers"].append(
                {
                    "public_key": cols[1],
                    "endpoint": "" if cols[3] == "(none)" else cols[3],
                    "allowed_ips": cols[4],
                    "handshake": int(cols[5]) if cols[5].isdigit() else 0,
                    "rx": int(cols[6]) if cols[6].isdigit() else 0,
                    "tx": int(cols[7]) if cols[7].isdigit() else 0,
                }
            )
    return out


def ppp_units() -> list[str]:
    """Unidades ppp@<peer> rodando: quem sobe o PPPoE, quando e' o systemd."""
    out = _run("systemctl", "list-units", "ppp@*.service", "--plain", "--no-legend", "--all")
    return [line.split()[0] for line in out.splitlines() if line.split()[2:3] == ["active"]]


def _f2b_fields(text: str) -> dict[str, str]:
    """'|- Currently banned:\\t1' -> {'Currently banned': '1'}."""
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.lstrip(" |`-").partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def fail2ban() -> dict[str, Any] | None:
    """Jails e banidos. None = fail2ban ausente ou parado."""
    overview = _run("fail2ban-client", "status")
    if not overview:
        return None
    names = [
        n.strip()
        for n in _f2b_fields(overview).get("Jail list", "").split(",")
        if SAFE_NAME.match(n.strip())
    ]
    jails = []
    for name in names:
        fields = _f2b_fields(_run("fail2ban-client", "status", name))
        jail: dict[str, Any] = {
            "name": name,
            "failed": fields.get("Currently failed", "0"),
            "failed_total": fields.get("Total failed", "0"),
            "banned": fields.get("Currently banned", "0"),
            "banned_total": fields.get("Total banned", "0"),
            "ips": fields.get("Banned IP list", "").split(),
        }
        for opt in ("bantime", "findtime", "maxretry"):
            jail[opt] = _run("fail2ban-client", "get", name, opt).strip()
        jails.append(jail)
    return {"jails": jails}


def unbound_stats() -> dict[str, str] | None:
    raw = _run("unbound-control", "stats_noreset")
    if not raw:
        return None
    stats = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    return {key: stats[key] for key in UNBOUND_STATS if key in stats}


# ---------------------------------------------------------------------------
# a fotografia
# ---------------------------------------------------------------------------


def _share(root: Path) -> None:
    """Deixa a fotografia legivel pelo grupo do painel, e so por ele."""
    try:
        gid = grp.getgrnam(GROUP).gr_gid if os.geteuid() == 0 else -1
    except KeyError:
        gid = -1
    for path in [root, *root.rglob("*")]:
        path.chmod(0o750 if path.is_dir() else 0o640)
        if gid >= 0:
            os.chown(path, 0, gid)


def collect() -> Path:
    """Tira a fotografia e troca a anterior de uma vez.

    Monta num diretorio novo e so entao renomeia: quem estiver lendo nunca ve
    uma fotografia pela metade.
    """
    paths.RUN.mkdir(parents=True, exist_ok=True)
    fresh = paths.RUN / f"live.{os.getpid()}"
    shutil.rmtree(fresh, ignore_errors=True)
    fresh.mkdir()

    missing = _copy_files(fresh)
    runtime = {"taken_at": time.time(), "missing": missing}
    if paths.sandboxed():
        # No sandbox os binarios seriam os da maquina de quem testa. O estado
        # de execucao vem de um arquivo de mentira, se houver.
        fixture = paths.SYSROOT / "runtime-fixture.json"
        fake = json.loads(fixture.read_text()) if fixture.exists() else {}
        runtime |= {key: fake.get(key) for key in ("wireguard", "fail2ban", "unbound", "ppp_units")}
    else:
        runtime |= {
            "wireguard": wireguard_dump(),
            "fail2ban": fail2ban(),
            "unbound": unbound_stats(),
            "ppp_units": ppp_units(),
        }
    (fresh / "runtime.json").write_text(json.dumps(runtime, indent=1))
    _share(fresh)

    old = paths.RUN / "live.old"
    shutil.rmtree(old, ignore_errors=True)
    if LIVE.exists():
        LIVE.rename(old)
    fresh.rename(LIVE)
    shutil.rmtree(old, ignore_errors=True)
    return LIVE
