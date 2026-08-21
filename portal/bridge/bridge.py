#!/usr/bin/env python3
"""
vpn-bridge — daemon Unix socket para operações privilegiadas de WireGuard/NFTables.

Escuta em /run/vpn-bridge/bridge.sock (grupo vpnbridge, modo 0660).
Aceita uma requisição JSON por conexão, retorna JSON.

Comandos: add_peer, remove_peer, set_quota, clear_quota, get_stats, genkeys,
          resolve_whitelist, update_bandwidth, sync_split_tunnel
"""

import asyncio
import fcntl
import grp
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import subprocess
from pathlib import Path

# ── Configuração ────────────────────────────────────────────────────────────────

SOCKET_PATH    = "/run/vpn-bridge/bridge.sock"
WG_IFACE       = "wg0"
IFB_IFACE      = "ifb0"
PEERS_FILE     = "/etc/wireguard/peers-dynamic.conf"
LOG_FILE       = "/var/log/vpn-bridge.log"
SOCKET_GROUP   = "vpnbridge"
TC_STATE_FILE  = "/var/lib/vpn-bridge/tc-peers.json"
TC_CLASS_START = 0x100  # classid mínimo (256); range 256-4094

VPN_SUBNETS = [
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("10.50.0.0/16"),
    ipaddress.ip_network("10.100.0.0/16"),
    ipaddress.ip_network("10.200.0.0/16"),
]

# ── Validação ───────────────────────────────────────────────────────────────────

_KEY_RE  = re.compile(r'^[A-Za-z0-9+/]{43}=$')
_FQDN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

def _valid_key(k: str) -> bool:
    return bool(_KEY_RE.match(k))

def _valid_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in VPN_SUBNETS)
    except ValueError:
        return False

def _valid_domain(d: str) -> bool:
    return len(d) <= 253 and bool(_FQDN_RE.match(d))

# ── Helpers de execução ─────────────────────────────────────────────────────────

def _run(*args: str, stdin: str | None = None) -> tuple[int, str, str]:
    r = subprocess.run(
        list(args), input=stdin,
        capture_output=True, text=True, timeout=15
    )
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def _nft(expr: str) -> tuple[int, str, str]:
    """Executa um comando nft via stdin (evita problemas com { } no shell)."""
    return _run("nft", "-f", "-", stdin=expr)

# ── TC por peer ─────────────────────────────────────────────────────────────────

def _tc_state_load() -> dict:
    try:
        with open(TC_STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _tc_state_save(state: dict) -> None:
    os.makedirs(os.path.dirname(TC_STATE_FILE), exist_ok=True)
    tmp = TC_STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, TC_STATE_FILE)


def _tc_next_classid(state: dict) -> int:
    used = {v["classid"] for v in state.values() if "classid" in v}
    cid = TC_CLASS_START
    while cid in used:
        cid += 1
    return cid


def _tc_class_op(op: str, dev: str, classid: int, rate_kbit: int) -> None:
    """add ou change uma HTB class. burst ≈ rate/8 KB (pelo menos 32 KB)."""
    burst = f"{max(32, rate_kbit // 8)}k"
    _run("tc", "class", op, "dev", dev,
         "parent", "1:1", "classid", f"1:{classid}",
         "htb", "rate", f"{rate_kbit}kbit", "ceil", f"{rate_kbit}kbit",
         "burst", burst)


def _tc_add_peer_rules(ip: str, classid: int, bandwidth_mbps: int) -> None:
    """Cria HTB class + filtro u32 em wg0 (download) e ifb0 (upload)."""
    rate_kbit = bandwidth_mbps * 1000
    hex_cid   = format(classid, "x")

    for dev, match_field in ((WG_IFACE, "dst"), (IFB_IFACE, "src")):
        _tc_class_op("add", dev, classid, rate_kbit)
        # handle explícito = 800::classid (nodeid único dentro do hash-table padrão)
        _run("tc", "filter", "add", "dev", dev,
             "parent", "1:", "protocol", "ip", "prio", "10",
             "handle", f"800::{hex_cid}",
             "u32", "match", "ip", match_field, f"{ip}/32",
             "flowid", f"1:{classid}")


def _tc_change_rate(classid: int, rate_kbit: int) -> None:
    """Altera rate de uma class existente (set_quota / clear_quota)."""
    for dev in (WG_IFACE, IFB_IFACE):
        _tc_class_op("change", dev, classid, rate_kbit)


def _tc_remove_peer_rules(classid: int) -> None:
    """Remove filtro u32 e HTB class em ambas as interfaces."""
    hex_cid = format(classid, "x")
    for dev in (WG_IFACE, IFB_IFACE):
        _run("tc", "filter", "del", "dev", dev,
             "parent", "1:", "protocol", "ip", "prio", "10",
             "handle", f"800::{hex_cid}", "u32")
        _run("tc", "class", "del", "dev", dev,
             "parent", "1:1", "classid", f"1:{classid}")


# ── Gerenciamento de peers-dynamic.conf ─────────────────────────────────────────

def _peers_append(pubkey: str, ip: str, label: str = "") -> None:
    path = Path(PEERS_FILE)
    if path.exists():
        with open(path, "r") as f:
            if f"PublicKey = {pubkey}" in f.read():
                return
    comment = f"  # {label}" if label else ""
    with open(PEERS_FILE, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(f"\n[Peer]{comment}\n")
        f.write(f"PublicKey = {pubkey}\n")
        f.write(f"AllowedIPs = {ip}/32\n")

def _peers_remove(pubkey: str) -> None:
    path = Path(PEERS_FILE)
    if not path.exists():
        return

    with open(path, "r") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        lines = f.readlines()

    out, i = [], 0
    while i < len(lines):
        if lines[i].lstrip().startswith("[Peer]"):
            # Coleta o bloco inteiro
            block, j = [lines[i]], i + 1
            while j < len(lines) and not lines[j].lstrip().startswith("["):
                block.append(lines[j])
                j += 1
            if any(f"PublicKey = {pubkey}" in ln for ln in block):
                # Remove blank line anterior se existir
                while out and out[-1].strip() == "":
                    out.pop()
                i = j
                continue
            out.extend(block)
            i = j
        else:
            out.append(lines[i])
            i += 1

    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.writelines(out)

# ── Handlers de ação ────────────────────────────────────────────────────────────

async def _add_peer(p: dict) -> dict:
    key           = p.get("pubkey", "")
    ip            = p.get("ip", "")
    label         = str(p.get("label", ""))[:80]
    bandwidth_mbps = int(p.get("bandwidth_mbps", 0))

    if not _valid_key(key): return {"ok": False, "error": "pubkey inválida"}
    if not _valid_ip(ip):   return {"ok": False, "error": "IP inválido ou fora dos subnets VPN"}

    rc, _, err = _run("wg", "set", WG_IFACE, "peer", key, "allowed-ips", f"{ip}/32")
    if rc != 0:
        return {"ok": False, "error": f"wg set: {err}"}

    _peers_append(key, ip, label)

    # Configura TC por peer (só se bandwidth_mbps fornecido e IP ainda não mapeado)
    if bandwidth_mbps > 0:
        state = _tc_state_load()
        if ip not in state:
            classid = _tc_next_classid(state)
            try:
                _tc_add_peer_rules(ip, classid, bandwidth_mbps)
                state[ip] = {"classid": classid, "bandwidth_mbps": bandwidth_mbps, "throttled": False}
                _tc_state_save(state)
                logging.info("tc add_peer ip=%s classid=%s bw=%dMbps", ip, hex(classid), bandwidth_mbps)
            except Exception as exc:
                logging.warning("tc add_peer falhou ip=%s: %s", ip, exc)

    logging.info("add_peer ip=%s label=%r", ip, label)
    return {"ok": True}


async def _remove_peer(p: dict) -> dict:
    key = p.get("pubkey", "")
    if not _valid_key(key): return {"ok": False, "error": "pubkey inválida"}

    # Descobre IP do peer antes de removê-lo (para limpar TC)
    peer_ip = None
    rc_dump, dump_out, _ = _run("wg", "show", WG_IFACE, "dump")
    if rc_dump == 0:
        for line in dump_out.splitlines()[1:]:
            cols = line.split("\t")
            if cols and cols[0] == key and len(cols) >= 4:
                allowed = cols[3]  # "10.50.x.y/32"
                peer_ip = allowed.split("/")[0]
                break

    rc, _, err = _run("wg", "set", WG_IFACE, "peer", key, "remove")
    if rc != 0:
        return {"ok": False, "error": f"wg set: {err}"}

    _peers_remove(key)

    if peer_ip:
        state = _tc_state_load()
        info  = state.pop(peer_ip, None)
        if info:
            try:
                _tc_remove_peer_rules(info["classid"])
                _tc_state_save(state)
                logging.info("tc remove_peer ip=%s classid=%s", peer_ip, hex(info["classid"]))
            except Exception as exc:
                logging.warning("tc remove_peer falhou ip=%s: %s", peer_ip, exc)

    logging.info("remove_peer pubkey=%s…", key[:8])
    return {"ok": True}


async def _set_quota(p: dict) -> dict:
    ip = p.get("ip", "")
    if not _valid_ip(ip): return {"ok": False, "error": "IP inválido"}

    rc, _, err = _nft(f"add element ip wg-plans quota-exceeded {{ {ip} timeout 31d }}")
    if rc != 0:
        return {"ok": False, "error": f"nft: {err}"}

    # Throttle TC: reduz rate da class do peer para 512 kbps
    state = _tc_state_load()
    info  = state.get(ip)
    if info:
        try:
            _tc_change_rate(info["classid"], 512)
            info["throttled"] = True
            _tc_state_save(state)
            logging.info("tc set_quota ip=%s classid=%s → 512kbps", ip, hex(info["classid"]))
        except Exception as exc:
            logging.warning("tc set_quota falhou ip=%s: %s", ip, exc)

    logging.info("set_quota ip=%s", ip)
    return {"ok": True}


async def _clear_quota(p: dict) -> dict:
    ip = p.get("ip", "")
    if not _valid_ip(ip): return {"ok": False, "error": "IP inválido"}

    _nft(f"delete element ip wg-plans quota-exceeded {{ {ip} }}")  # ignora se ausente

    # Restaura TC: retorna ao rate original do plano
    state = _tc_state_load()
    info  = state.get(ip)
    if info:
        try:
            bw    = info.get("bandwidth_mbps", 10)
            _tc_change_rate(info["classid"], bw * 1000)
            info["throttled"] = False
            _tc_state_save(state)
            logging.info("tc clear_quota ip=%s classid=%s → %dMbps", ip, hex(info["classid"]), bw)
        except Exception as exc:
            logging.warning("tc clear_quota falhou ip=%s: %s", ip, exc)

    logging.info("clear_quota ip=%s", ip)
    return {"ok": True}


async def _get_stats(p: dict) -> dict:
    key = p.get("pubkey", "")
    if not _valid_key(key): return {"ok": False, "error": "pubkey inválida"}

    rc, out, err = _run("wg", "show", WG_IFACE, "dump")
    if rc != 0:
        return {"ok": False, "error": f"wg show: {err}"}

    # Primeira linha = interface; demais = peers (tab-separated)
    # Colunas peer: pubkey, preshared, endpoint, allowed-ips, handshake, rx, tx, keepalive
    for line in out.splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) >= 7 and cols[0] == key:
            return {
                "ok":               True,
                "endpoint":         cols[2],
                "allowed_ips":      cols[3],
                "latest_handshake": int(cols[4]),
                "rx_bytes":         int(cols[5]),
                "tx_bytes":         int(cols[6]),
            }

    return {"ok": False, "error": "peer não encontrado"}


async def _genkeys(_p: dict) -> dict:
    rc, privkey, err = _run("wg", "genkey")
    if rc != 0:
        return {"ok": False, "error": f"wg genkey: {err}"}

    proc = subprocess.run(
        ["wg", "pubkey"], input=privkey,
        capture_output=True, text=True, timeout=5
    )
    if proc.returncode != 0:
        return {"ok": False, "error": f"wg pubkey: {proc.stderr.strip()}"}

    return {"ok": True, "privkey": privkey, "pubkey": proc.stdout.strip()}


async def _resolve_whitelist(p: dict) -> dict:
    domains = p.get("domains", [])
    if not isinstance(domains, list) or len(domains) > 10:
        return {"ok": False, "error": "domains deve ser lista de até 10 itens"}

    loop     = asyncio.get_running_loop()
    resolved : dict[str, list[str]] = {}
    failed   : list[str] = []

    for domain in domains:
        if not _valid_domain(domain):
            failed.append(domain)
            continue
        try:
            infos = await loop.run_in_executor(
                None,
                lambda d=domain: socket.getaddrinfo(d, None, socket.AF_INET)
            )
            ips = list({i[4][0] for i in infos})
            resolved[domain] = ips
            for ip in ips:
                _nft(f"add element ip wg-plans basic-whitelist {{ {ip} timeout 6h }}")
        except Exception as exc:
            logging.warning("resolve_whitelist %s: %s", domain, exc)
            failed.append(domain)

    logging.info("resolve_whitelist domains=%d resolved=%d failed=%d",
                 len(domains), len(resolved), len(failed))
    return {"ok": True, "resolved": resolved, "failed": failed}


async def _sync_split_tunnel(p: dict) -> dict:
    """Repopula o set wg-plans/split-tunnel com a allowlist do split tunnel.

    A plan-policy usa este set para dois casos: peers basic só alcançam o que
    está aqui (ou na basic-whitelist dos domínios custom), e peers standard têm
    accept explícito nele antes do drop de streaming.

    O set é `flags interval`, que rejeita intervalos sobrepostos — a lista do
    app tem /32 resolvidos dentro de faixas estáticas (ex: 45.57.90.1/32 dentro
    de 45.57.0.0/17), então é obrigatório colapsar antes de aplicar.
    """
    cidrs = p.get("cidrs", [])
    if not isinstance(cidrs, list) or not cidrs:
        return {"ok": False, "error": "cidrs deve ser lista não vazia"}
    if len(cidrs) > 5000:
        return {"ok": False, "error": "cidrs excede o limite de 5000 entradas"}

    nets = []
    invalid = 0
    for c in cidrs:
        try:
            net = ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            invalid += 1
            continue
        if net.version != 4 or net.is_private or net.is_loopback or net.is_link_local:
            invalid += 1
            continue
        nets.append(net)

    if not nets:
        return {"ok": False, "error": "nenhum CIDR público válido na lista"}

    collapsed = [str(n) for n in ipaddress.collapse_addresses(nets)]

    rc, _, err = _nft("flush set ip wg-plans split-tunnel")
    if rc != 0:
        return {"ok": False, "error": f"nft flush: {err}"}

    applied = 0
    for i in range(0, len(collapsed), 200):
        chunk = collapsed[i : i + 200]
        rc, _, err = _nft(
            f"add element ip wg-plans split-tunnel {{ {', '.join(chunk)} }}"
        )
        if rc != 0:
            logging.error("sync_split_tunnel: falha no lote %d: %s", i // 200, err)
            return {"ok": False, "error": f"nft add: {err}", "applied": applied}
        applied += len(chunk)

    logging.info(
        "sync_split_tunnel: %d CIDRs aplicados (%d recebidos, %d colapsados, %d inválidos)",
        applied, len(cidrs), len(collapsed), invalid,
    )
    return {"ok": True, "applied": applied, "received": len(cidrs), "invalid": invalid}


async def _update_bandwidth(p: dict) -> dict:
    ip  = p.get("ip", "")
    bw  = p.get("bandwidth_mbps", 0)
    if not _valid_ip(ip):
        return {"ok": False, "error": "IP inválido"}
    if not isinstance(bw, int) or bw <= 0:
        return {"ok": False, "error": "bandwidth_mbps inválido"}

    state = _tc_state_load()
    info  = state.get(ip)
    if not info:
        return {"ok": False, "error": "peer não encontrado no estado TC"}

    rate_kbit = bw * 1000
    try:
        _tc_change_rate(info["classid"], rate_kbit)
        info["bandwidth_mbps"] = bw
        info["throttled"] = False
        _tc_state_save(state)
        logging.info("update_bandwidth ip=%s → %dMbps", ip, bw)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    return {"ok": True}


# ── Dispatcher ──────────────────────────────────────────────────────────────────

_HANDLERS = {
    "add_peer":          _add_peer,
    "remove_peer":       _remove_peer,
    "set_quota":         _set_quota,
    "clear_quota":       _clear_quota,
    "get_stats":         _get_stats,
    "genkeys":           _genkeys,
    "resolve_whitelist": _resolve_whitelist,
    "update_bandwidth":  _update_bandwidth,
    "sync_split_tunnel": _sync_split_tunnel,
}


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername", "?")
    try:
        # Protocolo é JSON delimitado por newline; readline() não trunca
        # payloads grandes como o read(8192) anterior fazia.
        raw = await asyncio.wait_for(reader.readline(), timeout=10.0)
        req = json.loads(raw)
        action = str(req.get("action", ""))

        handler = _HANDLERS.get(action)
        if not handler:
            resp: dict = {"ok": False, "error": f"ação desconhecida: {action!r}"}
        else:
            resp = await handler(req)

        writer.write(json.dumps(resp).encode())
        await writer.drain()

    except asyncio.TimeoutError:
        logging.warning("timeout cliente %s", peer)
    except json.JSONDecodeError:
        writer.write(json.dumps({"ok": False, "error": "JSON inválido"}).encode())
        await writer.drain()
    except Exception:
        logging.exception("erro não tratado")
        writer.write(json.dumps({"ok": False, "error": "erro interno"}).encode())
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ── Entry point ─────────────────────────────────────────────────────────────────

async def _amain() -> None:
    sock_path = Path(SOCKET_PATH)
    sock_path.parent.mkdir(parents=True, mode=0o750, exist_ok=True)

    if sock_path.exists():
        sock_path.unlink()

    Path(PEERS_FILE).touch(mode=0o600, exist_ok=True)

    # limit acima do default (64 KiB) porque sync_split_tunnel manda a
    # allowlist inteira num único payload
    server = await asyncio.start_unix_server(
        _handle, path=str(sock_path), limit=1024 * 1024
    )

    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(str(sock_path), 0, gid)
    except KeyError:
        logging.warning("grupo %r não encontrado; socket ficará root:root", SOCKET_GROUP)
    os.chmod(str(sock_path), 0o660)

    logging.info("vpn-bridge escutando em %s", sock_path)

    loop = asyncio.get_running_loop()
    stop: asyncio.Future = loop.create_future()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: stop.set_result(None) if not stop.done() else None)

    async with server:
        await stop

    logging.info("vpn-bridge encerrado")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(),
        ],
    )
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
