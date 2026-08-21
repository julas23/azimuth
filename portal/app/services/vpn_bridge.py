"""
Async client for the vpn-bridge Unix socket daemon.

The daemon speaks newline-delimited JSON:
  request:  { "action": "...", ...fields }
  response: { "ok": true/false, "error": "...", ...payload }

Field names match the bridge handlers:
  add_peer/remove_peer/get_stats use "pubkey" (not "public_key")
  set_quota/clear_quota use "ip"
  genkeys returns {"pubkey": "...", "privkey": "..."}
"""
import asyncio
import json
from config import settings


class BridgeError(Exception):
    pass


async def _call(payload: dict) -> dict:
    reader, writer = await asyncio.open_unix_connection(settings.BRIDGE_SOCKET)
    try:
        writer.write(json.dumps(payload).encode() + b"\n")
        await writer.drain()
        line = await reader.readline()
        response = json.loads(line)
        if not response.get("ok"):
            raise BridgeError(response.get("error", "bridge error"))
        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def add_peer(public_key: str, ip: str, label: str = "", bandwidth_mbps: int = 0) -> None:
    await _call({
        "action": "add_peer",
        "pubkey": public_key,
        "ip": ip,
        "label": label,
        "bandwidth_mbps": bandwidth_mbps,
    })


async def remove_peer(public_key: str) -> None:
    await _call({"action": "remove_peer", "pubkey": public_key})


async def set_quota(ip: str) -> None:
    await _call({"action": "set_quota", "ip": ip})


async def clear_quota(ip: str) -> None:
    await _call({"action": "clear_quota", "ip": ip})


async def get_stats(public_key: str) -> dict:
    return await _call({"action": "get_stats", "pubkey": public_key})


async def genkeys() -> dict:
    """Returns {"pubkey": "...", "privkey": "..."}"""
    return await _call({"action": "genkeys"})


async def resolve_whitelist(domains: list[str]) -> dict:
    """Resolve DNS e atualiza basic-whitelist NFTables. Returns {"resolved": {...}, "failed": [...]}"""
    return await _call({"action": "resolve_whitelist", "domains": domains})


async def update_bandwidth(ip: str, bandwidth_mbps: int) -> dict:
    """Atualiza o rate TC do peer e persiste no state file do bridge."""
    return await _call({"action": "update_bandwidth", "ip": ip, "bandwidth_mbps": bandwidth_mbps})


async def sync_split_tunnel(cidrs: list[str]) -> dict:
    """Repopula o set NFTables wg-plans/split-tunnel com a allowlist.

    A plan-policy depende deste set: peers basic só alcançam o que está nele,
    e peers standard têm accept explícito nele antes do drop de streaming.
    """
    return await _call({"action": "sync_split_tunnel", "cidrs": cidrs})
