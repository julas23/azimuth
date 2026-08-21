"""
Gerencia a lista de CIDRs de serviços brasileiros para split tunnel.

Fluxo:
  1. APScheduler chama resolve_and_cache() a cada 4h
  2. Resolve todos os domínios de brazil_services.json via DNS
  3. Salva resultado em /var/lib/vpn-web/brazil_cidrs_cache.json
  4. Se a lista mudou, marca todos os peers ativos como config_stale=True
  5. get_allowed_ips(dns_gateway) monta a string AllowedIPs para o .conf WireGuard
"""
import asyncio
import hashlib
import json
import logging
import socket
from pathlib import Path

log = logging.getLogger("brazil_cidrs")

_DATA_FILE  = Path(__file__).parent.parent / "data" / "brazil_services.json"
_CACHE_FILE = Path("/app/cache/brazil_cidrs_cache.json")


def _load_services() -> dict:
    return json.loads(_DATA_FILE.read_text())


def _all_domains(services: dict) -> list[str]:
    domains = []
    for cat in services["domains"].values():
        domains.extend(e["domain"] for e in cat)
    return domains


async def _resolve(domain: str) -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.run_in_executor(
            None, socket.getaddrinfo, domain, None, socket.AF_INET
        )
        return list({info[4][0] for info in infos})
    except Exception:
        return []


async def resolve_and_cache() -> list[str]:
    """Resolve todos os domínios e persiste o cache. Retorna a lista completa de CIDRs."""
    services = _load_services()
    static = [e["cidr"] for e in services["static_cidrs"]]
    domains = _all_domains(services)

    results = await asyncio.gather(*[_resolve(d) for d in domains], return_exceptions=True)

    resolved: list[str] = []
    for r in results:
        if isinstance(r, list):
            resolved.extend(f"{ip}/32" for ip in r)

    # Deduplica mantendo ordem: estáticos primeiro, resolvidos depois
    seen: set[str] = set()
    all_cidrs: list[str] = []
    for c in static + resolved:
        if c not in seen:
            seen.add(c)
            all_cidrs.append(c)

    fp = hashlib.sha256(json.dumps(all_cidrs).encode()).hexdigest()[:12]
    _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_FILE.write_text(json.dumps({"cidrs": all_cidrs, "fingerprint": fp}, indent=2))

    log.info(
        "brazil_cidrs: %d CIDRs (%d estáticos + %d resolvidos de %d domínios)",
        len(all_cidrs), len(static), len(resolved), len(domains),
    )
    return all_cidrs


def get_allowed_ips(dns_gateway: str) -> str:
    """
    Retorna string AllowedIPs para o config WireGuard (split tunnel).

    NÃO usado desde 2026-08-16: o .conf passou a usar full tunnel (0.0.0.0/0)
    em wg_config.py. Mantido para rollback ao split tunnel.

    O gateway DNS do plano é sempre o primeiro entry (necessário para que
    consultas DNS cheguem ao dnsmasq do servidor via túnel).
    """
    cidrs: list[str] = [f"{dns_gateway}/32"]

    if _CACHE_FILE.exists():
        try:
            cache = json.loads(_CACHE_FILE.read_text())
            cidrs.extend(cache["cidrs"])
        except Exception:
            log.warning("brazil_cidrs: falha ao ler cache, usando apenas estáticos")

    if len(cidrs) == 1:
        # Sem cache ainda — fallback para CIDRs estáticos do JSON
        services = _load_services()
        cidrs.extend(e["cidr"] for e in services["static_cidrs"])

    return ", ".join(cidrs)


def get_cached_cidrs() -> list[str]:
    """CIDRs da allowlist já resolvidos. Cai nos estáticos se não houver cache."""
    if _CACHE_FILE.exists():
        try:
            return json.loads(_CACHE_FILE.read_text())["cidrs"]
        except Exception:
            log.warning("brazil_cidrs: cache ilegível, usando apenas estáticos")
    return [e["cidr"] for e in _load_services()["static_cidrs"]]


def get_fingerprint() -> str:
    """Retorna o fingerprint atual da lista cacheada (vazio se não há cache)."""
    if _CACHE_FILE.exists():
        try:
            return json.loads(_CACHE_FILE.read_text()).get("fingerprint", "")
        except Exception:
            pass
    return ""
