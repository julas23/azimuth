#!/usr/bin/env python3
"""Le a configuracao viva do firewall e produz o config.yaml inicial.

Nao comecamos de uma folha em branco: tudo que ja esta rodando no HP entra no
modelo, inclusive os cards do portal, que passam a ser a mesma entidade dos
registros DNS do dnsmasq.

O que nao couber no modelo nao e' descartado em silencio — vira uma linha no
relatorio final, para decisao humana.

    python3 tools/import_live.py legacy/live legacy/portal-index.html
"""

from __future__ import annotations

import re
import sys
from html import unescape
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from fwadmin.models import Config  # noqa: E402

FINDINGS: list[str] = []


def note(msg: str) -> None:
    FINDINGS.append(msg)


# ---------------------------------------------------------------------------
# /etc/network/interfaces
# ---------------------------------------------------------------------------


def parse_interfaces(text: str) -> dict[str, dict[str, Any]]:
    """Extrai os blocos 'iface X inet MODE' com suas opcoes."""
    out: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "iface" and len(parts) >= 4 and parts[2] == "inet":
            current = parts[1]
            out[current] = {"mode": parts[3], "options": {}}
        elif parts[0] in ("auto", "allow-hotplug", "source"):
            current = None
        elif current:
            out[current]["options"][parts[0]] = " ".join(parts[1:])
    return out


def netmask_to_prefix(mask: str) -> int:
    return sum(bin(int(o)).count("1") for o in mask.split("."))


# ---------------------------------------------------------------------------
# /etc/ppp/peers/*
# ---------------------------------------------------------------------------


def parse_ppp_peer(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"flags": set()}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0]
        if len(parts) == 1:
            out["flags"].add(key)
        else:
            out[key] = parts[1].strip().strip('"')
    return out


# ---------------------------------------------------------------------------
# /etc/dnsmasq.conf
# ---------------------------------------------------------------------------


def parse_dnsmasq(text: str) -> dict[str, list[str]]:
    """Agrupa as diretivas por chave, preservando a ordem dos valores."""
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        out.setdefault(key.strip(), []).append(value.strip())
    return out


# ---------------------------------------------------------------------------
# portal HTML
# ---------------------------------------------------------------------------

ACCENTS = {
    "lenovo": ("#22c55e", "#15803d"),
    "dell": ("#4a9eff", "#1d6fd0"),
    "hp": ("#f59e0b", "#b45309"),
}


def _text(html: str) -> str:
    """Remove tags internas e normaliza espacos."""
    return unescape(re.sub(r"<[^>]+>", "", html)).strip()


def _one(pattern: str, html: str, group: int = 1) -> str:
    m = re.search(pattern, html, re.S)
    return _text(m.group(group)) if m else ""


class PortalParser:
    """Extrai grupos, cards e endpoints do portal atual.

    O HTML e' conhecido e estavel (nos mesmos o escrevemos), entao extracao
    por regex e' mais direta e mais previsivel que um parser com estado.
    """

    SECTION = re.compile(r'<section style="--accent: var\(--([a-z]+)\)">(.*?)</section>', re.S)
    CARD = re.compile(r'<a class="card" href="([^"]+)">(.*?)</a>', re.S)
    ENDPOINT = re.compile(r'<span class="k">(.*?)</span>\s*<span class="v">(.*?)</span>', re.S)
    FOOTER = re.compile(r"<footer>(.*?)</footer>", re.S)

    def __init__(self) -> None:
        self.groups: list[dict[str, Any]] = []
        self.cards: list[dict[str, Any]] = []
        self.endpoints: list[dict[str, str]] = []
        self.notes: list[str] = []

    def feed(self, html: str) -> None:
        for key, body in self.SECTION.findall(html):
            if key not in ACCENTS:
                note(f"secao do portal com accent desconhecido '--{key}' ignorada")
                continue
            accent, accent_light = ACCENTS[key]
            h2 = _one(r"<h2>(.*?)</h2>", body)
            subtitle = _one(r'<span class="meta">(.*?)</span>', body)
            title = h2.replace(subtitle, "").strip() if subtitle else h2
            self.groups.append(
                {
                    "id": key,
                    "title": title,
                    "subtitle": subtitle.lstrip("·").strip(),
                    "accent": accent,
                    "accent_light": accent_light,
                    "order": len(self.groups) * 10,
                }
            )
            for url, card in self.CARD.findall(body):
                tag_m = re.search(r'<span class="tag( open)?">(.*?)</span>', card, re.S)
                self.cards.append(
                    {
                        "group": key,
                        "url": unescape(url),
                        "icon": _one(r'<span class="ico">(.*?)</span>', card),
                        "name": _one(r'<span class="name">(.*?)</span>', card),
                        "desc": _one(r'<div class="desc">(.*?)</div>', card),
                        "tag": _text(tag_m.group(2)) if tag_m else "",
                        "tag_style": "open" if tag_m and tag_m.group(1) else "",
                    }
                )

        self.endpoints = [
            {"name": _text(k), "address": _text(v)} for k, v in self.ENDPOINT.findall(html)
        ]

        footer = self.FOOTER.search(html)
        if footer:
            self.notes = [
                _text(p) for p in re.findall(r"<p>(.*?)</p>", footer.group(1), re.S) if _text(p)
            ]


# ---------------------------------------------------------------------------
# montagem
# ---------------------------------------------------------------------------


def build(live: Path, portal_html: Path) -> dict[str, Any]:
    ifaces_raw = parse_interfaces((live / "interfaces").read_text())
    dns_raw = parse_dnsmasq((live / "dnsmasq.conf").read_text())
    ppp_raw = parse_ppp_peer((live / "ppp-peers-vivo").read_text())

    # -- interfaces --------------------------------------------------------
    lan_dev = dns_raw["interface"][0]
    lan_cfg = ifaces_raw[lan_dev]
    prefix = netmask_to_prefix(lan_cfg["options"]["netmask"])
    lan_addr = f"{lan_cfg['options']['address']}/{prefix}"

    pppoe_dev = next(
        (k for k in ppp_raw if k in ifaces_raw and k != lan_dev),
        None,
    )
    if pppoe_dev is None:
        # o device do rp-pppoe vem numa linha sozinha, sem valor
        pppoe_dev = next((f for f in ppp_raw["flags"] if f in ifaces_raw), None)
    if pppoe_dev is None:
        raise SystemExit("nao consegui identificar o device do PPPoE em peers/vivo")

    dhcp_wan = next(
        d for d, c in ifaces_raw.items() if c["mode"] == "dhcp" and d != lan_dev
    )

    interfaces = [
        {
            "name": "lan",
            "device": lan_dev,
            "role": "lan",
            "description": "LAN 10GbE",
            "ipv4": {"mode": "static", "address": lan_addr},
        },
        {
            "name": "wan_star",
            "device": dhcp_wan,
            "role": "wan",
            "description": "Starlink",
            "ipv4": {"mode": "dhcp"},
        },
        {
            "name": "wan_vivo",
            "device": pppoe_dev,
            "role": "wan",
            "description": "Vivo Fibra (PPPoE)",
            "ipv4": {"mode": "pppoe"},
            "pppoe": {
                "peer": ppp_raw.get("linkname", "vivo"),
                "username": ppp_raw.get("user", ""),
                "password_ref": ppp_raw.get("linkname", "vivo"),
                "mtu": int(ppp_raw.get("mtu", 1492)),
                "mru": int(ppp_raw.get("mru", 1492)),
                "lcp_echo_interval": int(ppp_raw.get("lcp-echo-interval", 20)),
                "lcp_echo_failure": int(ppp_raw.get("lcp-echo-failure", 3)),
                "holdoff": int(ppp_raw.get("holdoff", 5)),
            },
        },
    ]
    note(
        f"senha do PPPoE ({ppp_raw.get('user')}) NAO foi importada: ela mora em "
        "/etc/ppp/chap-secrets e vai para /etc/fwadmin/secrets.yaml (0600, fora do git)"
    )

    # -- roteamento (valores tirados do wan-failover.sh atual) -------------
    routing = {
        "primary": "wan_vivo",
        "backup": "wan_star",
        "failover": {
            "enabled": True,
            "interval_seconds": 60,
            "threshold": 3,
            "ping_targets": ["8.8.8.8"],
            "ping_count": 2,
            "ping_timeout": 2,
        },
    }

    # -- DHCP --------------------------------------------------------------
    start, end, netmask, lease = dns_raw["dhcp-range"][0].split(",")
    reservations = []
    seen_macs: dict[str, str] = {}
    for entry in dns_raw.get("dhcp-host", []):
        mac, ip, name = entry.split(",")
        clean = re.sub(r"[^a-z0-9-]", "-", name.lower())
        if clean != name:
            note(f"reserva '{name}' renomeada para '{clean}' (o modelo nao aceita '_')")
        if mac in seen_macs:
            note(
                f"reserva '{name}' ({ip}) DESCARTADA: reusa o MAC {mac}, ja usado por "
                f"'{seen_macs[mac]}'. O dnsmasq so honra a primeira — era config quebrada"
            )
            continue
        seen_macs[mac] = name
        reservations.append({"mac": mac, "ip": ip, "name": clean})

    router = None
    dns_servers: list[str] = []
    for opt in dns_raw.get("dhcp-option", []):
        if opt.startswith("option:router,"):
            router = opt.split(",", 1)[1]
        elif opt.startswith("6,"):
            dns_servers = opt.split(",")[1:]

    dhcp = {
        "enabled": True,
        "interface": "lan",
        "range": {"start": start, "end": end, "netmask": netmask, "lease": lease},
        "router": router,
        "dns_servers": dns_servers,
        "reservations": reservations,
    }

    # -- DNS ---------------------------------------------------------------
    domain = dns_raw.get("domain", ["home.lan"])[0]
    dns = {
        "domain": domain,
        "expand_hosts": "expand-hosts" in dns_raw,
        "local_only": bool(dns_raw.get("local")),
        "upstream": dns_raw.get("server", []),
    }

    # -- hosts + portal ----------------------------------------------------
    parser = PortalParser()
    parser.feed(portal_html.read_text())

    hosts: dict[str, dict[str, Any]] = {}
    for entry in dns_raw.get("address", []):
        _, fqdn, ip = entry.split("/")
        label = fqdn[: -len(domain) - 1] if fqdn.endswith("." + domain) else fqdn
        hosts[fqdn] = {
            "name": label,
            "ip": ip,
            "group": None,
            "dns": True,
            "services": [],
        }

    for card in parser.cards:
        m = re.match(r"https?://([^/:]+)", card["url"])
        fqdn = m.group(1) if m else ""
        service = {
            "name": card["name"],
            "url": card["url"],
            "description": card["desc"],
            "icon": card["icon"],
            "tag": card["tag"],
            "tag_style": card["tag_style"],
        }
        if fqdn in hosts:
            hosts[fqdn]["services"].append(service)
            if card["group"]:
                hosts[fqdn]["group"] = card["group"]
        else:
            label = re.sub(r"[^a-z0-9-]", "-", fqdn.split(".")[0].lower())
            note(
                f"card '{card['name']}' aponta para {fqdn}, que nao tem registro no "
                f"dnsmasq — importado como host '{label}' com dns:false"
            )
            hosts.setdefault(
                fqdn,
                {
                    "name": label,
                    "ip": "0.0.0.0",
                    "group": card["group"],
                    "dns": False,
                    "description": f"sem registro DNS — URL literal {fqdn}",
                    "services": [],
                },
            )["services"].append(service)

    portal = {
        "title": "Home.Lan",
        "subtitle": f"Servicos da rede local · {lan_addr.rsplit('.', 1)[0]}.0/{prefix}",
        "groups": parser.groups,
        "endpoints": parser.endpoints,
        "notes": parser.notes,
    }

    # -- firewall (traduzido do nftables.conf atual) -----------------------
    firewall = {
        "input_policy": "accept",
        "forward_policy": "drop",
        "input_rules": [
            {
                "action": "drop",
                "description": "SSH so LAN",
                "proto": "tcp",
                "source": "wan",
                "destination": "this",
                "dest_ports": "22",
            },
            {
                "action": "drop",
                "description": "Cockpit/Webmin so LAN",
                "proto": "tcp",
                "source": "wan",
                "destination": "this",
                "dest_ports": "9090,10000",
            },
            {
                "action": "drop",
                "description": "Webmin UDP so LAN",
                "proto": "udp",
                "source": "wan",
                "destination": "this",
                "dest_ports": "10000",
            },
            {
                "action": "drop",
                "description": "Portal nginx so LAN",
                "proto": "tcp",
                "source": "wan",
                "destination": "this",
                "dest_ports": "80,443",
            },
        ],
        "forward_rules": [
            {
                "action": "accept",
                "description": "LAN sai para qualquer WAN",
                "source": "lan",
                "destination": "wan",
            }
        ],
        "port_forwards": [],
        "masquerade": ["wan_star", "wan_vivo"],
        "preserve_tables": ["inet f2b-table"],
    }
    note(
        "as duas regras de forward (lan->enp3s0 e lan->ppp0) viraram uma so "
        "'lan -> wan': o template expande de volta para cada WAN ativa"
    )
    note(
        "input_policy continua 'accept' para importar fielmente o estado atual. "
        "Recomendo migrar para 'drop' com allows explicitos — mudanca separada"
    )

    return {
        "version": 1,
        "system": {
            "hostname": "fw",
            "timezone": "America/Sao_Paulo",
            "admin_cidr": f"{lan_addr.rsplit('.', 1)[0]}.0/{prefix}",
            "confirm_timeout": 90,
        },
        "interfaces": interfaces,
        "routing": routing,
        "dns": dns,
        "dhcp": dhcp,
        "hosts": list(hosts.values()),
        "portal": portal,
        "firewall": firewall,
    }


def main() -> int:
    live = Path(sys.argv[1] if len(sys.argv) > 1 else "legacy/live")
    portal = Path(sys.argv[2] if len(sys.argv) > 2 else "legacy/portal-index.html")
    out = Path(sys.argv[3] if len(sys.argv) > 3 else "config/config.yaml")

    raw = build(live, portal)

    # A validacao e' o ponto do exercicio: se o modelo nao aceita o estado
    # atual, ou o modelo esta errado ou a config viva esta.
    cfg = Config.model_validate(raw)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "# Gerado por tools/import_live.py a partir do estado vivo do firewall.\n"
        "# Fonte da verdade do fwadmin — versionado em git, aplicado por fwctl.\n"
        + yaml.safe_dump(
            cfg.model_dump(mode="json", exclude_defaults=False),
            sort_keys=False,
            allow_unicode=True,
            width=100,
        )
    )

    print(f"config escrito em {out}")
    print(
        f"  {len(cfg.interfaces)} interfaces · {len(cfg.hosts)} hosts · "
        f"{sum(len(h.services) for h in cfg.hosts)} servicos · "
        f"{len(cfg.dhcp.reservations)} reservas DHCP · "
        f"{len(cfg.firewall.input_rules) + len(cfg.firewall.forward_rules)} regras"
    )
    if FINDINGS:
        print(f"\n{len(FINDINGS)} pontos que precisam de decisao:")
        for i, f in enumerate(FINDINGS, 1):
            print(f"  {i}. {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
