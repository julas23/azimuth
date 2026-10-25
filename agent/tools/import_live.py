#!/usr/bin/env python3
"""Le a configuracao viva do firewall e produz o config.yaml inicial.

Nao comecamos de uma folha em branco: tudo que ja esta rodando no firewall
entra no modelo, inclusive os cards do portal, que passam a ser a mesma
entidade dos registros DNS do dnsmasq.

O que nao couber no modelo nao e' descartado em silencio. Vira uma de duas
listas no relatorio final:

  - decisoes: o import ajustou algo sem mudar o comportamento (um '_' que
    virou '-', uma reserva placeholder que nunca casa com aparelho);
  - mudancas: o que o primeiro apply deste config faria diferente do que esta
    rodando hoje, porque o modelo nao representa. E' a lista que decide se o
    motor pode assumir a maquina.

    python3 tools/import_live.py legacy/live legacy/portal-index.html

O diretorio vivo e' uma copia achatada do /etc:

    interfaces          /etc/network/interfaces
    dnsmasq.conf        /etc/dnsmasq.conf
    nftables.conf       /etc/nftables.conf
    ppp-peers-<peer>    /etc/ppp/peers/<peer>
    wireguard/<dev>.conf   opcional, SEM as linhas PrivateKey/PresharedKey

O portal e' opcional: sem o arquivo, o config sai sem cards.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from html import unescape
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from fwadmin.models import Config  # noqa: E402

FINDINGS: list[str] = []
CHANGES: list[str] = []


def note(msg: str) -> None:
    FINDINGS.append(msg)


def change(msg: str) -> None:
    """O apply deste config faria algo diferente do que esta rodando."""
    CHANGES.append(msg)


def label(text: str) -> str:
    """Nome livre -> label aceito pelo modelo: 'Notebook hp' -> 'notebook-hp'."""
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", text.lower())).strip("-")


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


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


def iface_address(options: dict[str, str]) -> str:
    """'address 10.0.0.1/24', ou o par address + netmask do ifupdown antigo."""
    address = options["address"]
    if "/" in address:
        return address
    return f"{address}/{netmask_to_prefix(options['netmask'])}"


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


PPP_FIXED = {
    "plugin": "rp-pppoe.so",
    "maxfail": "0",
}
"""Opcoes com valor que o template escreve sempre igual."""

PPP_FIXED_FLAGS = {
    "noipdefault", "hide-password", "noauth", "persist", "noaccomp",
    "default-asyncmap", "nodefaultroute",
}
PPP_MODELED = {
    "user", "mtu", "mru", "lcp-echo-interval", "lcp-echo-failure", "holdoff",
    "linkname", "ipparam",
}


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


DNSMASQ_MODELED = {
    "interface", "bind-interfaces", "domain", "expand-hosts", "local",
    "dhcp-range", "dhcp-option", "dhcp-host", "address", "server",
}

ZERO_MAC = "00:00:00:00:00:00"


# ---------------------------------------------------------------------------
# /etc/nftables.conf
# ---------------------------------------------------------------------------


def parse_nft(text: str) -> dict[str, Any]:
    """Separa o ruleset em defines e chains, cada chain com hook, policy e regras.

    So entende o formato que nos mesmos escrevemos: uma regra por linha, uma
    chain por bloco. O que fugir disso cai como regra nao reconhecida e vira
    mudanca no relatorio — nunca some.
    """
    out: dict[str, Any] = {"defines": {}, "chains": {}}
    table = chain = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if m := re.match(r"define (\w+) = (.+)$", line):
            out["defines"][m.group(1)] = re.findall(r'"([^"]+)"', m.group(2))
        elif re.match(r"(delete )?table \S+ \S+$", line):
            continue  # o recria-e-apaga do topo, que o template tambem escreve
        elif m := re.match(r"table (\S+) (\S+) \{$", line):
            table = f"{m.group(1)} {m.group(2)}"
        elif m := re.match(r"chain (\S+) \{$", line):
            chain = m.group(1)
            out["chains"][(table, chain)] = {"hook": None, "policy": None, "rules": []}
        elif m := re.match(r"type \w+ hook (\w+) priority [^;]+; policy (\w+);$", line):
            out["chains"][(table, chain)].update(hook=m.group(1), policy=m.group(2))
        elif line == "}":
            if chain:
                chain = None
            else:
                table = None
        elif chain:
            out["chains"][(table, chain)]["rules"].append(line)
        else:
            change(f"nftables: linha fora de chain nao reconhecida: {line}")
    return out


COUNTER = r"(?:counter (?:packets \d+ bytes \d+ )?)"
COMMENT = r'(?: comment "(?P<comment>[^"]*)")?'

NFT_RULE = re.compile(
    r'^(?:iifname (?P<iif>\$\w+|"[^"]+") )?'
    r'(?:oifname (?P<oif>\$\w+|"[^"]+") )?'
    r"(?:ip saddr (?P<saddr>[\d./]+) )?"
    r"(?:ip daddr (?P<daddr>[\d./]+) )?"
    r"(?:(?P<proto>tcp|udp) dport (?P<ports>\{[^}]*\}|\d+(?:-\d+)?) )?"
    r"(?P<ctdnat>ct status dnat )?"
    rf"(?P<counter>{COUNTER})?"
    r"(?P<action>accept|drop|reject)" + COMMENT + "$"
)
"""Uma regra no formato que o rule_to_nft gera: e' o inverso dele."""

NFT_DNAT = re.compile(
    r'^iifname "(?P<dev>[^"]+)" (?:ip saddr (?P<saddr>[\d./]+) )?'
    r"(?P<proto>tcp|udp) dport (?P<port>\d+) "
    rf"{COUNTER}?dnat to (?P<ip>[\d.]+):(?P<to_port>\d+)" + COMMENT + "$"
)

NFT_MASQ = re.compile(r'^oifname "(?P<dev>[^"]+)" masquerade' + COMMENT + "$")

FORWARD_FIXED = {
    "ct state established,related accept",
    "tcp flags syn tcp option maxseg size set rt mtu",
}
"""O template escreve estas duas no topo da forward; nao viram regra do modelo."""


def nft_ports(spec: str) -> str:
    """'{ 80, 443 }' -> '80,443' · '22' -> '22'."""
    return spec.strip("{} ").replace(" ", "")


# ---------------------------------------------------------------------------
# /etc/wireguard/*.conf
# ---------------------------------------------------------------------------


def parse_wireguard(text: str) -> dict[str, Any]:
    """Interface + peers. O comentario dentro (ou logo antes) de um [Peer] vira o nome."""
    iface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section: dict[str, str] | None = None
    pending_comment = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            pending_comment = pending_comment or line.lstrip("# ").strip()
            continue
        if line == "[Interface]":
            section = iface
        elif line == "[Peer]":
            section = {"#": pending_comment}
            peers.append(section)
        elif section is not None and "=" in line:
            key, _, value = line.partition("=")
            if section is not iface and not section["#"]:
                section["#"] = pending_comment
            section[key.strip()] = value.strip()
        pending_comment = ""
    return {"interface": iface, "peers": peers}


WG_IFACE_MODELED = {"Address", "ListenPort", "MTU", "PostUp"}
WG_PEER_MODELED = {"#", "PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}


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


def build_interfaces(
    ifaces_raw: dict[str, dict[str, Any]], iface_text: str, lan_dev: str, ppp_raw: dict[str, Any]
) -> tuple[list[dict[str, Any]], str, str | None]:
    """Devolve (interfaces, device do PPPoE, device da WAN DHCP ou None)."""
    lan_cfg = ifaces_raw[lan_dev]
    lan_addr = iface_address(lan_cfg["options"])

    pppoe_dev = next(
        (k for k in ppp_raw if k in ifaces_raw and k != lan_dev),
        None,
    )
    if pppoe_dev is None:
        # o device do rp-pppoe vem numa linha sozinha, sem valor
        pppoe_dev = next((f for f in ppp_raw["flags"] if f in ifaces_raw), None)
    if pppoe_dev is None:
        raise SystemExit("nao consegui identificar o device do PPPoE em peers/vivo")

    # A placa do PPPoE pode estar como 'inet dhcp' no ifupdown; quem decide o
    # papel dela e' o peers/, nao o modo que sobrou no interfaces.
    dhcp_wan = next(
        (d for d, c in ifaces_raw.items() if c["mode"] == "dhcp" and d not in (lan_dev, pppoe_dev)),
        None,
    )

    pppoe_mode = ifaces_raw[pppoe_dev]["mode"]
    if pppoe_mode != "manual":
        change(
            f"{pppoe_dev} (placa do PPPoE) sobe hoje em 'inet {pppoe_mode}'; o motor gera "
            "'inet manual', porque quem poe IP no link e' o pppd"
        )

    for dev, cfg in ifaces_raw.items():
        if dev in ("lo", lan_dev, pppoe_dev, dhcp_wan):
            continue
        change(f"interface {dev} ('inet {cfg['mode']}') nao tem papel no modelo e sai do arquivo")

    expected = {lan_dev: {"address", "netmask", "gateway"}, pppoe_dev: set(), dhcp_wan: set()}
    for dev, allowed in expected.items():
        if dev is None:
            continue
        for key, value in ifaces_raw[dev]["options"].items():
            if key not in allowed:
                change(f"interfaces: '{key} {value}' em {dev} nao existe no modelo e sai do arquivo")

    hotplug = re.findall(r"^\s*allow-hotplug\s+(\S+)", iface_text, re.M)
    if hotplug:
        note(
            f"allow-hotplug em {', '.join(hotplug)} vira so 'auto': para placa que existe "
            "no boot, o efeito e' o mesmo"
        )

    interfaces = [
        {
            "name": "lan",
            "device": lan_dev,
            "role": "lan",
            "description": "LAN 10GbE",
            "ipv4": {
                "mode": "static",
                "address": lan_addr,
                "gateway": lan_cfg["options"].get("gateway"),
            },
        },
    ]
    if dhcp_wan:
        interfaces.append(
            {
                "name": "wan_star",
                "device": dhcp_wan,
                "role": "wan",
                "description": "Starlink",
                "ipv4": {"mode": "dhcp"},
            }
        )
    interfaces.append(
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
        }
    )
    return interfaces, pppoe_dev, dhcp_wan


def check_ppp(ppp_raw: dict[str, Any], peer: str, pppoe_dev: str) -> None:
    """Tudo o que o peers/ vivo faz e o template nao escreve."""
    if "password" in ppp_raw:
        change(
            f"a senha do PPPoE esta no proprio peers/{peer}, e o arquivo gerado nao a traz: "
            "sem ela em /etc/ppp/chap-secrets (ou pap-secrets) antes do apply, o link "
            "para de autenticar"
        )
    else:
        note(
            f"senha do PPPoE ({ppp_raw.get('user')}) NAO foi importada: ela mora em "
            "/etc/ppp/chap-secrets e vai para /etc/fwadmin/secrets.yaml (0600, fora do git)"
        )

    owns_route = {"defaultroute", "replacedefaultroute"} & ppp_raw["flags"]
    if owns_route:
        change(
            f"o pppd e' dono da rota padrao hoje ({', '.join(sorted(owns_route))}); o motor "
            "gera 'nodefaultroute' e passa a rota para o wan-failover.sh, que roda por timer. "
            "Entre o link subir e o timer disparar, nao ha rota padrao"
        )

    for key, want in PPP_FIXED.items():
        if key in ppp_raw and ppp_raw[key] != want:
            change(f"peers/{peer}: '{key} {ppp_raw[key]}' vira '{key} {want}'")
    for key in ppp_raw:
        if key not in PPP_FIXED and key not in PPP_MODELED and key not in ("flags", "password"):
            change(f"peers/{peer}: '{key} {ppp_raw[key]}' nao existe no modelo e sai do arquivo")
    for flag in ppp_raw["flags"] - PPP_FIXED_FLAGS - owns_route - {pppoe_dev}:
        change(f"peers/{peer}: '{flag}' nao existe no modelo e sai do arquivo")

    implicit = [k for k in ("mtu", "mru") if k not in ppp_raw]
    if implicit:
        note(
            f"peers/{peer} nao fixa {' nem '.join(implicit)}; o modelo escreve 1492, que e' o "
            "que o rp-pppoe ja negocia"
        )


def build_dns(dns_raw: dict[str, list[str]], domain: str) -> dict[str, Any]:
    for key, values in dns_raw.items():
        if key not in DNSMASQ_MODELED:
            for v in values:
                change(f"dnsmasq: '{key}{'=' + v if v else ''}' nao existe no modelo e sai do arquivo")

    for extra in dns_raw["interface"][1:]:
        change(f"dnsmasq: 'interface={extra}' sai; o modelo escuta so na LAN")
    for loc in dns_raw.get("local", []):
        if loc != f"/{domain}/":
            change(f"dnsmasq: 'local={loc}' sai; o modelo so declara local=/{domain}/")

    upstream = []
    for server in dns_raw.get("server", []):
        if is_ipv4(server):
            upstream.append(server)
        else:
            change(
                f"dnsmasq: upstream 'server={server}' sai — o modelo so aceita IPv4 sem porta. "
                "Sem ele o dnsmasq gerado consulta o que estiver no /etc/resolv.conf"
            )

    return {
        "domain": domain,
        "expand_hosts": "expand-hosts" in dns_raw,
        "local_only": bool(dns_raw.get("local")),
        "bind_interfaces": "bind-interfaces" in dns_raw,
        "upstream": upstream,
    }


def build_hosts(dns_raw: dict[str, list[str]], domain: str) -> dict[str, dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    for entry in dns_raw.get("address", []):
        _, fqdn, ip = entry.split("/")
        if fqdn.startswith(".") or not is_ipv4(ip):
            change(f"dnsmasq: 'address={entry}' nao e' registro de host simples e sai do arquivo")
            continue
        name = fqdn[: -len(domain) - 1] if fqdn.endswith("." + domain) else fqdn
        hosts[fqdn] = {
            "name": name,
            "ip": ip,
            "group": None,
            "dns": True,
            "services": [],
        }
    return hosts


def build_dhcp(
    dns_raw: dict[str, list[str]], hosts: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    ranges = dns_raw["dhcp-range"]
    for extra in ranges[1:]:
        change(f"dnsmasq: faixa extra 'dhcp-range={extra}' sai; o modelo tem uma so")
    fields = ranges[0].split(",")
    if len(fields) == 3:
        start, end, lease = fields
        netmask = "255.255.255.0"
    else:
        start, end, netmask, lease = fields

    names_by_ip: dict[str, list[str]] = {}
    for h in hosts.values():
        names_by_ip.setdefault(h["ip"], []).append(h["name"])

    reservations: list[dict[str, str]] = []
    seen_macs: dict[str, str] = {}
    seen_ips: set[str] = set()
    taken: set[str] = set()
    placeholders = 0
    for entry in dns_raw.get("dhcp-host", []):
        parts = entry.split(",")
        if len(parts) not in (2, 3):
            change(f"dnsmasq: 'dhcp-host={entry}' tem formato que o modelo nao representa e sai")
            continue
        mac, ip = parts[0].lower(), parts[1]
        name = parts[2] if len(parts) == 3 else ""

        if mac == ZERO_MAC:
            placeholders += 1
            continue

        if not name:
            # sem nome, o dnsmasq so entrega o IP; o nome vem do registro DNS
            # que aponta para o mesmo endereco, se houver um so
            candidates = names_by_ip.get(ip, [])
            if len(candidates) != 1:
                change(f"reserva {mac} -> {ip} sem nome, e nenhum registro DNS unico para emprestar um; sai")
                continue
            name = candidates[0]
            note(f"reserva {mac} -> {ip} nao tinha nome; ganhou '{name}', do registro DNS de {ip}")

        clean = label(name)
        if clean != name:
            note(f"reserva '{name}' renomeada para '{clean}' (o modelo nao aceita '_')")
        if mac in seen_macs:
            note(
                f"reserva '{name}' ({ip}) DESCARTADA: reusa o MAC {mac}, ja usado por "
                f"'{seen_macs[mac]}'. O dnsmasq so honra a primeira — era config quebrada"
            )
            continue
        if ip in seen_ips:
            change(f"reserva '{name}' ({ip}) sai: o IP ja esta reservado para outro MAC")
            continue
        if clean in taken:
            renamed = f"{clean}-{ip.rsplit('.', 1)[1]}"
            note(f"reserva '{name}' ({ip}) repete nome; vira '{renamed}'")
            clean = renamed
        seen_macs[mac] = name
        seen_ips.add(ip)
        taken.add(clean)
        reservations.append({"mac": mac, "ip": ip, "name": clean})

    if placeholders:
        note(
            f"{placeholders} reservas com MAC {ZERO_MAC} ignoradas: marcam faixa na planilha "
            "e nunca casam com aparelho nenhum"
        )

    # Reserva e registro com o mesmo nome precisam concordar (o modelo exige).
    # Quem ganha e' a reserva: e' onde o aparelho de fato esta.
    by_name = {h["name"]: h for h in hosts.values()}
    for r in reservations:
        h = by_name.get(r["name"])
        if h and h["ip"] != r["ip"]:
            change(
                f"'{r['name']}': DHCP entrega {r['ip']} e o DNS responde {h['ip']}; o modelo "
                f"exige que concordem, e o registro DNS passa a {r['ip']}"
            )
            h["ip"] = r["ip"]

    router = None
    dns_servers: list[str] = []
    for opt in dns_raw.get("dhcp-option", []):
        if opt.startswith("option:router,"):
            router = opt.split(",", 1)[1]
        elif opt.startswith("6,"):
            dns_servers = opt.split(",")[1:]
        else:
            change(f"dnsmasq: 'dhcp-option={opt}' nao existe no modelo e sai do arquivo")

    return {
        "enabled": True,
        "interface": "lan",
        "range": {"start": start, "end": end, "netmask": netmask, "lease": lease},
        "router": router,
        "dns_servers": dns_servers,
        "reservations": reservations,
    }


def build_firewall(
    nft: dict[str, Any], lan_dev: str, wan_by_dev: dict[str, str]
) -> dict[str, Any]:
    """Traduz o ruleset vivo para o modelo, regra a regra.

    'wan_by_dev' mapeia o device que aparece no nft (ppp0, ens17) para o nome
    logico da WAN. O que nao tiver traducao exata vira mudanca.
    """
    wan_devs = set(wan_by_dev)
    defined = set(nft["defines"].get("WAN", []))
    if defined and defined != wan_devs:
        change(
            f"nftables: define WAN = {sorted(defined)}, mas as WANs do modelo sao "
            f"{sorted(wan_devs)}; toda regra com $WAN muda de alcance"
        )

    def zone(expr: str | None, cidr: str | None) -> str | None:
        """iifname/oifname ou CIDR -> zona do modelo. None = sem traducao."""
        if expr and cidr:
            return None
        if cidr:
            return cidr
        if expr is None:
            return "any"
        if expr == "$WAN":
            return "wan"
        if expr == f'"{lan_dev}"':
            return "lan"
        return None

    def to_rule(line: str, chain: str) -> dict[str, Any] | None:
        m = NFT_RULE.match(line)
        if not m or m.group("ctdnat"):
            return None
        src = zone(m.group("iif"), m.group("saddr"))
        if chain == "input":
            if m.group("oif") or m.group("daddr"):
                return None
            dst = "this"
        else:
            dst = zone(m.group("oif"), m.group("daddr"))
        if src is None or dst is None:
            return None
        rule: dict[str, Any] = {
            "action": m.group("action"),
            "description": m.group("comment") or "",
            "source": src,
            "destination": dst,
            "counter": bool(m.group("counter")),
        }
        if m.group("proto"):
            rule["proto"] = m.group("proto")
            rule["dest_ports"] = nft_ports(m.group("ports"))
        return rule

    def merge_per_wan(lines: list[str]) -> list[str]:
        """'lan -> enp3s0' + 'lan -> ppp0' iguais no resto viram 'lan -> $WAN'.

        O template expande $WAN de volta para cada WAN ativa, entao a regra
        unica e' a mesma coisa — e continua certa se uma WAN entrar ou sair.
        """
        groups: dict[str, list[tuple[int, str]]] = {}
        for i, line in enumerate(lines):
            m = re.search(r'oifname "([^"]+)" ', line)
            if m and m.group(1) in wan_devs:
                groups.setdefault(line.replace(m.group(0), "oifname $WAN ", 1), []).append(
                    (i, m.group(1))
                )
        out = list(lines)
        for merged, members in groups.items():
            if {dev for _, dev in members} == wan_devs and len(members) == len(wan_devs):
                first = members[0][0]
                out[first] = merged
                for i, _ in members[1:]:
                    out[i] = ""
                note(
                    f"{len(members)} regras de forward por WAN viraram uma so com $WAN: "
                    f"{merged}"
                )
        return [line for line in out if line]

    chains = nft["chains"]
    filter_input = chains.pop(("inet filter", "input"), {"policy": "accept", "rules": []})
    filter_forward = chains.pop(("inet filter", "forward"), {"policy": "drop", "rules": []})
    prerouting = chains.pop(("ip nat", "prerouting"), {"rules": []})
    postrouting = chains.pop(("ip nat", "postrouting"), {"rules": []})
    for (table, chain), body in chains.items():
        change(f"nftables: chain '{chain}' da tabela '{table}' inteira sai ({len(body['rules'])} regras)")

    port_forwards = []
    for line in prerouting["rules"]:
        m = NFT_DNAT.match(line)
        if not m or m.group("dev") not in wan_by_dev:
            change(f"nftables/prerouting: regra sem traducao sai: {line}")
            continue
        port_forwards.append(
            {
                "description": m.group("comment") or "",
                "interface": wan_by_dev[m.group("dev")],
                "proto": m.group("proto"),
                "wan_port": int(m.group("port")),
                "to_ip": m.group("ip"),
                "to_port": int(m.group("to_port")),
                "source_filter": m.group("saddr") or "",
            }
        )

    input_rules = []
    for line in filter_input["rules"]:
        rule = to_rule(line, "input")
        if rule is None:
            change(f"nftables/input: regra sem traducao sai: {line}")
        else:
            input_rules.append(rule)

    forward_rules = []
    for line in merge_per_wan([r for r in filter_forward["rules"] if r not in FORWARD_FIXED]):
        m = NFT_RULE.match(line)
        if m and m.group("ctdnat"):
            # o template gera o accept do port-forward sozinho, a partir do DNAT
            if any(
                pf["interface"] == wan_by_dev.get((m.group("iif") or "").strip('"'))
                and pf["to_ip"] == m.group("daddr")
                and str(pf["to_port"]) == m.group("ports")
                for pf in port_forwards
            ):
                note(
                    "accept do port-forward absorvido pelo DNAT correspondente (o gerado "
                    f"nao exige 'ct status dnat'): {line}"
                )
                continue
        rule = to_rule(line, "forward")
        if rule is None:
            change(f"nftables/forward: regra sem traducao sai: {line}")
        else:
            forward_rules.append(rule)

    masquerade = []
    for line in postrouting["rules"]:
        m = NFT_MASQ.match(line)
        if not m or m.group("dev") not in wan_by_dev:
            change(f"nftables/postrouting: regra sem traducao sai: {line}")
        else:
            masquerade.append(wan_by_dev[m.group("dev")])

    input_policy = filter_input.get("policy") or "accept"
    if input_policy == "accept":
        note(
            "input_policy continua 'accept' para importar fielmente o estado atual. "
            "Recomendo migrar para 'drop' com allows explicitos — mudanca separada"
        )

    return {
        "input_policy": input_policy,
        "forward_policy": filter_forward.get("policy") or "drop",
        "input_rules": input_rules,
        "forward_rules": forward_rules,
        "port_forwards": port_forwards,
        "masquerade": masquerade,
        "preserve_tables": ["inet f2b-table"],
    }


def build_wireguard(live: Path) -> dict[str, Any] | None:
    """O tunel de acesso remoto: o primeiro .conf com ListenPort.

    O modelo tem um tunel so. Os outros nao entram, e tambem nao sao tocados:
    o motor nao e' dono do arquivo deles.
    """
    confs = sorted((live / "wireguard").glob("*.conf"))
    if not confs:
        return None

    parsed = {c.stem: parse_wireguard(c.read_text()) for c in confs}
    server = next((dev for dev, wg in parsed.items() if "ListenPort" in wg["interface"]), None)
    for dev in parsed:
        if dev != server:
            note(
                f"tunel WireGuard '{dev}' fica fora do modelo (que tem um tunel so); o motor "
                "nao e' dono do arquivo dele, entao ele continua como esta"
            )
    if server is None:
        return None

    iface = parsed[server]["interface"]
    for key, value in iface.items():
        if key == "PrivateKey":
            change(f"wireguard/{server}: a chave privada esta no proprio .conf; o gerado le de arquivo")
        elif key not in WG_IFACE_MODELED:
            change(f"wireguard/{server}: '{key} = {value}' nao existe no modelo e sai do arquivo")

    key_file = f"/etc/wireguard/{server}.key"
    if m := re.fullmatch(r"wg set %i private-key (\S+)", iface.get("PostUp", "")):
        key_file = m.group(1)
    elif "PostUp" in iface:
        change(f"wireguard/{server}: 'PostUp = {iface['PostUp']}' sai do arquivo")

    peers = []
    for n, p in enumerate(parsed[server]["peers"], 1):
        for key, value in p.items():
            if key not in WG_PEER_MODELED:
                change(f"wireguard/{server}: '{key}' do peer '{p['#'] or n}' sai do arquivo")
        peer: dict[str, Any] = {
            "name": label(p["#"]) or f"peer{n}",
            "public_key": p["PublicKey"],
            "allowed_ips": [a.strip() for a in p.get("AllowedIPs", "").split(",") if a.strip()],
            "description": p["#"],
        }
        if "Endpoint" in p:
            peer["endpoint"] = p["Endpoint"]
        if "PersistentKeepalive" in p:
            peer["keepalive"] = int(p["PersistentKeepalive"])
        peers.append(peer)

    wg: dict[str, Any] = {
        "enabled": True,
        "device": server,
        "listen_port": int(iface["ListenPort"]),
        "address": iface["Address"],
        "private_key_file": key_file,
        "peers": peers,
    }
    if "MTU" in iface:
        wg["mtu"] = int(iface["MTU"])
    return wg


def build(live: Path, portal_html: Path) -> dict[str, Any]:
    iface_text = (live / "interfaces").read_text()
    ifaces_raw = parse_interfaces(iface_text)
    dns_raw = parse_dnsmasq((live / "dnsmasq.conf").read_text())
    peer_file = next(iter(sorted(live.glob("ppp-peers-*"))), live / "ppp-peers-vivo")
    ppp_raw = parse_ppp_peer(peer_file.read_text())
    peer = ppp_raw.get("linkname", peer_file.name.removeprefix("ppp-peers-"))

    # -- interfaces --------------------------------------------------------
    lan_dev = dns_raw["interface"][0]
    interfaces, pppoe_dev, dhcp_wan = build_interfaces(ifaces_raw, iface_text, lan_dev, ppp_raw)
    lan_net = ipaddress.IPv4Interface(interfaces[0]["ipv4"]["address"]).network
    check_ppp(ppp_raw, peer, pppoe_dev)

    # -- roteamento (valores tirados do wan-failover.sh do HP) -------------
    # Failover so e' fiel se o pppd ja abria mao da rota padrao. Se ele e' o
    # dono dela hoje, nao existe failover rodando para importar.
    failover_live = dhcp_wan is not None and "nodefaultroute" in ppp_raw["flags"]
    if dhcp_wan and not failover_live:
        note("failover importado desligado: hoje nenhum script troca de WAN, quem decide a rota e' o pppd")
    routing = {
        "primary": "wan_vivo",
        "backup": "wan_star" if dhcp_wan else None,
        "failover": {
            "enabled": failover_live,
            "interval_seconds": 60,
            "threshold": 3,
            "ping_targets": ["8.8.8.8"],
            "ping_count": 2,
            "ping_timeout": 2,
        },
    }

    # -- DNS, hosts, DHCP --------------------------------------------------
    domain = dns_raw.get("domain", ["home.lan"])[0]
    dns = build_dns(dns_raw, domain)
    hosts = build_hosts(dns_raw, domain)
    dhcp = build_dhcp(dns_raw, hosts)

    # -- portal ------------------------------------------------------------
    parser = PortalParser()
    if portal_html.exists():
        parser.feed(portal_html.read_text())
    else:
        note(f"sem portal em {portal_html}: o config sai sem cards")

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
            name = label(fqdn.split(".")[0])
            note(
                f"card '{card['name']}' aponta para {fqdn}, que nao tem registro no "
                f"dnsmasq — importado como host '{name}' com dns:false"
            )
            hosts.setdefault(
                fqdn,
                {
                    "name": name,
                    "ip": "0.0.0.0",
                    "group": card["group"],
                    "dns": False,
                    "description": f"sem registro DNS — URL literal {fqdn}",
                    "services": [],
                },
            )["services"].append(service)

    portal = {
        "title": "Home.Lan",
        "subtitle": f"Servicos da rede local · {lan_net}",
        "groups": parser.groups,
        "endpoints": parser.endpoints,
        "notes": parser.notes,
    }

    # -- firewall (traduzido do nftables.conf vivo) ------------------------
    wan_by_dev = {"ppp0": "wan_vivo"}
    if dhcp_wan:
        wan_by_dev[dhcp_wan] = "wan_star"
    firewall = build_firewall(
        parse_nft((live / "nftables.conf").read_text()), lan_dev, wan_by_dev
    )

    config: dict[str, Any] = {
        "version": 1,
        "system": {
            "hostname": "fw",
            "timezone": "America/Sao_Paulo",
            "admin_cidr": str(lan_net),
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
    wireguard = build_wireguard(live)
    if wireguard:
        config["wireguard"] = wireguard
    return config


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
        f"{len(cfg.firewall.input_rules) + len(cfg.firewall.forward_rules)} regras · "
        f"{len(cfg.firewall.port_forwards)} port-forwards · "
        f"{len(cfg.wireguard.active_peers) if cfg.wireguard.enabled else 0} peers WireGuard"
    )
    if FINDINGS:
        print(f"\n{len(FINDINGS)} pontos que precisam de decisao:")
        for i, f in enumerate(FINDINGS, 1):
            print(f"  {i}. {f}")
    if CHANGES:
        print(f"\n{len(CHANGES)} MUDANCAS se este config for aplicado — o modelo nao representa:")
        for i, c in enumerate(CHANGES, 1):
            print(f"  {i}. {c}")
    else:
        print("\nnenhuma mudanca: aplicar este config reproduz o que esta rodando")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
