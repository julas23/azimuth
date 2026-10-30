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

O painel usa o mesmo codigo em modo somente leitura: o `fwctl observe` copia o
/etc vivo (sem segredos) para /run/fwadmin/live, e `run()` devolve o modelo
mais as duas listas, sem escrever nada.

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
import json
import re
import sys
from html import unescape
from pathlib import Path
from typing import Any

import yaml

from fwadmin.models import Config

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
    "no-resolv", "proxy-dnssec", "dhcp-authoritative",
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
    out: dict[str, Any] = {"defines": {}, "chains": {}, "tables": []}
    table = chain = None

    def seen(name: str) -> None:
        if name not in out["tables"]:
            out["tables"].append(name)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if m := re.match(r"define (\w+) = (.+)$", line):
            out["defines"][m.group(1)] = re.findall(r'"([^"]+)"', m.group(2))
        elif m := re.match(r"(?:delete )?table (\S+ \S+)$", line):
            seen(m.group(1))  # o recria-e-apaga do topo, que o template tambem escreve
        elif m := re.match(r"table (\S+) (\S+) \{$", line):
            table = f"{m.group(1)} {m.group(2)}"
            seen(table)
        elif m := re.match(r"chain (\S+) \{$", line):
            chain = m.group(1)
            out["chains"][(table, chain)] = {"hook": None, "policy": None, "decl": "", "rules": []}
        elif m := re.match(r"type \w+ hook (\w+) priority [^;]+; policy (\w+);$", line):
            out["chains"][(table, chain)].update(hook=m.group(1), policy=m.group(2), decl=line)
        elif line == "}":
            if chain:
                chain = None
            else:
                table = None
        elif chain:
            out["chains"][(table, chain)]["rules"].append(line)
        else:
            note(f"nftables: linha fora de chain nao reconhecida, fica no arquivo do administrador: {line}")
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

NFT_MASQ = re.compile(
    r'^oifname "(?P<dev>[^"]+)" (?:ip saddr (?P<saddr>[\d./]+) )?masquerade' + COMMENT + "$"
)

FORWARD_FIXED = {
    "ct state established,related accept",
    "tcp flags syn tcp option maxseg size set rt mtu",
}
"""O template escreve estas duas no topo da forward; nao viram regra do modelo."""


def expand_defines(rule: str, defines: dict[str, list[str]]) -> str:
    """'$WAN' -> '{ "ppp0", "ens17" }', como o nft faria."""
    return re.sub(
        r"\$(\w+)",
        lambda m: "{ " + ", ".join(f'"{d}"' for d in defines.get(m.group(1), [])) + " }",
        rule,
    )


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
    ifaces_raw: dict[str, dict[str, Any]],
    iface_text: str,
    lan_dev: str,
    ppp_raw: dict[str, Any],
    peer: str = "vivo",
    ppp_unit: str | None = None,
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
        raise ValueError(f"nao consegui identificar o device do PPPoE em peers/{peer}")

    # A placa do PPPoE pode estar como 'inet dhcp' no ifupdown; quem decide o
    # papel dela e' o peers/, nao o modo que sobrou no interfaces.
    dhcp_wan = next(
        (d for d, c in ifaces_raw.items() if c["mode"] == "dhcp" and d not in (lan_dev, pppoe_dev)),
        None,
    )

    pppoe_mode = ifaces_raw[pppoe_dev]["mode"]
    carrier = "manual"
    if pppoe_mode == "dhcp":
        carrier = "dhcp"
        note(
            f"{pppoe_dev} (placa do PPPoE) sobe em 'inet dhcp' e continua assim; o dhclient "
            "pede IP a quem nunca responde — vale trocar para manual"
        )
    elif pppoe_mode != "manual":
        change(
            f"{pppoe_dev} (placa do PPPoE) sobe hoje em 'inet {pppoe_mode}'; o motor gera "
            "'inet manual', porque quem poe IP no link e' o pppd"
        )

    for dev, cfg in ifaces_raw.items():
        if dev in ("lo", lan_dev, pppoe_dev, dhcp_wan):
            continue
        change(f"interface {dev} ('inet {cfg['mode']}') nao tem papel no modelo e sai do arquivo")

    expected = {
        lan_dev: {"address", "netmask", "gateway", "dns-nameservers"},
        pppoe_dev: {"dns-nameservers"},
        dhcp_wan: {"dns-nameservers"},
    }

    def nameservers(dev: str | None) -> list[str]:
        if dev is None:
            return []
        return ifaces_raw[dev]["options"].get("dns-nameservers", "").split()

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
                "dns_nameservers": nameservers(lan_dev),
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
                "ipv4": {"mode": "dhcp", "dns_nameservers": nameservers(dhcp_wan)},
            }
        )
    interfaces.append(
        {
            "name": "wan_vivo",
            "device": pppoe_dev,
            "role": "wan",
            "description": "Vivo Fibra (PPPoE)",
            "ipv4": {"mode": "pppoe", "dns_nameservers": nameservers(pppoe_dev)},
            "pppoe": {
                "peer": ppp_raw.get("linkname", peer),
                "username": ppp_raw.get("user", ""),
                "password_ref": ppp_raw.get("linkname", peer),
                # o que o peer vivo nao escreve, o gerado tambem nao escreve
                "mtu": int(ppp_raw["mtu"]) if "mtu" in ppp_raw else None,
                "mru": int(ppp_raw["mru"]) if "mru" in ppp_raw else None,
                "lcp_echo_interval": int(ppp_raw.get("lcp-echo-interval", 0)),
                "lcp_echo_failure": int(ppp_raw.get("lcp-echo-failure", 3)),
                "holdoff": int(ppp_raw.get("holdoff", 5)),
                "default_route": bool({"defaultroute", "replacedefaultroute"} & ppp_raw["flags"])
                and "nodefaultroute" not in ppp_raw["flags"],
                "carrier": carrier,
                "unit": ppp_unit,
                # senha dentro do peer: o motor passa a cuidar dela num arquivo
                # proprio; senha no chap-secrets: continua la, com o administrador
                "password_file": "password" in ppp_raw,
            },
        }
    )
    return interfaces, pppoe_dev, dhcp_wan


def check_ppp(ppp_raw: dict[str, Any], peer: str, pppoe_dev: str) -> None:
    """A senha. O resto do peer e' conferido contra o gerado, em compare_ppp."""
    if "password" in ppp_raw:
        note(
            f"a senha do PPPoE sai de dentro do peers/{peer} e vai para "
            f"/etc/ppp/azimuth-{peer}.secret (0600), que o peer gerado inclui com 'file'; "
            "o fwctl a copia para o /etc/fwadmin/secrets.yaml no primeiro apply"
        )
    else:
        note(
            f"senha do PPPoE ({ppp_raw.get('user')}) continua onde esta, no chap-secrets "
            "ou pap-secrets do administrador; o motor nao toca nesses arquivos"
        )


PPP_HARMLESS = {"noipdefault", "hide-password", "noaccomp", "default-asyncmap"}
"""O que o peer gerado sempre escreve e nao muda nada no PPPoE: o IP vem do
provedor de qualquer jeito, a senha so some do log, e accomp e asyncmap sao do
PPP serial — o PPPoE e' sincrono e ignora os dois."""


SECRET_INCLUDE = re.compile(r"^file /etc/ppp/azimuth-[a-z0-9_-]+\.secret$")
"""A senha que estava no peer, agora num arquivo a parte: mesma coisa."""


def _ppp_lines(text: str) -> set[str]:
    out = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if SECRET_INCLUDE.match(line):
            continue
        if line and not line.lower().startswith("password") and line not in PPP_HARMLESS:
            out.add(" ".join(line.split()))
    return out


def compare_ppp(cfg: Config, live: Path) -> None:
    """Gera cada peer pelo modelo e compara com o vivo, linha a linha.

    Conferir so o que o vivo tem deixava passar o que o gerado acrescenta
    (eco LCP, MTU fixo, linkname). Comparar com o arquivo que o motor de fato
    escreveria pega as duas direcoes.
    """
    from fwadmin.render import render_all

    rendered = render_all(cfg)
    for wan in cfg.wans:
        if not wan.pppoe:
            continue
        name = f"ppp-peers-{wan.pppoe.peer}"
        source = live / name
        if not source.exists() or name not in rendered:
            continue
        vivo, gerado = _ppp_lines(source.read_text()), _ppp_lines(rendered[name])
        for line in sorted(vivo - gerado):
            change(f"peers/{wan.pppoe.peer}: '{line}' sai do arquivo")
        for line in sorted(gerado - vivo):
            change(f"peers/{wan.pppoe.peer}: '{line}' entra no arquivo")


def build_dns(dns_raw: dict[str, list[str]], domain: str) -> dict[str, Any]:
    for key, values in dns_raw.items():
        if key not in DNSMASQ_MODELED:
            for v in values:
                change(f"dnsmasq: '{key}{'=' + v if v else ''}' nao existe no modelo e sai do arquivo")

    for extra in dns_raw["interface"][1:]:
        change(f"dnsmasq: 'interface={extra}' sai; o modelo escuta so na LAN")
    for loc in dns_raw.get("local", []):
        # local=/azimuth/ e' do proprio motor (a versao do unbound nao sai
        # para a LAN) e volta sozinho quando o resolvedor esta no modelo
        if loc not in (f"/{domain}/", "/azimuth/"):
            change(f"dnsmasq: 'local={loc}' sai; o modelo so declara local=/{domain}/")

    upstream = []
    for server in dns_raw.get("server", []):
        ip, sep, port = server.partition("#")
        if is_ipv4(ip) and (not sep or (port.isdigit() and 0 < int(port) < 65536)):
            upstream.append(server)
        else:
            change(
                f"dnsmasq: upstream 'server={server}' sai — o modelo aceita IPv4, com ou sem "
                "#porta. Sem ele o dnsmasq gerado consulta o que estiver no /etc/resolv.conf"
            )

    no_resolv = "no-resolv" in dns_raw
    if no_resolv and not upstream:
        change(
            "dnsmasq: 'no-resolv' sai, porque nenhum upstream sobrou; sem ele e sem upstream o "
            "dnsmasq ficaria sem ninguem para perguntar"
        )
        no_resolv = False

    return {
        "domain": domain,
        "expand_hosts": "expand-hosts" in dns_raw,
        "local_only": bool(dns_raw.get("local")),
        "bind_interfaces": "bind-interfaces" in dns_raw,
        "upstream": upstream,
        "no_resolv": no_resolv,
        "proxy_dnssec": "proxy-dnssec" in dns_raw,
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
    held: list[str] = []
    for entry in dns_raw.get("dhcp-host", []):
        parts = entry.split(",")
        if len(parts) not in (2, 3):
            change(f"dnsmasq: 'dhcp-host={entry}' tem formato que o modelo nao representa e sai")
            continue
        mac, ip = parts[0].lower(), parts[1]
        name = parts[2] if len(parts) == 3 else ""

        if mac == ZERO_MAC:
            held.append(ip)
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
            # O aparelho fica com a primeira; o IP desta continua fora da
            # distribuicao dinamica, como o dhcp-host vivo deixava.
            held.append(ip)
            note(
                f"reserva '{name}' ({ip}) DESCARTADA: reusa o MAC {mac}, ja usado por "
                f"'{seen_macs[mac]}'. O aparelho fica com a primeira, e {ip} vira IP segurado"
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

    reserved_ips = {r["ip"] for r in reservations}
    for ip in sorted(set(held) & reserved_ips):
        note(f"IP {ip} segurado e tambem reservado para um aparelho; vale a reserva")
    held = sorted(set(held) - reserved_ips, key=lambda a: ipaddress.IPv4Address(a))
    if held:
        note(
            f"{len(held)} reservas com MAC {ZERO_MAC} viram IPs segurados: nunca casam com "
            "aparelho nenhum, mas tiram o IP da distribuicao dinamica"
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
        "authoritative": "dhcp-authoritative" in dns_raw,
        "reservations": reservations,
        "held": held,
    }


def build_firewall(
    nft: dict[str, Any],
    lan_dev: str,
    wan_by_dev: dict[str, str],
    vpn_dev: str | None = None,
    other_devs: list[str] | None = None,
) -> dict[str, Any]:
    """Traduz o ruleset vivo para o modelo, regra a regra.

    'wan_by_dev' mapeia o device que aparece no nft (ppp0, ens17) para o nome
    logico da WAN. 'vpn_dev' e' o tunel do modelo (zona vpn); 'other_devs' sao
    os tuneis que o motor nao configura, que viram outras interfaces com o
    proprio device como nome. O que nao tiver traducao exata vira mudanca.
    """
    other_by_dev = {dev: label(dev) for dev in other_devs or []}
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
        if vpn_dev and expr == f'"{vpn_dev}"':
            return "vpn"
        if expr.strip('"') in other_by_dev:
            return other_by_dev[expr.strip('"')]
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
    order = list(chains)
    decls = {key: body.get("decl", "") for key, body in chains.items()}
    leftover: dict[tuple[str, str], list[str]] = {}

    def keep(key: tuple[str, str], line: str) -> None:
        """Sem traducao: a linha volta ao arquivo do administrador como estava."""
        leftover.setdefault(key, []).append(expand_defines(line, nft["defines"]))

    filter_input = chains.pop(("inet filter", "input"), {"policy": "accept", "rules": []})
    filter_forward = chains.pop(("inet filter", "forward"), {"policy": "drop", "rules": []})
    prerouting = chains.pop(("ip nat", "prerouting"), {"rules": []})
    postrouting = chains.pop(("ip nat", "postrouting"), {"rules": []})
    for (table, chain), body in chains.items():
        leftover[(table, chain)] = [expand_defines(r, nft["defines"]) for r in body["rules"]]
        note(
            f"nftables: chain '{chain}' da tabela '{table}' fica no arquivo do administrador "
            f"({len(body['rules'])} regras), como esta"
        )

    port_forwards = []
    for line in prerouting["rules"]:
        m = NFT_DNAT.match(line)
        if not m or m.group("dev") not in wan_by_dev:
            keep(("ip nat", "prerouting"), line)
            note(f"nftables/prerouting: regra sem traducao fica no arquivo do administrador e continua valendo: {line}")
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

    # O modelo so aceita entrada fechada. Regra de bloqueio vira redundante;
    # o que importa traduzir sao as excecoes.
    input_rules = []
    for line in filter_input["rules"]:
        m = NFT_RULE.match(line)
        if (m and m.group("action") in ("drop", "reject")) or re.search(r"\b(drop|reject)\b", line):
            note(f"nftables/input: bloqueio redundante com a entrada fechada, sai: {line}")
            continue
        rule = to_rule(line, "input")
        if rule is None:
            keep(("inet filter", "input"), line)
            change(
                f"nftables/input: regra sem traducao fica no arquivo do administrador, mas o que ela "
                f"libera passa a ser barrado pela entrada fechada do motor: {line}"
            )
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
            keep(("inet filter", "forward"), line)
            if re.search(r"\b(drop|reject)\b", line):
                note(f"nftables/forward: bloqueio sem traducao fica no arquivo do administrador e continua valendo: {line}")
            else:
                change(
                    f"nftables/forward: regra sem traducao fica no arquivo do administrador, mas o "
                    f"que ela libera passa a ser barrado pelo encaminhamento do motor: {line}"
                )
        else:
            forward_rules.append(rule)

    masquerade = []
    masquerade_rules = []
    for line in postrouting["rules"]:
        m = NFT_MASQ.match(line)
        if m and m.group("dev") in wan_by_dev and not m.group("saddr"):
            masquerade.append(wan_by_dev[m.group("dev")])
            continue
        dev = m.group("dev") if m else None
        target = wan_by_dev.get(dev) or other_by_dev.get(dev) if dev else None
        if not target:
            keep(("ip nat", "postrouting"), line)
            note(f"nftables/postrouting: regra sem traducao fica no arquivo do administrador e continua valendo: {line}")
            continue
        masquerade_rules.append(
            {
                "interface": target,
                "source": m.group("saddr") or "",
                "description": m.group("comment") or "",
            }
        )

    # Com a entrada aberta, tudo o que chegava por um tunel de terceiros ao
    # proprio firewall passava. Para importar sem mudar nada, isso vira uma
    # excecao explicita — larga de proposito, para ser revista com calma.
    if (filter_input.get("policy") or "accept") != "drop":
        for dev, name in other_by_dev.items():
            input_rules.append(
                {
                    "action": "accept",
                    "description": f"tudo o que chega pelo tunel {dev} (era a entrada aberta)",
                    "source": name,
                    "destination": "this",
                    "counter": True,
                }
            )
            note(
                f"nftables/input: o tunel '{dev}' entrava inteiro no firewall pela entrada "
                "aberta; virou uma excecao explicita e larga — vale restringir a porta"
            )

    admin_chains = []
    for table, chain in order:
        rules = leftover.get((table, chain))
        if rules is None:
            continue  # uma das quatro chains traduzidas, sem sobra: sai inteira
        decl = decls[(table, chain)]
        if re.search(r"hook (input|forward) ", decl) and decl.endswith("policy drop;"):
            # A politica e' da chain do motor. Aqui ela so derrubaria o que o
            # motor aceita; os drops explicitos que sobraram continuam valendo.
            decl = decl[: -len("drop;")] + "accept;"
            note(f"nftables: a chain '{chain}' da tabela '{table}' fica com policy accept; quem bloqueia por padrao e' o motor")
        if re.search(r"hook (input|forward) ", decl):
            # Com policy accept, accept aqui nao faz nada: o que passa e' o
            # que o motor aceita. Sobra so o que muda o destino do pacote.
            mudos = [r for r in rules if re.search(r'\baccept(?: comment "[^"]*")?$', r)]
            for r in mudos:
                note(f"nftables/{chain}: accept sem efeito na chain que sobra, sai: {r}")
            rules = [r for r in rules if r not in mudos]
            if not rules:
                continue
        admin_chains.append({"table": table, "name": chain, "decl": decl, "rules": rules})
    absorbed_tables = [t for t in nft.get("tables", []) if t != "inet azimuth"]
    if absorbed_tables:
        change(
            "nftables: o /etc/nftables.conf e' absorvido — o motor passa a escrever o arquivo, com "
            f"so as {len(admin_chains)} chains sem traducao (o original vai para o backup do apply). "
            "Sem isso, o forward com policy drop do arquivo derrubaria tudo o que o painel libera"
        )
    for chain, body in (("input", filter_input), ("forward", filter_forward)):
        if (body.get("policy") or "accept") != "drop":
            change(
                f"nftables/{chain}: a politica passa de '{body.get('policy') or 'accept'}' para "
                "'drop' (lista negra vira lista branca). Hoje tudo o que nao tem regra passa; "
                "com o modelo, so passa o que tiver excecao"
                + (
                    " — da WAN, so a porta do WireGuard. Servico exposto de proposito "
                    "precisa de regra 'accept'; o resto que escuta em 0.0.0.0 fecha"
                    if chain == "input"
                    else ""
                )
            )

    return {
        "input_policy": "drop",
        "forward_policy": "drop",
        "input_rules": input_rules,
        "forward_rules": forward_rules,
        "port_forwards": port_forwards,
        "masquerade": masquerade,
        "masquerade_rules": masquerade_rules,
        "other_interfaces": [
            {"name": name, "device": dev, "description": "tunel WireGuard fora do modelo"}
            for dev, name in other_by_dev.items()
        ],
        "absorbed_tables": absorbed_tables,
        "admin_chains": admin_chains,
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


def unit_peer(unit: str, aliases: dict[str, str]) -> str:
    """ppp@provider.service -> o peer que ela disca, atravessando o link."""
    name = unit.removeprefix("ppp@").removesuffix(".service")
    return aliases.get(name, name)


def pick_peer(live: Path, ppp_units: list[str], aliases: dict[str, str] | None = None) -> Path:
    """O peer que esta em uso, entre os que sao PPPoE de fato.

    O pacote ppp do Debian instala um 'provider' de exemplo (discagem por
    modem, sem rp-pppoe); pegar o primeiro em ordem alfabetica importaria o
    exemplo. Vale o que a unidade ppp@ ativa chama; sem ela, o primeiro PPPoE.
    """
    peers = sorted(live.glob("ppp-peers-*"))
    pppoe = [p for p in peers if re.search(r"^\s*plugin\s+\S*pppoe", p.read_text(), re.M)]
    if pppoe:
        for p in peers:
            if p not in pppoe:
                note(f"peers/{p.name.removeprefix('ppp-peers-')} nao e' PPPoE; ficou de fora")
    for unit in ppp_units:
        name = unit_peer(unit, aliases or {})
        for p in pppoe:
            if p.name == f"ppp-peers-{name}":
                return p
    if pppoe:
        return pppoe[0]
    return peers[0] if peers else live / "ppp-peers-vivo"


# ---------------------------------------------------------------------------
# unbound — o resolvedor atras do dnsmasq (UNBOUND.md, "Adocao")
# ---------------------------------------------------------------------------

UNBOUND_DEFAULTS = {
    # o que o unbound faz quando a opcao nao esta escrita; o modelo tem outros
    # padroes, e trazer o padrao do modelo mudaria a caixa sem ninguem pedir
    "do-ip6": "yes",
    "qname-minimisation": "yes",
    "hide-identity": "no",
    "hide-version": "no",
    "prefetch": "no",
    "prefetch-key": "no",
    "cache-min-ttl": "0",
    "cache-max-ttl": "86400",
    "msg-cache-size": "4m",
    "rrset-cache-size": "4m",
    "num-threads": "1",
    "edns-buffer-size": "1232",
    "harden-dnssec-stripped": "yes",
    "aggressive-nsec": "yes",
    "harden-glue": "yes",
    "harden-referral-path": "no",
    "so-reuseport": "yes",
}

UNBOUND_FIXED = {
    # o que o render escreve sempre; divergir disto e' mudanca da adocao
    "do-ip4": "yes",
    "do-udp": "yes",
    "do-tcp": "yes",
    "prefer-ip6": "no",
    "harden-glue": "yes",
    "harden-referral-path": "yes",
    "so-reuseport": "yes",
}

UNBOUND_SERVER_KEYS = set(UNBOUND_DEFAULTS) | set(UNBOUND_FIXED) | {
    "interface", "access-control", "root-hints", "module-config", "local-zone",
    "domain-insecure", "tls-cert-bundle",
}
UNBOUND_PACKAGE_KEYS = {"include", "include-toplevel", "auto-trust-anchor-file"}


def parse_unbound_file(text: str) -> list[tuple[str, str, str]]:
    """(secao, chave, valor) de cada linha. Comentario e aspas saem."""
    out, section = [], ""
    for raw in text.splitlines():
        # '#' so abre comentario no inicio ou depois de espaco: o nome TLS do
        # forward-addr ('1.1.1.1@853#cloudflare-dns.com') tem '#' no meio.
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        m = re.match(r"^([a-z0-9-]+):\s*(.*)$", line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        elif value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if not value and key in ("server", "remote-control", "forward-zone", "stub-zone"):
            section = key
            out.append((section, "", ""))
            continue
        out.append((section, key, value))
    return out


def build_resolver(live: Path) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    """Traduz o unbound vivo para a secao 'resolver'. (modelo, decisoes, mudancas).

    Devolve as proprias listas, e nao so as globais, porque a pagina de DNS
    usa esta funcao numa caixa ja adotada, para trazer o unbound ao modelo.

    Arquivo do pacote (so include e trust anchor) fica como esta. Arquivo em
    que toda linha tem traducao e' absorvido. Arquivo com sobra nao e'
    absorvido pela metade: o modulo sai desligado e a mudanca lista a sobra.
    """
    notes: list[str] = []
    changes: list[str] = []
    root = live / "unbound"
    files = sorted((root / "unbound.conf.d").glob("*.conf")) if (root / "unbound.conf.d").is_dir() else []
    if not files and not (root / "unbound.conf").exists():
        return None, notes, changes

    live_opts: dict[str, list[str]] = {}
    zones: list[dict[str, Any]] = []
    absorbed: list[str] = []
    sobra: list[str] = []
    for path in [root / "unbound.conf", *files]:
        if not path.exists():
            continue
        lines = parse_unbound_file(path.read_text())
        keys = {k for _, k, _ in lines if k}
        if keys <= UNBOUND_PACKAGE_KEYS:
            continue  # do pacote: o motor nao mexe
        if path.name == "azimuth.conf":
            continue
        resto = []
        zone: dict[str, Any] | None = None
        for section, key, value in lines:
            if not key:
                zone = {"name": "", "addrs": [], "tls": False} if section == "forward-zone" else None
                if zone is not None:
                    zones.append(zone)
                continue
            if section == "server" and key in UNBOUND_SERVER_KEYS:
                live_opts.setdefault(key, []).append(value)
            elif section == "remote-control" and key in ("control-enable", "control-interface"):
                live_opts.setdefault(f"rc:{key}", []).append(value)
            elif section == "forward-zone" and zone is not None and key in ("name", "forward-addr", "forward-tls-upstream"):
                if key == "name":
                    zone["name"] = value.rstrip(".").lower()
                elif key == "forward-addr":
                    zone["addrs"].append(value)
                else:
                    zone["tls"] = value == "yes"
            else:
                resto.append(f"{section or '(topo)'}: {key}: {value}")
        if resto:
            sobra += [f"{path.name}: {r}" for r in resto]
        else:
            absorbed.append(path.name)

    if not live_opts.get("interface"):
        return None, notes, changes  # unbound sem config da casa: nada a trazer

    def opt(key: str) -> str:
        values = live_opts.get(key)
        return values[-1] if values else UNBOUND_DEFAULTS.get(key, "")

    yes = lambda key: opt(key) == "yes"  # noqa: E731

    listen = live_opts["interface"][0]
    if "@" not in listen:
        listen += "@53"
    for extra in live_opts["interface"][1:]:
        sobra.append(f"interface: {extra} (o modelo escuta num endereco so)")
    try:
        loopback = ipaddress.IPv4Address(listen.partition("@")[0]).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        sobra.append(f"interface: {listen} (o modelo so escuta no loopback)")

    for key, fixed in UNBOUND_FIXED.items():
        if opt(key) != fixed:
            changes.append(f"unbound: '{key}: {opt(key)}' passa a '{fixed}' (valor fixo do modelo)")
    acl = set(live_opts.get("access-control", []))
    if acl != {"127.0.0.0/8 allow", "0.0.0.0/0 refuse"} and acl != {
        "127.0.0.0/8 allow", "0.0.0.0/0 refuse", "::1 allow", "::/0 refuse"
    }:
        changes.append(f"unbound: access-control passa a so loopback (hoje: {', '.join(sorted(acl)) or 'o padrao'})")
    if live_opts.get("root-hints", ["/usr/share/dns/root.hints"])[-1] != "/usr/share/dns/root.hints":
        notes.append("unbound: root-hints passa a /usr/share/dns/root.hints, a lista do pacote dns-root-data")
    rc_iface = live_opts.get("rc:control-interface", [""])[-1]
    if live_opts.get("rc:control-enable", ["no"])[-1] != "yes" or rc_iface != "/run/unbound.ctl":
        changes.append(
            "unbound: o controle passa a /run/unbound.ctl (unbound-control por socket), "
            "que o painel e a recarga sem perder cache usam"
        )

    dnssec = opt("module-config") != "iterator"
    if dnssec and not yes("harden-dnssec-stripped"):
        changes.append("unbound: 'harden-dnssec-stripped' passa a yes, que acompanha o DNSSEC ligado")
    if opt("hide-identity") != opt("hide-version"):
        changes.append("unbound: hide-identity e hide-version passam a andar juntos")
    if opt("prefetch") != opt("prefetch-key"):
        changes.append("unbound: prefetch e prefetch-key passam a andar juntos")

    blocked = []
    for value in live_opts.get("local-zone", []):
        m = re.fullmatch(r'"?([^"\s]+?)\.?"?\s+always_nxdomain', value)
        if m:
            blocked.append({"domain": m.group(1).lower()})
        else:
            sobra.append(f"local-zone: {value} (o modelo so sabe always_nxdomain)")

    forward_zones, forwarders, mode = [], [], "recursive"
    for z in zones:
        if z["name"] in ("", "."):
            mode = "forward"
            for addr in z["addrs"]:
                main, _, tls_name = addr.partition("#")  # ip[@porta][#nome]
                ip, _, port = main.partition("@")
                f: dict[str, Any] = {"address": ip}
                if z["tls"] and tls_name:
                    f["tls_name"] = tls_name
                if port and not (z["tls"] and port == "853"):
                    f["port"] = int(port)
                forwarders.append(f)
        else:
            forward_zones.append({"domain": z["name"], "servers": [a.partition("#")[0] for a in z["addrs"]]})
    insecure = {d.rstrip(".").lower() for d in live_opts.get("domain-insecure", [])}
    for d in insecure - {z["domain"] for z in forward_zones}:
        sobra.append(f"domain-insecure: {d} (o modelo so o usa nos dominios encaminhados)")

    resolver: dict[str, Any] = {
        "enabled": not sobra,
        "listen": listen,
        "mode": mode,
        "forwarders": forwarders,
        "dnssec": dnssec,
        "ipv6": yes("do-ip6"),
        "privacy": {"qname_minimisation": yes("qname-minimisation"), "hide_identity": yes("hide-identity")},
        "cache": {
            "min_ttl": int(opt("cache-min-ttl")),
            "max_ttl": int(opt("cache-max-ttl")),
            "msg_size": opt("msg-cache-size"),
            "rrset_size": opt("rrset-cache-size"),
            "prefetch": yes("prefetch"),
        },
        "threads": int(opt("num-threads")),
        "edns_buffer_size": int(opt("edns-buffer-size")),
        "forward_zones": forward_zones,
        "blocked": blocked,
        "absorbed": absorbed if not sobra else [],
    }
    if sobra:
        changes.append(
            "unbound: fica fora do modelo, porque estas linhas nao tem traducao e o motor nao "
            "absorve arquivo pela metade: " + "; ".join(sobra)
        )
    else:
        for name in absorbed:
            changes.append(
                f"unbound: {name} e' absorvido — o conteudo passa a vir do config.yaml, escrito em "
                f"azimuth.conf, e o arquivo fica so com um aviso (o original vai para o backup do apply)"
            )
    return resolver, notes, changes


def build(live: Path, portal_html: Path | None = None) -> dict[str, Any]:
    iface_text = (live / "interfaces").read_text()
    ifaces_raw = parse_interfaces(iface_text)
    dns_raw = parse_dnsmasq((live / "dnsmasq.conf").read_text())
    try:
        runtime = json.loads((live / "runtime.json").read_text())
    except (OSError, ValueError):
        runtime = {}
    aliases = runtime.get("ppp_aliases") or {}
    peer_file = pick_peer(live, runtime.get("ppp_units") or [], aliases)
    ppp_raw = parse_ppp_peer(peer_file.read_text())
    peer = ppp_raw.get("linkname", peer_file.name.removeprefix("ppp-peers-"))
    # So a unidade que disca este peer e' dele: um ppp@ de outro peer (o
    # exemplo do Debian, um modem) nao pode ser reiniciado no lugar do PPPoE.
    ppp_units = [
        u for u in runtime.get("ppp_units") or []
        if unit_peer(u, aliases) == peer_file.name.removeprefix("ppp-peers-")
    ]
    if len(ppp_units) > 1:
        note(f"mais de uma unidade ppp@ rodando ({', '.join(ppp_units)}); o modelo fica com a primeira")

    # -- interfaces --------------------------------------------------------
    lan_dev = dns_raw["interface"][0]
    interfaces, pppoe_dev, dhcp_wan = build_interfaces(
        ifaces_raw, iface_text, lan_dev, ppp_raw, peer, ppp_units[0] if ppp_units else None
    )
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
    if portal_html is None:
        pass
    elif portal_html.exists():
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
    # O WireGuard vem antes: o firewall precisa saber qual tunel e' a zona vpn
    # e quais ficam como outras interfaces.
    wireguard = build_wireguard(live)
    vpn_dev = wireguard["device"] if wireguard else None
    others = [c.stem for c in sorted((live / "wireguard").glob("*.conf")) if c.stem != vpn_dev]
    firewall = build_firewall(
        parse_nft((live / "nftables.conf").read_text()), lan_dev, wan_by_dev, vpn_dev, others
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
    if wireguard:
        config["wireguard"] = wireguard

    resolver, r_notes, r_changes = build_resolver(live)
    FINDINGS.extend(r_notes)
    CHANGES.extend(r_changes)
    if resolver:
        server = f"{resolver['listen'].partition('@')[0]}#{resolver['listen'].partition('@')[2]}"
        if resolver["enabled"] and dns["upstream"] == [server]:
            dns["upstream"] = []
            note(f"dnsmasq: o upstream {server} e' o unbound, que entra no modelo; o server= passa a sair dele")
        elif resolver["enabled"]:
            resolver["enabled"] = False
            resolver["absorbed"] = []
            CHANGES.append(
                f"unbound: fica fora do modelo, porque o dnsmasq pergunta a {', '.join(dns['upstream']) or 'ninguem'} "
                f"e nao so a ele ({server})"
            )
        config["resolver"] = resolver
    return config


def run(live: Path, portal_html: Path | None = None) -> tuple[Config, list[str], list[str]]:
    """Importa e valida, devolvendo (modelo, decisoes, mudancas).

    As listas sao globais do modulo por heranca do script; aqui elas sao
    zeradas antes e copiadas depois, para que duas leituras nao se misturem.
    Levanta ValidationError se o modelo recusar o que esta rodando.
    """
    FINDINGS.clear()
    CHANGES.clear()
    cfg = Config.model_validate(build(live, portal_html))
    compare_ppp(cfg, live)
    return cfg, list(FINDINGS), list(CHANGES)


def main() -> int:
    live = Path(sys.argv[1] if len(sys.argv) > 1 else "legacy/live")
    portal = Path(sys.argv[2] if len(sys.argv) > 2 else "legacy/portal-index.html")
    out = Path(sys.argv[3] if len(sys.argv) > 3 else "config/config.yaml")

    raw = build(live, portal)

    # A validacao e' o ponto do exercicio: se o modelo nao aceita o estado
    # atual, ou o modelo esta errado ou a config viva esta.
    cfg = Config.model_validate(raw)
    compare_ppp(cfg, live)

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
