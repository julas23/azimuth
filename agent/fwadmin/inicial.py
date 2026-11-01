"""A primeira configuracao de uma caixa nova: de um formulario a um config.yaml.

Uma caixa instalada pela ISO nao tem LAN, WAN nem DHCP no /etc, e o modelo
exige os tres: nao ha o que adotar. Aqui o dono diz qual placa e' qual, e sai
o config minimo valido. Nada e' aplicado: o config entra como o de uma
maquina adotada, e o primeiro apply continua sendo decisao a parte.

O painel monta o config para validar e mostrar o erro na tela; o fwctl monta
de novo, como root, a partir do mesmo pedido, e e' essa a que vale.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from fwadmin import paths
from fwadmin.models import Config

MARKER = paths.VAR / "caixa-nova"
"""Criado pelo primeiro boot da ISO. Com ele e sem config.yaml, o painel abre
direto na configuracao da rede."""

REQUEST = paths.VAR / "inicial-pedido.json"
"""O formulario, gravado pelo painel e lido pelo fwctl. Pode ter a senha do
PPPoE: 0600, e o fwctl apaga depois de ler."""

STATUS = paths.VAR / "inicial-status.json"
"""Onde o fwctl conta como foi, para o painel mostrar."""

PPPOE_REF = "wan"
WAN_MODES = ("dhcp", "pppoe", "static")


def fresh_box() -> bool:
    return MARKER.exists() and not paths.CONFIG.exists()


def nics() -> list[dict[str, Any]]:
    """As placas fisicas (as que tem /device no sysfs), com o IPv4 de agora."""
    addrs: dict[str, str] = {}
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=5).stdout
        for item in json.loads(out or "[]"):
            for a in item.get("addr_info", []):
                addrs.setdefault(item["ifname"], f"{a['local']}/{a['prefixlen']}")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    found = []
    for dev in sorted(Path("/sys/class/net").iterdir()):
        if not (dev / "device").exists():
            continue

        def read(name: str) -> str:
            try:
                return (dev / name).read_text().strip()
            except OSError:
                return ""

        found.append(
            {
                "device": dev.name,
                "mac": read("address"),
                "carrier": read("carrier") == "1",
                "ipv4": addrs.get(dev.name, ""),
            }
        )
    return found


SUGESTOES = ("10.0.0.1/24", "192.168.50.1/24", "172.16.50.1/24")


def _wan_net(placas: list[dict[str, Any]], device: str) -> ipaddress.IPv4Network | None:
    for p in placas:
        if p["device"] == device and p.get("ipv4"):
            return ipaddress.IPv4Interface(p["ipv4"]).network
    return None


def defaults(placas: list[dict[str, Any]]) -> dict[str, str]:
    """Sugestao: a WAN e' a placa que hoje tem IP (e' por ela que a caixa chegou
    a internet na instalacao); a LAN, a primeira outra, numa rede que nao cruze
    a de cima (atras de outro roteador 10.0.0.x, a casa vai para 192.168.50.x)."""
    wan = next((p["device"] for p in placas if p.get("ipv4")), placas[0]["device"] if placas else "")
    lan = next((p["device"] for p in placas if p["device"] != wan), "")
    acima = _wan_net(placas, wan)
    rede = next(ipaddress.IPv4Interface(c) for c in SUGESTOES
                if not (acima and ipaddress.IPv4Interface(c).network.overlaps(acima)))
    base = rede.network.network_address
    return {
        "wan_device": wan,
        "wan_mode": "dhcp",
        "lan_device": lan,
        "lan_address": str(rede),
        "dhcp_start": str(base + 100),
        "dhcp_end": str(base + 199),
        "domain": "lan",
    }


def _field(pedido: dict[str, Any], name: str) -> str:
    return str(pedido.get(name, "")).strip()


def build(pedido: dict[str, Any], placas: list[dict[str, Any]]) -> dict[str, Any]:
    """O config minimo, como dicionario. Levanta ValueError com a frase para a
    tela; o resto quem recusa e' o modelo. 'placas' e' o que nics() devolve."""
    wan_dev, lan_dev = _field(pedido, "wan_device"), _field(pedido, "lan_device")
    nomes = [p["device"] for p in placas]
    if wan_dev not in nomes or lan_dev not in nomes:
        raise ValueError("escolha a WAN e a LAN entre as placas desta máquina")
    if wan_dev == lan_dev:
        raise ValueError("a WAN e a LAN precisam ser placas diferentes")
    mode = _field(pedido, "wan_mode")
    if mode not in WAN_MODES:
        raise ValueError("modo da WAN desconhecido")

    try:
        lan = ipaddress.IPv4Interface(_field(pedido, "lan_address"))
    except ValueError:
        raise ValueError("endereço da LAN inválido: use o formato 10.0.0.1/24") from None
    if lan.ip == lan.network.network_address or lan.ip == lan.network.broadcast_address:
        raise ValueError("o endereço da LAN não pode ser o da rede nem o de broadcast")
    if lan.network.prefixlen > 30:
        raise ValueError("a rede da LAN é pequena demais")
    acima = _wan_net(placas, wan_dev)
    if acima and lan.network.overlaps(acima):
        raise ValueError(
            f"a LAN ({lan.network}) cruza a rede que a WAN recebe agora ({acima}): "
            "escolha outra faixa para a casa, como 192.168.50.1/24"
        )
    try:
        start = ipaddress.IPv4Address(_field(pedido, "dhcp_start"))
        end = ipaddress.IPv4Address(_field(pedido, "dhcp_end"))
    except ValueError:
        raise ValueError("faixa de DHCP inválida") from None
    if start not in lan.network or end not in lan.network:
        raise ValueError(f"a faixa de DHCP precisa estar dentro da LAN ({lan.network})")
    if start <= lan.ip <= end:
        raise ValueError("o endereço da própria caixa não pode estar na faixa de DHCP")

    wan: dict[str, Any] = {"name": "wan", "device": wan_dev, "role": "wan", "description": "WAN"}
    if mode == "dhcp":
        wan["ipv4"] = {"mode": "dhcp"}
    elif mode == "static":
        wan["ipv4"] = {
            "mode": "static",
            "address": _field(pedido, "wan_address"),
            "gateway": _field(pedido, "wan_gateway") or None,
            "dns_nameservers": [s for s in re.split(r"[\s,]+", _field(pedido, "wan_dns")) if s],
        }
    else:
        if not _field(pedido, "pppoe_user"):
            raise ValueError("o PPPoE precisa do usuário do provedor")
        if not str(pedido.get("pppoe_password", "")):
            raise ValueError("o PPPoE precisa da senha do provedor")
        wan["ipv4"] = {"mode": "pppoe"}
        # Sem failover (uma WAN so), quem poe a rota padrao e' o pppd.
        wan["pppoe"] = {
            "peer": "wan",
            "username": _field(pedido, "pppoe_user"),
            "password_ref": PPPOE_REF,
            "default_route": True,
        }

    return {
        "version": 1,
        "system": {"hostname": "azimuth", "admin_cidr": str(lan.network)},
        "interfaces": [
            {
                "name": "lan",
                "device": lan_dev,
                "role": "lan",
                "description": "LAN",
                "ipv4": {"mode": "static", "address": str(lan)},
            },
            wan,
        ],
        "routing": {"primary": "wan", "failover": {"enabled": False}},
        "dns": {"domain": _field(pedido, "domain") or "lan", "bind_interfaces": True},
        "dhcp": {"range": {"start": str(start), "end": str(end), "netmask": str(lan.netmask)}},
        "firewall": {
            "forward_rules": [
                {
                    "action": "accept",
                    "description": "LAN sai para a internet",
                    "proto": "any",
                    "source": "lan",
                    "destination": "wan",
                }
            ],
            "masquerade": ["wan"],
        },
    }


def validate(pedido: dict[str, Any], placas: list[dict[str, Any]]) -> Config:
    """O config validado pelo modelo; ValueError com a frase para a tela."""
    from pydantic import ValidationError

    raw = build(pedido, placas)
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first.get("loc", ()))
        raise ValueError(f"{first.get('msg', 'inválido')}{f' ({where})' if where else ''}") from None
