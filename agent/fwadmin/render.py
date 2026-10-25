"""Traduz o config.yaml nos arquivos de /etc.

Esta e' a unica camada que sabe a sintaxe do dnsmasq, do nft e do ifupdown.
O resto do sistema fala apenas em termos do modelo.

Nada aqui escreve em /etc: a saida vai para um diretorio de staging, que so
e' promovido pelo fwctl depois de validado.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from fwadmin import services
from fwadmin.models import Config, IPv4Mode, Proto, Rule, Zone

TEMPLATE_DIR = Path(__file__).parent / "etc_templates"

# Quais arquivos existem, para onde vao e com que template: pergunte ao
# registro de servicos. Este modulo so sabe traduzir modelo em texto.


# ---------------------------------------------------------------------------
# helpers de nftables
# ---------------------------------------------------------------------------


def nft_ports(spec: str) -> str:
    """'22' -> '22' · '80,443' -> '{ 80, 443 }' · '9000-9010' -> '9000-9010'."""
    if "," not in spec:
        return spec
    return "{ " + ", ".join(spec.split(",")) + " }"


def nft_set(items: list[str]) -> str:
    """Um item vira literal; varios viram set anonimo."""
    quoted = [f'"{i}"' for i in items]
    if len(quoted) == 1:
        return quoted[0]
    return "{ " + ", ".join(quoted) + " }"


def _endpoint_expr(cfg: Config, value: Zone | str, direction: str) -> list[str]:
    """Traduz zona/CIDR num fragmento de match do nft.

    'direction' e' 'in' (origem) ou 'out' (destino).
    """
    ifkey = "iifname" if direction == "in" else "oifname"
    ipkey = "ip saddr" if direction == "in" else "ip daddr"

    if isinstance(value, Zone):
        if value is Zone.any or value is Zone.this:
            return []
        if value is Zone.lan:
            return [f'{ifkey} "{cfg.lan.device}"']
        if value is Zone.wan:
            return [f"{ifkey} $WAN"]
    return [f"{ipkey} {value}"]


def rule_to_nft(cfg: Config, rule: Rule) -> list[str]:
    """Uma regra do modelo vira uma ou duas linhas de nft (tcp/udp = duas)."""
    if not rule.enabled:
        return []

    protos: list[str | None]
    if rule.proto is Proto.tcpudp:
        protos = ["tcp", "udp"]
    elif rule.proto is Proto.any:
        protos = [None]
    else:
        protos = [rule.proto.value]

    lines = []
    for proto in protos:
        parts: list[str] = []
        parts += _endpoint_expr(cfg, rule.source, "in")
        parts += _endpoint_expr(cfg, rule.destination, "out")
        if proto:
            parts.append(proto)
            if rule.dest_ports:
                parts.append(f"dport {nft_ports(rule.dest_ports)}")
        if rule.log:
            parts.append(f'log prefix "fwadmin {rule.action.value}: "')
        if rule.counter:
            parts.append("counter")
        parts.append(rule.action.value)
        if rule.description:
            parts.append(f'comment "{rule.description}"')
        lines.append(" ".join(parts))
    return lines


# ---------------------------------------------------------------------------
# ambiente Jinja
# ---------------------------------------------------------------------------


def base_input(cfg: Config) -> list[tuple[str, str]]:
    """As excecoes que toda caixa tem, antes das regras do usuario.

    Com a entrada em 'drop', sao elas que impedem o dono de se trancar do lado
    de fora e o proprio firewall de parar de funcionar. Ficam no codigo, e
    nao no config.yaml, porque nenhuma delas e' escolha: sem a LAN o painel
    some, sem o 'established' a caixa nao resolve um nome, sem o ICMPv6 o
    IPv6 morre em silencio. O painel as mostra, com o porque de cada uma.

    Devolve (linha nft, explicacao).
    """
    out = [
        ('iifname "lo" accept', "o firewall falando com ele mesmo"),
        ("ct state established,related accept", "respostas de conexões que já foram aceitas"),
        ("ct state invalid drop", "pacote que não pertence a conexão nenhuma"),
        (
            "meta l4proto { icmp, ipv6-icmp } accept",
            "ping e o ICMP sem o qual IPv4 e IPv6 quebram (MTU, vizinhança)",
        ),
        (
            f'iifname "{cfg.lan.device}" accept',
            "a LAN alcança o firewall: DNS, DHCP, SSH e o painel",
        ),
    ]
    for wan in cfg.wans:
        if wan.ipv4.mode is IPv4Mode.dhcp:
            out.append(
                (
                    f'iifname "{wan.device}" udp sport 67 udp dport 68 accept',
                    f"resposta do DHCP do provedor em {wan.description or wan.name}",
                )
            )
    wg = cfg.wireguard
    if wg.enabled:
        out.append(
            (
                f"iifname $WAN udp dport {wg.listen_port} accept",
                f"o WireGuard ({wg.device}) recebendo os peers pela internet",
            )
        )
        out.append((f'iifname "{wg.device}" accept', "peers da VPN alcançam o firewall, como a LAN"))
    return out


def environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        undefined=StrictUndefined,  # erro de template nunca vira arquivo silencioso
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["nft_ports"] = nft_ports
    env.filters["nft_set"] = nft_set
    return env


def render_all(cfg: Config) -> dict[str, str]:
    """Renderiza todos os arquivos gerenciados. Chave = nome do arquivo."""
    env = environment()

    wan_devices = [w.ppp_device for w in cfg.wans]
    primary = cfg.iface(cfg.routing.primary)
    backup = cfg.iface(cfg.routing.backup) if cfg.routing.backup else None

    ctx = {
        "cfg": cfg,
        "system": cfg.system,
        "lan": cfg.lan,
        "wans": cfg.wans,
        "wan_devices": wan_devices,
        "primary": primary,
        "backup": backup,
        "dns": cfg.dns,
        "dhcp": cfg.dhcp,
        "hosts": cfg.hosts,
        "firewall": cfg.firewall,
        "routing": cfg.routing,
        "rule_to_nft": lambda r: rule_to_nft(cfg, r),
        "base_input": base_input(cfg),
        "IPv4Mode": IPv4Mode,
    }

    out = {}
    for name in services.targets(cfg):
        template = env.get_template(services.template_for(name, cfg))
        out[name] = template.render(**ctx, **services.context_for(name, cfg))
    return out


def load(path: Path) -> Config:
    """Le e valida o config.yaml."""
    return Config.model_validate(yaml.safe_load(path.read_text()))


def prune(obj):
    """Remove chaves None para o YAML ficar legivel na edicao manual."""
    if isinstance(obj, dict):
        return {k: prune(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [prune(v) for v in obj]
    return obj


def dump(cfg: Config, header: str = "") -> str:
    """Serializa o config de volta para YAML, estavel e legivel."""
    body = yaml.safe_dump(
        prune(cfg.model_dump(mode="json")),
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )
    return f"{header}{body}" if header else body
