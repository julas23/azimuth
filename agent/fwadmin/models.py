"""Schema de configuracao do fwadmin.

Estes modelos sao a fonte da verdade em tres papeis ao mesmo tempo:

  1. schema do config.yaml (load/dump com validacao)
  2. validacao dos formularios da UI (FastAPI monta o form a partir daqui)
  3. contrato dos templates que geram /etc/*

Regra de ouro: nada entra em disco sem passar por aqui.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# tipos base
# ---------------------------------------------------------------------------

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
IFNAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,14}$")
DEVICE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,14}$")
HOSTLABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
"""Label simples (vira nome.dominio) ou FQDN ja completo (ex: puter.lan)."""

Lease = Annotated[str, Field(pattern=r"^(\d+[smhd]|infinite)$")]
"""Tempo de lease no formato do dnsmasq: 12h, 30m, infinite."""


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _ipv4(value: str) -> str:
    """Valida um IPv4 puro (sem prefixo) e devolve a forma canonica."""
    return str(ipaddress.IPv4Address(value))


def _ipv4_net(value: str) -> str:
    """Valida CIDR IPv4 mantendo o IP do host (10.0.0.1/24, nao 10.0.0.0/24)."""
    iface = ipaddress.IPv4Interface(value)
    return str(iface)


def _reject_dups(values: list[str], message: str) -> None:
    """Sobe aqui, e nao no fim do arquivo: o default de Config.wireguard e'
    construido na definicao da classe e ja precisa desta funcao existindo."""
    seen: set[str] = set()
    for v in values:
        if v in seen:
            raise ValueError(f"{message}: {v!r}")
        seen.add(v)


# ---------------------------------------------------------------------------
# interfaces
# ---------------------------------------------------------------------------


class IfRole(str, Enum):
    lan = "lan"
    wan = "wan"
    unused = "unused"


class IPv4Mode(str, Enum):
    static = "static"
    dhcp = "dhcp"
    pppoe = "pppoe"
    manual = "manual"


class PPPoE(Base):
    """Parametros do link PPPoE. A senha nunca mora aqui."""

    peer: Annotated[str, Field(pattern=r"^[a-z0-9_-]{1,32}$")]
    username: Annotated[str, Field(min_length=1, max_length=128)]
    password_ref: Annotated[str, Field(pattern=r"^[a-z0-9_-]{1,32}$")]
    """Chave em /etc/fwadmin/secrets.yaml (modo 0600, fora do git)."""

    mtu: Annotated[int, Field(ge=576, le=1500)] = 1492
    mru: Annotated[int, Field(ge=576, le=1500)] = 1492
    lcp_echo_interval: Annotated[int, Field(ge=0, le=300)] = 20
    lcp_echo_failure: Annotated[int, Field(ge=0, le=100)] = 3
    holdoff: Annotated[int, Field(ge=0, le=600)] = 5


class IPv4Config(Base):
    mode: IPv4Mode
    address: str | None = None
    """Obrigatorio em modo static, no formato CIDR: 10.0.0.1/24."""

    gateway: str | None = None
    """Opcional em static. Em dhcp/pppoe vem do provedor."""

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: str | None) -> str | None:
        return _ipv4_net(v) if v else None

    @field_validator("gateway")
    @classmethod
    def _check_gateway(cls, v: str | None) -> str | None:
        return _ipv4(v) if v else None

    @property
    def ip(self) -> str:
        """IP sem o prefixo: '10.0.0.1/24' -> '10.0.0.1'."""
        return self.address.split("/")[0] if self.address else ""

    @property
    def netmask(self) -> str:
        """Mascara em notacao decimal, que e' o que o ifupdown quer."""
        return str(ipaddress.IPv4Interface(self.address).netmask) if self.address else ""

    @property
    def network(self) -> str:
        """Rede em CIDR: '10.0.0.1/24' -> '10.0.0.0/24'."""
        return str(ipaddress.IPv4Interface(self.address).network) if self.address else ""

    @model_validator(mode="after")
    def _coherent(self) -> IPv4Config:
        if self.mode is IPv4Mode.static and not self.address:
            raise ValueError("modo static exige 'address' em CIDR (ex: 10.0.0.1/24)")
        if self.mode is not IPv4Mode.static and self.address:
            raise ValueError(f"'address' so faz sentido em modo static, nao em {self.mode.value}")
        if self.mode is not IPv4Mode.static and self.gateway:
            raise ValueError(f"'gateway' so faz sentido em modo static, nao em {self.mode.value}")
        return self


class Interface(Base):
    """Uma interface fisica e o papel dela na rede."""

    name: Annotated[str, Field(pattern=IFNAME_RE.pattern)]
    """Nome logico e estavel usado no resto do config: lan, wan_vivo, wan_star."""

    device: Annotated[str, Field(pattern=DEVICE_RE.pattern)]
    """Nome real no kernel: enp2s0, enp4s0."""

    role: IfRole
    description: Annotated[str, Field(max_length=120)] = ""
    ipv4: IPv4Config
    pppoe: PPPoE | None = None

    @model_validator(mode="after")
    def _pppoe_pairing(self) -> Interface:
        if self.ipv4.mode is IPv4Mode.pppoe and self.pppoe is None:
            raise ValueError(f"interface '{self.name}': modo pppoe exige o bloco 'pppoe'")
        if self.ipv4.mode is not IPv4Mode.pppoe and self.pppoe is not None:
            raise ValueError(f"interface '{self.name}': bloco 'pppoe' so vale no modo pppoe")
        if self.role is IfRole.wan and self.ipv4.mode is IPv4Mode.manual and not self.pppoe:
            # enp4s0 e' 'manual' no ifupdown porque quem sobe o IP e' o pppd,
            # mas ai o modo correto no nosso modelo e' pppoe.
            raise ValueError(
                f"interface '{self.name}': WAN em modo manual sem pppoe nao tem como rotear"
            )
        return self

    @property
    def ppp_device(self) -> str:
        """Device que aparece na tabela de rotas (ppp0 no caso de PPPoE)."""
        return "ppp0" if self.ipv4.mode is IPv4Mode.pppoe else self.device


# ---------------------------------------------------------------------------
# roteamento e failover
# ---------------------------------------------------------------------------


class Failover(Base):
    """Substitui o wan-failover.sh do cron por algo derivado do config."""

    enabled: bool = True
    interval_seconds: Annotated[int, Field(ge=10, le=3600)] = 60
    threshold: Annotated[int, Field(ge=1, le=20)] = 3
    """Falhas consecutivas antes de trocar de link."""

    ping_targets: Annotated[list[str], Field(min_length=1, max_length=4)] = ["8.8.8.8"]
    ping_count: Annotated[int, Field(ge=1, le=10)] = 2
    ping_timeout: Annotated[int, Field(ge=1, le=30)] = 2

    @field_validator("ping_targets")
    @classmethod
    def _check_targets(cls, v: list[str]) -> list[str]:
        return [_ipv4(t) for t in v]


class Routing(Base):
    primary: str
    """Nome logico da WAN preferida."""

    backup: str | None = None
    failover: Failover = Failover()


# ---------------------------------------------------------------------------
# DHCP e DNS (dnsmasq)
# ---------------------------------------------------------------------------


class DHCPRange(Base):
    start: str
    end: str
    netmask: str = "255.255.255.0"
    lease: Lease = "12h"

    @field_validator("start", "end", "netmask")
    @classmethod
    def _check(cls, v: str) -> str:
        return _ipv4(v)

    @model_validator(mode="after")
    def _ordered(self) -> DHCPRange:
        if ipaddress.IPv4Address(self.start) > ipaddress.IPv4Address(self.end):
            raise ValueError(f"faixa DHCP invertida: {self.start} > {self.end}")
        return self


class Reservation(Base):
    """Reserva estatica por MAC (dhcp-host do dnsmasq)."""

    mac: str
    ip: str
    name: Annotated[str, Field(pattern=HOSTLABEL_RE.pattern)]
    description: Annotated[str, Field(max_length=120)] = ""

    @field_validator("mac")
    @classmethod
    def _check_mac(cls, v: str) -> str:
        v = v.lower().replace("-", ":")
        if not MAC_RE.match(v):
            raise ValueError(f"MAC invalido: {v!r} (esperado aa:bb:cc:dd:ee:ff)")
        return v

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        return _ipv4(v)


class DHCP(Base):
    enabled: bool = True
    interface: str = "lan"
    range: DHCPRange
    router: str | None = None
    """Gateway anunciado. None = o proprio IP da interface LAN."""

    dns_servers: list[str] = []
    """DNS anunciado. Vazio = o proprio firewall."""

    authoritative: bool = True
    """dhcp-authoritative: o firewall e' o unico DHCP da LAN. Responde na hora
    a quem pede um IP que nao conhece (aparelho que voltou de outra rede, lease
    que se perdeu num reinicio), em vez de deixa-lo esperando o timeout. Ligado
    por padrao porque e' a caixa; desligar so faz sentido com outro servidor
    DHCP na mesma rede."""

    reservations: list[Reservation] = []

    held: list[str] = []
    """IPs que o DHCP nunca entrega dinamicamente, sem aparelho dono.

    O dnsmasq nao distribui um endereco que aparece num dhcp-host, mesmo que o
    MAC nunca case; e' assim que se segura um pedaco da faixa ('RESERVADO' com
    MAC zerado, nos firewalls montados a mao). Gerado do mesmo jeito."""

    @field_validator("held")
    @classmethod
    def _check_held(cls, v: list[str]) -> list[str]:
        return [_ipv4(ip) for ip in v]

    @field_validator("router")
    @classmethod
    def _check_router(cls, v: str | None) -> str | None:
        return _ipv4(v) if v else None

    @field_validator("dns_servers")
    @classmethod
    def _check_dns(cls, v: list[str]) -> list[str]:
        return [_ipv4(s) for s in v]

    @model_validator(mode="after")
    def _no_dup(self) -> DHCP:
        _reject_dups([r.mac for r in self.reservations], "MAC duplicado nas reservas")
        _reject_dups([r.ip for r in self.reservations], "IP duplicado nas reservas")
        _reject_dups([r.name for r in self.reservations], "nome duplicado nas reservas")
        _reject_dups([r.ip for r in self.reservations] + self.held, "IP segurado e reservado ao mesmo tempo")
        return self


class DNS(Base):
    domain: Annotated[str, Field(pattern=r"^[a-z0-9.-]{1,64}$")] = "home.lan"
    expand_hosts: bool = True
    local_only: bool = True
    """local=/dominio/ — nao consulta upstream para o dominio interno."""

    bind_interfaces: bool = False
    """True limita o dnsmasq a escutar so na LAN, em vez do wildcard."""

    upstream: list[str] = []
    """Para quem o dnsmasq pergunta o que nao e' da LAN. Vazio = herda o
    /etc/resolv.conf (que o pppd atualiza). Aceita porta no formato do
    dnsmasq — '127.0.0.1#5335' e' o unbound da stack, atras do dnsmasq."""

    no_resolv: bool = False
    """no-resolv: ignora o /etc/resolv.conf e pergunta so ao upstream. Sem isso
    o dnsmasq tambem consulta o que o pppd escreveu la, e uma resposta pode
    sair da operadora em vez do unbound."""

    proxy_dnssec: bool = False
    """proxy-dnssec: repassa aos clientes o selo DNSSEC que o upstream deu.
    So faz sentido com um upstream que valida, como o unbound local."""

    @field_validator("upstream")
    @classmethod
    def _check_upstream(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            ip, sep, port = item.partition("#")
            if sep and not (port.isdigit() and 0 < int(port) < 65536):
                raise ValueError(f"porta invalida no upstream: {item!r}")
            out.append(_ipv4(ip) + (f"#{port}" if sep else ""))
        return out

    @model_validator(mode="after")
    def _resolve_algum(self) -> DNS:
        if self.no_resolv and not self.upstream:
            raise ValueError(
                "no_resolv sem upstream deixa o dnsmasq sem ninguem para perguntar: "
                "a LAN ficaria sem DNS"
            )
        return self


# ---------------------------------------------------------------------------
# hosts e servicos (unifica os registros DNS com os cards do portal)
# ---------------------------------------------------------------------------


class Service(Base):
    """Um servico web publicado por um host. Vira card no portal."""

    name: Annotated[str, Field(min_length=1, max_length=60)]
    url: Annotated[str, Field(pattern=r"^https?://[^\s<>\"']{1,200}$")]
    description: Annotated[str, Field(max_length=160)] = ""
    icon: Annotated[str, Field(max_length=8)] = ""
    tag: Annotated[str, Field(max_length=24)] = ""
    tag_style: Literal["", "open", "warn"] = ""
    """'open' pinta a tag de vermelho — usado para 'sem auth'."""


class HostGroup(Base):
    """Agrupamento visual do portal (uma maquina fisica, em geral)."""

    id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,23}$")]
    title: Annotated[str, Field(min_length=1, max_length=80)]
    subtitle: Annotated[str, Field(max_length=120)] = ""
    accent: Annotated[str, Field(pattern=r"^#[0-9a-fA-F]{6}$")] = "#4a9eff"
    accent_light: Annotated[str, Field(pattern=r"^#[0-9a-fA-F]{6}$")] = "#1d6fd0"
    order: int = 100


class Host(Base):
    """Um registro DNS interno, com os servicos que ele expoe.

    Substitui de uma vez o 'address=/nome.home.lan/IP' do dnsmasq e o card
    correspondente no portal — que hoje sao a mesma informacao em dois lugares.
    """

    name: Annotated[str, Field(pattern=HOSTNAME_RE.pattern)]
    """Label curto ('pve' -> pve.home.lan) ou FQDN completo ('puter.lan')."""

    ip: str
    group: str | None = None
    description: Annotated[str, Field(max_length=120)] = ""
    dns: bool = True
    """False cadastra o host so no portal, sem criar registro no dnsmasq."""

    services: list[Service] = []

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        return _ipv4(v)

    def fqdn(self, domain: str) -> str:
        """Nome completo. Um label ganha o dominio local; um FQDN fica como esta."""
        return self.name if "." in self.name else f"{self.name}.{domain}"


class Endpoint(Base):
    """Servico sem interface web — a lista do rodape do portal."""

    name: Annotated[str, Field(min_length=1, max_length=60)]
    address: Annotated[str, Field(min_length=1, max_length=160)]


class Portal(Base):
    title: Annotated[str, Field(max_length=80)] = "Home.Lan"
    subtitle: Annotated[str, Field(max_length=120)] = ""
    groups: list[HostGroup] = []
    endpoints: list[Endpoint] = []
    notes: list[Annotated[str, Field(max_length=300)]] = []


# ---------------------------------------------------------------------------
# firewall
# ---------------------------------------------------------------------------


class Action(str, Enum):
    accept = "accept"
    drop = "drop"
    reject = "reject"


class Proto(str, Enum):
    tcp = "tcp"
    udp = "udp"
    tcpudp = "tcp/udp"
    icmp = "icmp"
    any = "any"


class Zone(str, Enum):
    """Origem/destino em termos logicos, resolvidos para iifname/oifname."""

    lan = "lan"
    wan = "wan"
    any = "any"
    this = "this"
    """O proprio firewall (usado no destino das regras de input)."""


PORTSPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class Rule(Base):
    """Uma regra abstrata, no espirito do pfSense. Vira nft na renderizacao."""

    enabled: bool = True
    action: Action
    description: Annotated[str, Field(max_length=120)] = ""
    proto: Proto = Proto.any
    source: Zone | str = Zone.any
    """Zona (lan/wan/any) ou CIDR literal: 10.0.0.0/24, 10.0.0.15/32."""

    destination: Zone | str = Zone.any
    dest_ports: str = ""
    """Vazio = qualquer. Aceita '22', '80,443', '9000-9010'."""

    log: bool = False
    counter: bool = True

    @field_validator("dest_ports")
    @classmethod
    def _check_ports(cls, v: str) -> str:
        if not v:
            return v
        v = v.replace(" ", "")
        if not PORTSPEC_RE.match(v):
            raise ValueError(f"porta invalida: {v!r} (use '22', '80,443' ou '9000-9010')")
        for part in v.split(","):
            for n in part.split("-"):
                if not 1 <= int(n) <= 65535:
                    raise ValueError(f"porta fora da faixa 1-65535: {n}")
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-"))
                if lo > hi:
                    raise ValueError(f"faixa de portas invertida: {part}")
        return v

    @field_validator("source", "destination")
    @classmethod
    def _check_endpoint(cls, v: Zone | str) -> Zone | str:
        if isinstance(v, Zone):
            return v
        try:
            return Zone(v)
        except ValueError:
            pass
        try:
            ipaddress.IPv4Network(v, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"{v!r} nao e' zona (lan/wan/any/this) nem CIDR valido"
            ) from exc
        return v

    @model_validator(mode="after")
    def _ports_need_proto(self) -> Rule:
        if self.dest_ports and self.proto in (Proto.any, Proto.icmp):
            raise ValueError("filtrar por porta exige proto tcp, udp ou tcp/udp")
        return self


class PortForward(Base):
    """DNAT: publica um servico interno numa porta da WAN."""

    enabled: bool = True
    description: Annotated[str, Field(max_length=120)] = ""
    interface: str
    """Nome logico da WAN que recebe a conexao."""

    proto: Literal["tcp", "udp", "tcp/udp"] = "tcp"
    wan_port: Annotated[int, Field(ge=1, le=65535)]
    to_ip: str
    to_port: Annotated[int, Field(ge=1, le=65535)]
    source_filter: str = ""
    """CIDR opcional: so aceita DNAT vindo dessa origem."""

    @field_validator("to_ip")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        return _ipv4(v)

    @field_validator("source_filter")
    @classmethod
    def _check_src(cls, v: str) -> str:
        if v:
            ipaddress.IPv4Network(v, strict=False)
        return v


class Firewall(Base):
    """Bloqueia tudo e abre so as excecoes, nas duas cadeias.

    Nao e' um padrao que se troca: o modelo recusa politica 'accept'. Com
    lista negra, todo servico novo que escuta em 0.0.0.0 nasce aberto para a
    internet sem ninguem decidir isso — foi o que o import da VM em 25/10
    achou (um rpc.statd em porta alta, exposto na WAN). Com lista branca,
    abrir e' sempre um ato explicito, e esquecer de abrir so quebra um
    servico, nunca expoe um.

    O que a caixa precisa para funcionar e para o dono nao se trancar do lado
    de fora vem pronto no nftables gerado, antes das regras do usuario: a
    loopback, conexoes ja estabelecidas, ICMP, a LAN inteira, os peers da VPN
    e a porta do WireGuard na WAN. Ver BASE_INPUT em render.py.
    """

    input_policy: Action = Action.drop
    forward_policy: Action = Action.drop
    input_rules: list[Rule] = []
    forward_rules: list[Rule] = []
    port_forwards: list[PortForward] = []
    masquerade: list[str] = []
    """Nomes logicos das interfaces que fazem NAT de saida."""

    preserve_tables: list[str] = ["inet f2b-table"]
    """Tabelas de terceiros que o reload NAO pode apagar (fail2ban)."""

    @field_validator("input_policy", "forward_policy")
    @classmethod
    def _bloqueia_por_padrao(cls, v: Action) -> Action:
        if v is not Action.drop:
            raise ValueError(
                f"politica '{v.value}' recusada: o firewall bloqueia tudo e abre so as "
                "excecoes, com regras 'accept'"
            )
        return v


# ---------------------------------------------------------------------------
# wireguard
# ---------------------------------------------------------------------------

WGKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
"""Chave de 32 bytes em base64. O ultimo caractere e' restrito porque os dois
bits finais do quarto sexteto nao existem — 'AAAA...A=' nunca sai do wg."""


class WGPeer(Base):
    """Um cliente do tunel."""

    name: Annotated[str, Field(pattern=HOSTLABEL_RE.pattern)]
    public_key: Annotated[str, Field(pattern=WGKEY_RE.pattern)]
    """Chave PUBLICA. A privada e' do cliente e nunca passa por aqui."""

    allowed_ips: list[str] = []
    """O que este peer pode usar como origem — e para onde roteamos por ele."""

    endpoint: str | None = None
    """Só para peer de saida fixa (site a site). Cliente movel nao tem."""

    keepalive: Annotated[int, Field(ge=0, le=3600)] | None = None
    description: Annotated[str, Field(max_length=120)] = ""

    enabled: bool = True
    """Revogacao e' declarativa: desligar tira o peer do arquivo gerado, e o
    historico em git guarda quem era. Apagar a linha perderia o registro."""

    @field_validator("allowed_ips")
    @classmethod
    def _check_allowed(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(item, strict=False)) for item in v]

    @field_validator("endpoint")
    @classmethod
    def _check_endpoint(cls, v: str | None) -> str | None:
        if v is None:
            return None
        host, _, port = v.rpartition(":")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError(f"endpoint precisa ser host:porta — recebido {v!r}")
        return v


class WireGuard(Base):
    """O tunel de acesso remoto. Desligado por padrao."""

    enabled: bool = False
    device: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,14}$")] = "wg0"
    listen_port: Annotated[int, Field(ge=1, le=65535)] = 51820

    address: str | None = None
    """Endereco do servidor dentro do tunel, em CIDR: 10.9.0.1/24."""

    mtu: Annotated[int, Field(ge=1280, le=1500)] | None = None

    private_key_file: str = "/etc/wireguard/private.key"
    """Caminho da chave privada, modo 0600 e dona do root.

    A chave NAO entra no modelo nem no arquivo gerado: o wg0.conf traz um
    'PostUp = wg set %i private-key <arquivo>' e o segredo fica so ali. Sem
    isso a chave apareceria no staging, no backup, no 'fwctl diff' e na tela
    de diagnostico — o mesmo motivo pelo qual a senha do PPPoE mora no
    chap-secrets e nao no /etc/ppp/peers.
    """

    peers: list[WGPeer] = []

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: str | None) -> str | None:
        return _ipv4_net(v) if v else None

    @field_validator("private_key_file")
    @classmethod
    def _check_key_file(cls, v: str) -> str:
        if not v.startswith("/") or not re.fullmatch(r"[A-Za-z0-9/._-]{2,128}", v):
            raise ValueError(f"caminho de chave invalido: {v!r}")
        return v

    @model_validator(mode="after")
    def _coerencia(self) -> WireGuard:
        if self.enabled and not self.address:
            raise ValueError("wireguard ligado exige 'address' (ex: 10.9.0.1/24)")
        _reject_dups([p.name for p in self.peers], "peer de wireguard duplicado")
        _reject_dups([p.public_key for p in self.peers], "chave publica repetida em dois peers")
        return self

    @property
    def active_peers(self) -> list[WGPeer]:
        return [p for p in self.peers if p.enabled]


# ---------------------------------------------------------------------------
# raiz
# ---------------------------------------------------------------------------


class System(Base):
    hostname: Annotated[str, Field(pattern=HOSTLABEL_RE.pattern)] = "fw"
    timezone: Annotated[str, Field(max_length=64)] = "America/Sao_Paulo"
    admin_cidr: str = "10.0.0.0/24"
    """Unica origem autorizada a falar com a UI. Aplicado no nginx e no nft."""

    confirm_timeout: Annotated[int, Field(ge=30, le=900)] = 90
    """Segundos ate o rollback automatico se o apply nao for confirmado."""

    @field_validator("admin_cidr")
    @classmethod
    def _check(cls, v: str) -> str:
        return str(ipaddress.IPv4Network(v, strict=False))


class Config(Base):
    """Raiz do config.yaml — tudo que descreve o firewall."""

    version: Literal[1] = 1
    system: System = System()
    interfaces: list[Interface]
    routing: Routing
    dns: DNS = DNS()
    dhcp: DHCP
    hosts: list[Host] = []
    portal: Portal = Portal()
    firewall: Firewall = Firewall()
    wireguard: WireGuard = WireGuard()

    # -- indices de conveniencia -------------------------------------------

    def iface(self, name: str) -> Interface:
        for i in self.interfaces:
            if i.name == name:
                return i
        raise KeyError(f"interface logica desconhecida: {name!r}")

    @property
    def lan(self) -> Interface:
        for i in self.interfaces:
            if i.role is IfRole.lan:
                return i
        raise KeyError("nenhuma interface com role=lan")

    @property
    def wans(self) -> list[Interface]:
        return [i for i in self.interfaces if i.role is IfRole.wan]

    # -- coerencia global --------------------------------------------------

    @model_validator(mode="after")
    def _consistent(self) -> Config:
        names = [i.name for i in self.interfaces]
        _reject_dups(names, "nome logico de interface duplicado")
        _reject_dups([i.device for i in self.interfaces], "device duplicado")

        lans = [i for i in self.interfaces if i.role is IfRole.lan]
        if len(lans) != 1:
            raise ValueError(f"e' preciso exatamente uma interface lan, achei {len(lans)}")

        if not self.wans:
            raise ValueError("nenhuma interface com role=wan — o firewall ficaria sem saida")

        wan_names = {i.name for i in self.wans}
        if self.routing.primary not in wan_names:
            raise ValueError(
                f"routing.primary={self.routing.primary!r} nao e' uma WAN "
                f"(disponiveis: {sorted(wan_names)})"
            )
        if self.routing.backup:
            if self.routing.backup not in wan_names:
                raise ValueError(f"routing.backup={self.routing.backup!r} nao e' uma WAN")
            if self.routing.backup == self.routing.primary:
                raise ValueError("routing.backup nao pode ser igual ao primary")
        if self.routing.failover.enabled and not self.routing.backup:
            raise ValueError("failover ligado exige routing.backup")

        for name in self.firewall.masquerade:
            if name not in names:
                raise ValueError(f"masquerade aponta para interface inexistente: {name!r}")
        for pf in self.firewall.port_forwards:
            if pf.interface not in wan_names:
                raise ValueError(
                    f"port-forward '{pf.description or pf.wan_port}' aponta para "
                    f"{pf.interface!r}, que nao e' uma WAN"
                )

        if self.dhcp.interface not in names:
            raise ValueError(f"dhcp.interface desconhecida: {self.dhcp.interface!r}")

        # A LAN precisa ser estatica: e' o gateway anunciado no DHCP.
        if self.lan.ipv4.mode is not IPv4Mode.static:
            raise ValueError("a interface LAN precisa de IP estatico")

        lan_net = ipaddress.IPv4Interface(self.lan.ipv4.address).network
        if self.dhcp.enabled:
            for edge in (self.dhcp.range.start, self.dhcp.range.end):
                if ipaddress.IPv4Address(edge) not in lan_net:
                    raise ValueError(f"faixa DHCP {edge} esta fora da rede da LAN ({lan_net})")

        _reject_dups([h.name for h in self.hosts], "nome de host duplicado")

        group_ids = {g.id for g in self.portal.groups}
        for h in self.hosts:
            if h.group and h.group not in group_ids:
                raise ValueError(f"host {h.name!r} referencia grupo inexistente: {h.group!r}")

        # Reserva e host com o mesmo nome precisam concordar no IP, senao o
        # dnsmasq responde uma coisa e entrega outra por DHCP.
        by_name = {h.name: h.ip for h in self.hosts}
        for r in self.dhcp.reservations:
            if r.name in by_name and by_name[r.name] != r.ip:
                raise ValueError(
                    f"'{r.name}': reserva DHCP diz {r.ip} mas o registro DNS diz "
                    f"{by_name[r.name]}"
                )
        return self
