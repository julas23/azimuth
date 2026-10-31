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

    password_file: bool = True
    """O motor escreve a senha em /etc/ppp/azimuth-<peer>.secret (0600) e o
    peer a inclui com 'file'. False = a senha fica no chap-secrets ou
    pap-secrets do administrador, que o motor nao toca."""

    mtu: Annotated[int, Field(ge=576, le=1500)] | None = 1492
    """None = nao escreve; o rp-pppoe negocia (1492 no PPPoE comum)."""

    mru: Annotated[int, Field(ge=576, le=1500)] | None = 1492
    lcp_echo_interval: Annotated[int, Field(ge=0, le=300)] = 20
    """Segundos entre ecos LCP. 0 = nao escreve: o pppd so percebe o link
    morto quando o kernel avisa, o que no PPPoE pode nunca acontecer."""

    lcp_echo_failure: Annotated[int, Field(ge=0, le=100)] = 3
    holdoff: Annotated[int, Field(ge=0, le=600)] = 5

    default_route: bool = False
    """O pppd poe a rota padrao (defaultroute + replacedefaultroute). So vale
    sem failover: com ele, quem decide a rota e' o wan-failover.sh, e os dois
    brigariam pela tabela."""

    carrier: Literal["manual", "dhcp"] = "manual"
    """Como o ifupdown sobe a placa de baixo. 'manual' e' o certo — quem poe
    IP no link e' o pppd. 'dhcp' existe para importar sem mudar maquina que
    subia assim (o dhclient fica pedindo IP a quem nunca responde)."""

    unit: Annotated[str, Field(pattern=r"^ppp@[a-z0-9_-]{1,32}\.service$")] | None = None
    """Unidade do systemd que mantem o link (ppp@provider.service, no Debian).
    None = o motor sobe e derruba com pon/poff."""


class IPv4Config(Base):
    mode: IPv4Mode
    address: str | None = None
    """Obrigatorio em modo static, no formato CIDR: 10.0.0.1/24."""

    gateway: str | None = None
    """Opcional em static. Em dhcp/pppoe vem do provedor."""

    dns_nameservers: list[str] = []
    """'dns-nameservers' do ifupdown: com o resolvconf instalado, e' o que o
    proprio firewall usa para resolver nomes. Nao mexe no DNS da LAN."""

    @field_validator("dns_nameservers")
    @classmethod
    def _check_ns(cls, v: list[str]) -> list[str]:
        return [_ipv4(s) for s in v]

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
    enabled: bool = True
    """Desligada sai do dnsmasq e fica no modelo, com IP e MAC guardados: os
    validadores de duplicata continuam contando com ela, para o IP nao ser
    entregue a outro aparelho enquanto ela estiver so pausada."""

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
    vpn = "vpn"
    """Os peers do tunel WireGuard do modelo (wireguard.device)."""

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
    """Zona (lan/wan/vpn/any), CIDR literal (10.0.0.0/24, 10.0.0.15/32) ou o
    nome de uma das firewall.other_interfaces."""

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
        if OTHER_IFACE_RE.match(v):
            return v  # nome de outra interface; o Config confere se existe
        try:
            ipaddress.IPv4Network(v, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"{v!r} nao e' zona (lan/wan/vpn/any/this), CIDR valido nem nome de interface"
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


OTHER_IFACE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,14}$")


class OtherInterface(Base):
    """Interface que o firewall filtra mas o motor nao configura.

    E' o caso do tunel WireGuard para a VPS: o .conf dele e' do administrador,
    mas as regras que deixam a LAN falar com ele sao do firewall. Com nome
    aqui, uma regra pode dizer 'vps -> lan' em vez de repetir o device.
    """

    name: Annotated[str, Field(pattern=OTHER_IFACE_RE.pattern)]
    device: Annotated[str, Field(pattern=DEVICE_RE.pattern)]
    description: Annotated[str, Field(max_length=120)] = ""


class Masquerade(Base):
    """NAT de saida com origem: 'o que sai por X vindo de Y leva o IP de X'.

    O mascaramento simples das WANs fica em firewall.masquerade; este e' para
    quando so uma rede deve ser mascarada, como os peers da VPN saindo pelo
    tunel da VPS.
    """

    interface: str
    """Nome de WAN ou de outra interface."""

    source: str = ""
    """CIDR de origem. Vazio = qualquer."""

    description: Annotated[str, Field(max_length=120)] = ""

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        return str(ipaddress.IPv4Network(v, strict=False)) if v else v


NFT_TABLE_RE = re.compile(r"^(ip|ip6|inet|arp|bridge|netdev) [A-Za-z_][A-Za-z0-9_-]{0,63}$")
NFT_DECL_RE = re.compile(r"^type \w+ hook (\w+) priority [^;{}]+; policy (accept|drop);$")


class AdminChain(Base):
    """Uma chain do /etc/nftables.conf que o modelo nao traduz, guardada como
    estava (NETMAP, snat por mapa, chain de terceiros). Volta ao arquivo tal e
    qual, linha a linha: o motor nao entende, so carrega."""

    table: Annotated[str, Field(pattern=NFT_TABLE_RE.pattern)]
    name: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")]
    decl: str = ""
    """'type nat hook prerouting priority dstnat; policy accept;' — vazio em
    chain comum, que so recebe jump."""

    rules: list[str] = []

    @field_validator("decl")
    @classmethod
    def _check_decl(cls, v: str) -> str:
        if v and not NFT_DECL_RE.match(v):
            raise ValueError(f"cabecalho de chain invalido: {v!r}")
        return v

    @field_validator("rules")
    @classmethod
    def _check_rules(cls, v: list[str]) -> list[str]:
        for line in v:
            # Uma linha por regra, sem fechar o bloco: o arquivo e' montado em
            # volta delas, e uma chave a mais tiraria a regra da chain.
            if not line or "\n" in line or line.count("{") != line.count("}") or line.startswith("#"):
                raise ValueError(f"regra invalida para o arquivo do administrador: {line!r}")
        return v

    @property
    def gate(self) -> bool:
        """Base chain de filtro que derrubaria por padrao o que o motor aceita."""
        m = NFT_DECL_RE.match(self.decl)
        return bool(m) and m.group(1) in ("input", "forward") and m.group(2) == "drop"


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

    masquerade_rules: list[Masquerade] = []

    other_interfaces: list[OtherInterface] = []

    absorbed_tables: list[str] = []
    """Tabelas do /etc/nftables.conf que o motor absorveu. Vazia, o arquivo e'
    do administrador e o motor nao toca nele. Com algo aqui, o motor passa a
    escrever o arquivo: apaga cada uma destas tabelas e recria so o que ficou
    em 'admin_chains'. O original fica no backup do apply que o absorveu.

    Por que absorver: um drop em qualquer tabela e' final, entao um forward com
    policy drop no arquivo do administrador derruba cada regra e cada
    port-forward que o painel cadastra, e o painel mostraria ativo o que nao
    funciona."""

    admin_chains: list[AdminChain] = []
    """O que sobrou do arquivo do administrador, sem traducao no modelo."""

    @field_validator("absorbed_tables")
    @classmethod
    def _check_tables(cls, v: list[str]) -> list[str]:
        for t in v:
            if not NFT_TABLE_RE.match(t) or t == "inet azimuth":
                raise ValueError(f"tabela absorvida invalida: {t!r}")
        _reject_dups(v, "tabela absorvida repetida")
        return v

    @model_validator(mode="after")
    def _admin_coerente(self) -> Firewall:
        for c in self.admin_chains:
            if c.table not in self.absorbed_tables:
                raise ValueError(f"chain {c.table} {c.name} fora das tabelas absorvidas")
            if c.gate:
                raise ValueError(
                    f"chain {c.table} {c.name} com policy drop: derrubaria o que o motor aceita "
                    "(a politica e' do motor; aqui so policy accept)"
                )
        _reject_dups([f"{c.table} {c.name}" for c in self.admin_chains], "chain repetida")
        return self

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

    endpoint: Annotated[str, Field(pattern=HOSTNAME_RE.pattern)] | None = None
    """Nome ou IP publico pelo qual os aparelhos chegam, sem a porta. So vai
    no perfil de cada peer; o servidor nao precisa dele para nada."""

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
# resolvedor recursivo (unbound)
# ---------------------------------------------------------------------------

CACHE_SIZE_RE = re.compile(r"^\d{1,5}[kmg]?$")


def _domain(v: str) -> str:
    """Dominio em minusculas e sem o ponto final: 'Corp.Exemplo.' -> 'corp.exemplo'."""
    v = v.strip().lower().rstrip(".")
    if not HOSTNAME_RE.match(v):
        raise ValueError(f"dominio invalido: {v!r}")
    return v


class Forwarder(Base):
    """Um servidor para o qual o unbound encaminha, no modo 'forward'."""

    address: str
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    tls_name: str = ""
    """Com nome, a consulta vai por DNS sobre TLS (853) e o certificado tem de
    ser desse nome. Sem nome, vai em claro, na 53."""

    @field_validator("address")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        return _ipv4(v)

    @field_validator("tls_name")
    @classmethod
    def _check_tls(cls, v: str) -> str:
        return _domain(v) if v else ""


class ForwardZone(Base):
    """Um dominio que nao vai para as raizes, e sim para servidores dados."""

    domain: str
    servers: Annotated[list[str], Field(min_length=1)]
    """IPv4, com porta opcional no formato do unbound: '10.8.0.1@5353'."""

    description: Annotated[str, Field(max_length=120)] = ""
    enabled: bool = True

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return _domain(v)

    @field_validator("servers")
    @classmethod
    def _check_servers(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            ip, sep, port = item.strip().partition("@")
            if sep and not (port.isdigit() and 0 < int(port) < 65536):
                raise ValueError(f"porta invalida: {item!r}")
            out.append(_ipv4(ip) + (f"@{port}" if sep else ""))
        return out


class BlockedDomain(Base):
    """Um dominio, e tudo abaixo dele, que responde NXDOMAIN."""

    domain: str
    description: Annotated[str, Field(max_length=120)] = ""
    enabled: bool = True

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return _domain(v)


class ResolverPrivacy(Base):
    qname_minimisation: bool = True
    hide_identity: bool = True
    """hide-identity e hide-version juntos."""


class ResolverCache(Base):
    min_ttl: Annotated[int, Field(ge=0, le=3600)] = 0
    max_ttl: Annotated[int, Field(ge=60, le=604800)] = 86400
    msg_size: Annotated[str, Field(pattern=CACHE_SIZE_RE.pattern)] = "4m"
    rrset_size: Annotated[str, Field(pattern=CACHE_SIZE_RE.pattern)] = "4m"
    prefetch: bool = True
    """prefetch e prefetch-key juntos."""


class Resolver(Base):
    """O unbound, atras do dnsmasq. Desligado por padrao.

    O motor escreve so /etc/unbound/unbound.conf.d/azimuth.conf. O unbound.conf
    do Debian e o arquivo do trust anchor continuam do pacote.
    """

    enabled: bool = False
    listen: str = "127.0.0.1@5335"
    """So loopback: a porta da LAN e' o dnsmasq. Um recursivo aberto na LAN e'
    um amplificador de DDoS esperando acontecer."""

    mode: Literal["recursive", "forward"] = "recursive"
    forwarders: list[Forwarder] = []
    dnssec: bool = True
    ipv6: bool = False
    privacy: ResolverPrivacy = ResolverPrivacy()
    cache: ResolverCache = ResolverCache()
    threads: Annotated[int, Field(ge=1, le=16)] = 1
    edns_buffer_size: Annotated[int, Field(ge=512, le=4096)] = 1232

    forward_zones: list[ForwardZone] = []
    blocked: list[BlockedDomain] = []

    absorbed: list[str] = []
    """Arquivos de unbound.conf.d que a adocao trouxe para o modelo. O motor
    passa a ser dono deles tambem, e os escreve so com um aviso: o conteudo
    vive no azimuth.conf, e o original fica no backup do apply que os
    absorveu, de onde o rollback o devolve."""

    @field_validator("listen")
    @classmethod
    def _check_listen(cls, v: str) -> str:
        ip, sep, port = v.partition("@")
        if not (sep and port.isdigit() and 0 < int(port) < 65536):
            raise ValueError(f"escuta invalida: {v!r} (esperado 127.0.0.1@5335)")
        if not ipaddress.IPv4Address(ip).is_loopback:
            raise ValueError(f"o unbound escuta so no loopback, nao em {ip}: a porta da LAN e' o dnsmasq")
        return f"{ip}@{port}"

    @field_validator("absorbed")
    @classmethod
    def _check_absorbed(cls, v: list[str]) -> list[str]:
        for name in v:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,60}\.conf", name) or name == "azimuth.conf":
                raise ValueError(f"arquivo absorvido invalido: {name!r}")
        return v

    @model_validator(mode="after")
    def _coerencia(self) -> Resolver:
        if self.mode == "forward" and not self.forwarders:
            raise ValueError("modo 'forward' sem servidor: o unbound nao teria para onde perguntar")
        if len({bool(f.tls_name) for f in self.forwarders}) > 1:
            # forward-tls-upstream vale para a zona inteira: misturar mandaria
            # o servidor sem nome por TLS e sem certificado para conferir.
            raise ValueError("encaminhamento: ou todos os servidores tem nome TLS, ou nenhum")
        _reject_dups([z.domain for z in self.forward_zones], "dominio encaminhado repetido")
        _reject_dups([b.domain for b in self.blocked], "dominio bloqueado repetido")
        _reject_dups(
            [z.domain for z in self.forward_zones] + [b.domain for b in self.blocked],
            "dominio encaminhado e bloqueado ao mesmo tempo",
        )
        _reject_dups(self.absorbed, "arquivo absorvido repetido")
        return self

    @property
    def ip(self) -> str:
        return self.listen.partition("@")[0]

    @property
    def port(self) -> int:
        return int(self.listen.partition("@")[2])

    @property
    def tls(self) -> bool:
        return any(f.tls_name for f in self.forwarders)

    @property
    def dnsmasq_server(self) -> str:
        """O mesmo endereco na sintaxe do dnsmasq: '127.0.0.1#5335'."""
        return f"{self.ip}#{self.port}"


# ---------------------------------------------------------------------------
# raiz
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# DDNS (inadyn) — o nome e' do usuario, no provedor que ele escolher
# ---------------------------------------------------------------------------

DDNSProvider = Literal[
    "duckdns.org",
    "cloudflare.com",
    "noip.com",
    "dynu.com",
    "freedns.afraid.org",
    "desec.io",
    "namecheap.com",
    "he.net",
    "dyndns.org",
]
"""Os provedores que a tela oferece. Todos sao plugins nativos do inadyn 2.11
(inadyn -L); outro provedor do inadyn entra acrescentando o nome aqui."""


class DDNS(Base):
    """O nome estavel da caixa na internet, num provedor do proprio usuario.

    O projeto nao fornece DDNS: o usuario cadastra a conta dele (DuckDNS,
    Cloudflare, No-IP...) e o inadyn mantem o nome apontando para o IP
    publico. O segredo (token ou senha) nunca mora aqui: fica em
    secrets.yaml sob 'secret_ref', como a senha do PPPoE.
    """

    enabled: bool = False
    provider: DDNSProvider = "duckdns.org"
    hostname: Annotated[str, Field(pattern=HOSTNAME_RE.pattern)] | None = None
    """Nome completo que o provedor atualiza: casa.duckdns.org."""

    username: Annotated[str, Field(pattern=r"^[A-Za-z0-9@._+-]{1,128}$")] | None = None
    """Usuario da conta, ou a zona no Cloudflare. Vazio = provedor de token
    (DuckDNS): o token vai como usuario e a senha e' ignorada."""

    secret_ref: Annotated[str, Field(pattern=r"^[a-z0-9_-]{1,32}$")] = "ddns"
    period: Annotated[int, Field(ge=60, le=86400)] = 300
    """Segundos entre verificacoes do IP publico. E' esse intervalo que faz o
    nome seguir a WAN ativa depois de um failover."""

    @field_validator("hostname", mode="before")
    @classmethod
    def _lower(cls, v: str | None) -> str | None:
        return v.strip().lower().rstrip(".") if isinstance(v, str) and v.strip() else None

    @model_validator(mode="after")
    def _coerencia(self) -> DDNS:
        if self.enabled and not self.hostname:
            raise ValueError("DDNS ligado exige o nome (ex: casa.duckdns.org)")
        if self.enabled and self.provider == "cloudflare.com" and not self.username:
            raise ValueError("no Cloudflare, o usuario e' a zona (ex: exemplo.com)")
        return self


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
    resolver: Resolver = Resolver()
    ddns: DDNS = DDNS()

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

        # Quem responde ao dnsmasq: o unbound do modelo, ou o upstream escrito.
        # Os dois juntos seriam dois lugares dizendo a mesma coisa, e um dia
        # dizendo coisas diferentes.
        if self.resolver.enabled and self.dns.upstream:
            raise ValueError(
                "com o unbound ligado (resolver.enabled), o dnsmasq pergunta a ele: "
                "dns.upstream precisa ficar vazio"
            )
        if self.dns.no_resolv and not self.dns.upstream and not self.resolver.enabled:
            raise ValueError(
                "no_resolv sem upstream deixa o dnsmasq sem ninguem para perguntar: "
                "a LAN ficaria sem DNS"
            )
        casa = self.dns.domain
        for d in [z.domain for z in self.resolver.forward_zones] + [b.domain for b in self.resolver.blocked]:
            if d == casa or d.endswith("." + casa) or d == "azimuth":
                raise ValueError(f"{d!r} e' do dnsmasq (o dominio da casa), nao do unbound")
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
        route_owners = [w.name for w in self.wans if w.pppoe and w.pppoe.default_route]
        if route_owners and self.routing.failover.enabled:
            raise ValueError(
                f"{route_owners[0]}: o pppd dono da rota padrao e o failover ligado brigariam "
                "pela tabela; escolha um"
            )
        if len(route_owners) > 1:
            raise ValueError(f"mais de um pppd dono da rota padrao: {route_owners}")

        for name in self.firewall.masquerade:
            if name not in names:
                raise ValueError(f"masquerade aponta para interface inexistente: {name!r}")

        others = {o.name: o for o in self.firewall.other_interfaces}
        _reject_dups([o.name for o in self.firewall.other_interfaces], "outra interface duplicada")
        for o in self.firewall.other_interfaces:
            if o.name in names or o.name in {z.value for z in Zone}:
                raise ValueError(f"outra interface {o.name!r} usa nome de zona ou de interface do modelo")
            taken = {i.device for i in self.interfaces} | {i.ppp_device for i in self.interfaces}
            if self.wireguard.enabled:
                taken.add(self.wireguard.device)
            if o.device in taken:
                raise ValueError(f"outra interface {o.name!r}: o device {o.device} ja e' do modelo")
        for chain in ("input", "forward"):
            for rule in getattr(self.firewall, f"{chain}_rules"):
                for end in (rule.source, rule.destination):
                    if end is Zone.vpn and not self.wireguard.enabled:
                        raise ValueError(f"regra '{rule.description}' usa a zona vpn, mas o wireguard esta desligado")
                    if isinstance(end, str) and not isinstance(end, Zone) and "/" not in end and end not in others:
                        try:
                            ipaddress.IPv4Address(end)
                        except ValueError:
                            raise ValueError(
                                f"regra '{rule.description}' cita {end!r}, que nao e' outra interface conhecida"
                            ) from None
        for m in self.firewall.masquerade_rules:
            if m.interface not in names and m.interface not in others:
                raise ValueError(f"mascaramento aponta para interface inexistente: {m.interface!r}")
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
