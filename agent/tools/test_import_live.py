#!/usr/bin/env python3
"""O importador le o firewall que existe, nao o que ele esperava encontrar.

Regressao de 2026-10-25: o import_live.py tinha sido escrito em cima do HP e
quebrava no primeiro firewall diferente — endereco em CIDR, placa do PPPoE
declarada como 'inet dhcp', upstream com porta, reserva sem nome. Pior: as
regras de nftables nao eram lidas, eram escritas a mao no proprio script, de
modo que tudo o que a maquina tinha alem disso sumia sem aviso no primeiro
apply.

O firewall daqui e' sintetico (MACs e chaves inventados), com a forma do
firewall virtual que substituiu o HP.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import import_live  # noqa: E402

from pydantic import ValidationError  # noqa: E402

from fwadmin.models import Config  # noqa: E402
from fwadmin.render import render_all  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

pass_n = fail_n = 0


def check(label: str, got, want) -> None:
    global pass_n, fail_n
    if got == want:
        print(f"  \033[32mok\033[0m   {label}")
        pass_n += 1
    else:
        print(f"  \033[31mFALHA\033[0m {label}\n       esperado: {want}\n       obtido:   {got}")
        fail_n += 1


def run(live: Path, portal: Path) -> tuple[Config, list[str], list[str]]:
    import_live.FINDINGS.clear()
    import_live.CHANGES.clear()
    cfg = Config.model_validate(import_live.build(live, portal))
    return cfg, list(import_live.FINDINGS), list(import_live.CHANGES)


def mentions(items: list[str], text: str) -> bool:
    return any(text in i for i in items)


LIVE = {
    "interfaces": """\
auto lo
iface lo inet loopback

auto lan0
allow-hotplug lan0
iface lan0 inet static
\taddress 10.0.0.1/24
\tdns-nameservers 9.9.9.9

auto wanp
iface wanp inet dhcp

auto wand
iface wand inet dhcp
""",
    "ppp-peers-vivo": """\
plugin rp-pppoe.so
wanp
user "fulano@provedor"
password "segredo"
noauth
defaultroute
replacedefaultroute
persist
maxfail 0
holdoff 5
""",
    "dnsmasq.conf": """\
interface=lan0
bind-interfaces
domain=home.lan
expand-hosts
local=/home.lan/
dhcp-authoritative
dhcp-range=10.0.0.10,10.0.0.99,255.255.255.0,12h
dhcp-option=option:router,10.0.0.1
dhcp-option=6,10.0.0.1
dhcp-host=02:00:00:00:00:01,10.0.0.11,desk_1
dhcp-host=00:00:00:00:00:00,10.0.0.12,RESERVADO
dhcp-host=00:00:00:00:00:00,10.0.0.13,RESERVADO
dhcp-host=02:00:00:00:00:02,10.0.0.14,
dhcp-host=02:00:00:00:00:03,10.0.0.15,tv
address=/desk-1.home.lan/10.0.0.11
address=/kali.home.lan/10.0.0.14
address=/tv.home.lan/10.0.0.50
no-resolv
server=127.0.0.1#5335
""",
    "nftables.conf": """\
#!/usr/sbin/nft -f
table inet filter
delete table inet filter
table ip nat
delete table ip nat

define WAN = { "ppp0", "wand" }

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname $WAN tcp dport 22 counter drop comment "SSH so LAN"
        iifname $WAN tcp dport { 80, 443 } counter drop comment "web so LAN"
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        tcp flags syn tcp option maxseg size set rt mtu
        iifname "lan0" oifname $WAN counter accept comment "LAN sai"
        iifname "wg0" oifname "lan0" counter accept comment "VPN entra na LAN"
        iifname "ppp0" oifname "lan0" ip daddr 10.0.0.15 tcp dport 8096 ct status dnat counter accept comment "midia"
    }
}

table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "ppp0" tcp dport 18096 counter dnat to 10.0.0.15:8096 comment "midia"
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "ppp0" masquerade comment "NAT vivo"
        oifname "wand" masquerade comment "NAT star"
        oifname "wgsite" ip saddr 10.80.0.0/24 masquerade comment "VPN para o site"
    }
}
""",
    "runtime.json": '{"ppp_units": ["ppp@provider.service"]}',
    "wireguard/wg0.conf": """\
[Interface]
Address = 10.80.0.1/24
ListenPort = 51820
MTU = 1420
PostUp = wg set %i private-key /etc/wireguard/wg0.key

[Peer]
# Celular
PublicKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
AllowedIPs = 10.80.0.2/32
""",
    "wireguard/wgsite.conf": """\
[Interface]
Address = 10.90.0.2/24
PostUp = wg set %i private-key /etc/wireguard/wgsite.key

[Peer]
PublicKey = ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=
Endpoint = 192.0.2.10:51821
AllowedIPs = 10.90.0.0/24
""",
}

with tempfile.TemporaryDirectory(prefix="fwadmin-import.") as tmp:
    live = Path(tmp)
    for name, text in LIVE.items():
        (live / name).parent.mkdir(parents=True, exist_ok=True)
        (live / name).write_text(text)

    cfg, findings, changes = run(live, live / "sem-portal.html")

    print("== interfaces ==")
    check("LAN em CIDR", cfg.lan.ipv4.address, "10.0.0.1/24")
    check("placa do PPPoE em 'inet dhcp' nao vira a WAN DHCP", cfg.iface("wan_star").device, "wand")
    check("PPPoE no device certo", cfg.iface("wan_vivo").device, "wanp")
    vivo_if = cfg.iface("wan_vivo")
    check("'inet dhcp' do PPPoE fica como esta", vivo_if.pppoe.carrier, "dhcp")
    check("e so com aviso", mentions(findings, "vale trocar para manual"), True)
    check("dns-nameservers importado", cfg.lan.ipv4.dns_nameservers, ["9.9.9.9"])
    gerado_if = render_all(cfg)["interfaces"]
    check("e gerado de volta", "dns-nameservers 9.9.9.9" in gerado_if, True)
    check("nenhum dos dois vira mudanca",
          [mentions(changes, k) for k in ("inet dhcp", "dns-nameservers")], [False, False])

    print("\n== PPPoE ==")
    check("senha no peers/ nao e' mais mudanca", mentions(changes, "senha"), False)
    check("vai para o arquivo de senha do motor", cfg.iface("wan_vivo").pppoe.password_file, True)
    check("e o peer gerado o inclui", "file /etc/ppp/azimuth-vivo.secret" in render_all(cfg)["ppp-peers-vivo"], True)
    check("sem a senha em nada que o painel renderiza",
          any('password "segredo"' in v or "segredo\"" in v for v in render_all(cfg).values()), False)
    check("sem failover, o pppd continua dono da rota", cfg.iface("wan_vivo").pppoe.default_route, True)
    check("o link e' do systemd", cfg.iface("wan_vivo").pppoe.unit, "ppp@provider.service")
    from fwadmin.services import pppoe as pppoe_svc
    recarga = pppoe_svc.reloads(cfg, None, ["ppp-peers-vivo"])[0].argv[-1]
    check("e o reinicio passa pelo systemctl, sem pon/poff",
          ("systemctl restart ppp@provider.service" in recarga, "pon " in recarga), (True, False))
    peer = render_all(cfg)["ppp-peers-vivo"]
    check("o peer gerado pede a rota como o vivo",
          ["defaultroute" in peer.split(), "replacedefaultroute" in peer.split(), "nodefaultroute" in peer.split()],
          [True, True, False])
    check("o que o vivo nao escreve, o gerado nao escreve",
          [k in peer for k in ("lcp-echo-interval", "mtu ", "mru ")], [False, False, False])
    check("o peer gerado bate com o vivo, fora a senha",
          [c for c in changes if c.startswith("peers/")], [])
    check("sem failover vivo, failover importado desligado", cfg.routing.failover.enabled, False)

    print("\n== DNS e DHCP ==")
    check("bind-interfaces importado", cfg.dns.bind_interfaces, True)
    check("upstream com porta entra (o unbound atras do dnsmasq)", cfg.dns.upstream, ["127.0.0.1#5335"])
    check("no-resolv entra", cfg.dns.no_resolv, True)
    check("dhcp-authoritative entra", cfg.dhcp.authoritative, True)
    check("nenhuma delas vira mudanca",
          [mentions(changes, k) for k in ("5335", "dhcp-authoritative", "no-resolv")], [False, False, False])
    gerado = render_all(cfg)["dnsmasq.conf"]
    check("e o dnsmasq gerado traz as tres",
          [line in gerado.splitlines() for line in ("dhcp-authoritative", "no-resolv", "server=127.0.0.1#5335")],
          [True, True, True])
    try:
        Config.model_validate(cfg.model_dump() | {"dns": cfg.dns.model_dump() | {"upstream": []}})
        sem_dns = False
    except ValidationError:
        sem_dns = True
    check("no-resolv sem upstream e' recusado (LAN sem DNS)", sem_dns, True)
    names = {r.ip: r.name for r in cfg.dhcp.reservations}
    check("MAC zerado nao vira reserva de aparelho", "10.0.0.12" in names or "10.0.0.13" in names, False)
    check("mas segura o IP fora da distribuicao", cfg.dhcp.held, ["10.0.0.12", "10.0.0.13"])
    check("e o gerado segura do mesmo jeito",
          "dhcp-host=00:00:00:00:00:00,10.0.0.12" in render_all(cfg)["dnsmasq.conf"], True)
    check("reserva sem nome empresta o do DNS", names.get("10.0.0.14"), "kali")
    check("'_' vira '-'", names.get("10.0.0.11"), "desk-1")
    tv = next(h for h in cfg.hosts if h.name == "tv")
    check("DNS divergente segue a reserva", tv.ip, "10.0.0.15")
    check("e a divergencia vira mudanca", mentions(changes, "'tv': DHCP entrega 10.0.0.15"), True)

    print("\n== nftables ==")
    check("bloqueios de input viram redundantes",
          [r.description for r in cfg.firewall.input_rules if r.action.value != "accept"], [])
    check("e saem com aviso", mentions(findings, "redundante com a entrada fechada"), True)
    check("entrada sempre fechada", cfg.firewall.input_policy.value, "drop")
    check("a troca de politica vira mudanca", mentions(changes, "lista negra vira lista branca"), True)
    check("forward lan -> wan e vpn -> lan lidos",
          [(r.source.value, r.destination.value) for r in cfg.firewall.forward_rules],
          [("lan", "wan"), ("vpn", "lan")])
    pf = cfg.firewall.port_forwards
    check("DNAT vira port-forward",
          [(p.interface, p.wan_port, p.to_ip, p.to_port) for p in pf],
          [("wan_vivo", 18096, "10.0.0.15", 8096)])
    check("accept do port-forward absorvido, nao duplicado", mentions(changes, "midia"), False)
    check("o tunel do modelo vira a zona vpn, sem mudanca", mentions(changes, "VPN entra na LAN"), False)
    check("masquerade lido na ordem", cfg.firewall.masquerade, ["wan_vivo", "wan_star"])
    check("masquerade com origem pelo outro tunel entra",
          [(m.interface, m.source) for m in cfg.firewall.masquerade_rules], [("wgsite", "10.80.0.0/24")])
    check("e nao vira mudanca", mentions(changes, "VPN para o site"), False)

    print("\n== WireGuard ==")
    check("tunel com ListenPort entra", (cfg.wireguard.enabled, cfg.wireguard.device), (True, "wg0"))
    check("chave continua fora do modelo", cfg.wireguard.private_key_file, "/etc/wireguard/wg0.key")
    check("comentario vira nome do peer", [p.name for p in cfg.wireguard.peers], ["celular"])
    check("o outro tunel fica de fora, com aviso", mentions(findings, "'wgsite' fica fora"), True)
    check("e vira outra interface do firewall",
          [(o.name, o.device) for o in cfg.firewall.other_interfaces], [("wgsite", "wgsite")])
    check("que entrava pela entrada aberta e continua entrando, como excecao explicita",
          [(r.source, r.destination.value, r.action.value) for r in cfg.firewall.input_rules],
          [("wgsite", "this", "accept")])

    print("\n== nftables gerado: entrada fechada, com a base ==")
    nft = render_all(cfg)["azimuth.nft"]
    input_chain = nft.split("chain input {")[1].split("chain forward {")[0]
    check("so a tabela do motor", [t for t in ("table inet azimuth {", "table inet filter", "table ip nat") if t in nft],
          ["table inet azimuth {"])
    check("apaga so a propria tabela", [l for l in nft.splitlines() if l.startswith("delete table")],
          ["delete table inet azimuth"])
    check("DNAT no formato da familia inet", "dnat ip to 10.0.0.15:8096" in nft, True)
    check("politica drop", "policy drop;" in input_chain, True)
    check("LAN entra", 'iifname "lan0" accept' in input_chain, True)
    check("established antes de tudo", "ct state established,related accept" in input_chain, True)
    check("WireGuard aberto na WAN", "iifname $WAN udp dport 51820 accept" in input_chain, True)
    check("peers da VPN entram", 'iifname "wg0" accept' in input_chain, True)
    check("excecao do outro tunel gerada", 'iifname "wgsite" counter accept' in input_chain, True)
    check("regra da zona vpn gerada com o device", 'iifname "wg0" oifname "lan0" counter accept' in nft, True)
    check("masquerade com origem gerado",
          'oifname "wgsite" ip saddr 10.80.0.0/24 masquerade comment "VPN para o site"' in nft, True)
    check("DHCP do provedor responde na WAN dhcp", 'iifname "wand" udp sport 67 udp dport 68 accept' in input_chain, True)
    try:
        Config.model_validate(cfg.model_dump() | {"firewall": cfg.firewall.model_dump() | {"input_policy": "accept"}})
        recusou = False
    except ValidationError:
        recusou = True
    check("o modelo recusa entrada aberta", recusou, True)

    print("\n== gravar e recarregar devolve o mesmo modelo ==")
    import yaml as _yaml
    from fwadmin.render import dump
    volta = Config.model_validate(_yaml.safe_load(dump(cfg)))
    check("o YAML gravado recarrega igual (None que importa nao some)", volta == cfg, True)
    check("MTU negociado continua negociado", volta.iface("wan_vivo").pppoe.mtu, None)

print("\n== o HP so muda a entrada, que fecha ==")
cfg, findings, changes = run(ROOT / "legacy" / "live", ROOT / "legacy" / "portal-index.html")
check("so muda a entrada, de lista negra para lista branca",
      [c.split(":")[0] for c in changes], ["nftables/input"])
check("failover continua ligado (o pppd abria mao da rota)", cfg.routing.failover.enabled, True)
check("as duas regras por WAN viram uma so",
      [(r.source.value, r.destination.value) for r in cfg.firewall.forward_rules],
      [("lan", "wan")])

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
sys.exit(1 if fail_n else 0)
