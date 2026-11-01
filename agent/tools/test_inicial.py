#!/usr/bin/env python3
"""A configuracao da rede de uma caixa nova: do formulario a um config que o
modelo aceita e que o motor consegue renderizar inteiro.

O formulario e' a unica entrada de dados numa caixa recem-instalada, entao o
que ele recusa importa tanto quanto o que ele aceita: placa repetida, a
propria caixa dentro da faixa de DHCP, faixa fora da LAN, PPPoE sem senha.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fwadmin import inicial  # noqa: E402
from fwadmin.render import render_all  # noqa: E402

pass_n = fail_n = 0


def check(label: str, got, want) -> None:
    global pass_n, fail_n
    if got == want:
        print(f"  \033[32mok\033[0m   {label}")
        pass_n += 1
    else:
        print(f"  \033[31mFALHA\033[0m {label}\n       esperado: {want}\n       obtido:   {got}")
        fail_n += 1


PLACAS = [{"device": "enp1s0", "ipv4": "192.168.1.50/24"}, {"device": "enp2s0", "ipv4": ""}]
BASE = {
    "wan_device": "enp1s0", "wan_mode": "dhcp", "lan_device": "enp2s0",
    "lan_address": "10.0.0.1/24", "dhcp_start": "10.0.0.100", "dhcp_end": "10.0.0.199", "domain": "lan",
}


def recusa(label: str, **troca) -> None:
    try:
        inicial.validate(dict(BASE, **troca), PLACAS)
    except ValueError as exc:
        check(label, bool(str(exc)), True)
    else:
        check(label, "aceitou", "recusou")


print("== o que sai do formulario ==")
cfg = inicial.validate(BASE, PLACAS)
check("uma LAN, com o endereco pedido", cfg.lan.ipv4.address, "10.0.0.1/24")
check("uma WAN por DHCP", [(w.device, w.ipv4.mode.value) for w in cfg.wans], [("enp1s0", "dhcp")])
check("sem failover: uma WAN so", cfg.routing.failover.enabled, False)
check("a LAN e' a rede de administracao", cfg.system.admin_cidr, "10.0.0.0/24")
check("NAT de saida pela WAN", cfg.firewall.masquerade, ["wan"])
check("a LAN sai para a internet", [(r.source.value, r.destination.value) for r in cfg.firewall.forward_rules], [("lan", "wan")])
check("faixa de DHCP", (cfg.dhcp.range.start, cfg.dhcp.range.end), ("10.0.0.100", "10.0.0.199"))
check("dominio da casa", cfg.dns.domain, "lan")
arquivos = render_all(cfg)
check("o motor renderiza nftables, dnsmasq e interfaces", sorted(arquivos), ["azimuth.nft", "dnsmasq.conf", "interfaces"])
check("o nft gerado tem o NAT da WAN", "masquerade" in arquivos["azimuth.nft"], True)

ppp = inicial.validate(dict(BASE, wan_mode="pppoe", pppoe_user="cliente@provedor", pppoe_password="s3nha"), PLACAS)
w = ppp.wans[0]
check("PPPoE: o pppd poe a rota", (w.ipv4.mode.value, w.pppoe.default_route), ("pppoe", True))
check("PPPoE: a senha so por referencia", (w.pppoe.password_ref, "s3nha" in ppp.model_dump_json()), ("wan", False))
check("PPPoE renderiza", len(render_all(ppp)) > 3, True)

fixo = inicial.validate(dict(BASE, wan_mode="static", wan_address="203.0.113.10/29",
                             wan_gateway="203.0.113.9", wan_dns="1.1.1.1, 8.8.8.8"), PLACAS)
check("IP fixo na WAN", (fixo.wans[0].ipv4.address, fixo.wans[0].ipv4.dns_nameservers),
      ("203.0.113.10/29", ["1.1.1.1", "8.8.8.8"]))

print("\n== o que ele recusa ==")
recusa("WAN e LAN na mesma placa", lan_device="enp1s0")
recusa("placa que a maquina nao tem", wan_device="eth9")
recusa("modo de WAN desconhecido", wan_mode="satelite")
recusa("endereco da LAN sem prefixo valido", lan_address="10.0.0.1/33")
recusa("endereco da LAN e' o da rede", lan_address="10.0.0.0/24")
recusa("a propria caixa dentro da faixa", dhcp_start="10.0.0.1")
recusa("faixa fora da LAN", dhcp_start="192.168.0.10", dhcp_end="192.168.0.20")
recusa("faixa invertida", dhcp_start="10.0.0.199", dhcp_end="10.0.0.100")
recusa("PPPoE sem usuario", wan_mode="pppoe", pppoe_password="x")
recusa("PPPoE sem senha", wan_mode="pppoe", pppoe_user="u")
recusa("IP fixo sem endereco", wan_mode="static")
recusa("LAN cruzando a rede que a WAN recebe", lan_address="192.168.1.1/24", dhcp_start="192.168.1.100", dhcp_end="192.168.1.199")

print("\n== sugestao inicial ==")
placas = [{"device": "enp1s0", "ipv4": "192.168.1.50/24"}, {"device": "enp2s0", "ipv4": ""}]
d = inicial.defaults(placas)
check("WAN sugerida e' a que ja tem IP", (d["wan_device"], d["lan_device"]), ("enp1s0", "enp2s0"))
check("a sugestao passa na validacao", bool(inicial.validate(d, PLACAS)), True)
check("sem conflito, sugere 10.0.0.1/24", d["lan_address"], "10.0.0.1/24")
atras = [{"device": "enp1s0", "ipv4": "10.0.0.61/24"}, {"device": "enp2s0", "ipv4": ""}]
d2 = inicial.defaults(atras)
check("atras de um 10.0.0.x, sugere 192.168.50.1/24", (d2["lan_address"], d2["dhcp_start"]), ("192.168.50.1/24", "192.168.50.100"))
check("e essa sugestao passa", bool(inicial.validate(d2, atras)), True)

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
sys.exit(1 if fail_n else 0)
