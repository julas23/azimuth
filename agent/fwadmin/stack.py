"""Os servicos da stack do Azimuth: a tela de Servicos, o 'fwctl servico' e o
comando 'azimuth' dos agentes usam a mesma lista.

Fora daqui (zabbix, ssh, nginx) nao e' do portal: nao aparece na tela e o
'fwctl servico' recusa.
"""

from __future__ import annotations

from fwadmin.models import Config


def stack(cfg: Config) -> list[dict[str, str]]:
    """Os servicos que o portal administra, na ordem da tela de Servicos.

    So a stack do Azimuth: o que mais roda na maquina (zabbix, ssh, nginx)
    nao e' do portal e nao aparece aqui.
    """
    wg = cfg.wireguard.device if cfg.wireguard.enabled else "wg0"
    return [
        {"key": "nftables", "name": "Firewall", "role": "filtra o que entra e o que atravessa",
         "unit": "nftables.service", "package": "nftables", "href": "/firewall"},
        {"key": "fail2ban", "name": "Fail2Ban", "role": "bane quem erra a senha demais",
         "unit": "fail2ban.service", "package": "fail2ban", "href": "/fail2ban"},
        {"key": "dnsmasq", "name": "DHCP e domínio", "role": "entrega IPs e responde os nomes da LAN",
         "unit": "dnsmasq.service", "package": "dnsmasq", "href": "/dhcp"},
        {"key": "unbound", "name": "DNS", "role": "resolve na internet o que não é da LAN",
         "unit": "unbound.service", "package": "unbound", "href": "/dns"},
        {"key": "wireguard", "name": "VPN", "role": f"túnel WireGuard {wg}",
         "unit": f"wg-quick@{wg}.service", "package": "wireguard-tools", "href": "/vpn"},
        {"key": "ddns", "name": "DDNS", "role": "mantém o nome da caixa no IP público",
         "unit": "azimuth-ddns.service", "package": "inadyn", "href": "/vpn"},
        {"key": "docker", "name": "Containers", "role": "roda os aplicativos, fora do firewall",
         "unit": "docker.service", "package": "docker.io", "href": "/services"},
    ]


def by_key(cfg: Config) -> dict[str, dict[str, str]]:
    return {s["key"]: s for s in stack(cfg)}
