"""
Gera o arquivo .conf do WireGuard para o cliente e o QR code PNG correspondente.

Full tunnel (desde 2026-08-16): todo o tráfego do cliente vai pelo túnel, então
o IP visto por qualquer destino é o do concentrador. A diferenciação por plano
NÃO é feita aqui — AllowedIPs é escolha do cliente e ele pode editar o .conf.
Quem restringe é a chain `plan-policy` do NFTables no servidor.

Antes disso o AllowedIPs era a allowlist do split tunnel; a lista continua
existindo em brazil_services.json porque alimenta o set NFTables usado pela
plan-policy (e `brazil_cidrs.get_allowed_ips()` segue disponível para rollback).
"""
import io
import qrcode
from config import settings

# Rota default v4. IPv6 fica de fora: o servidor não provisiona endereço v6 nos
# peers, e anunciar ::/0 sem rota deixaria o cliente sem saída v6.
_FULL_TUNNEL_ALLOWED_IPS = "0.0.0.0/0"


def build_conf(
    private_key: str,
    client_ip: str,
    dns_ip: str,
) -> str:
    allowed = _FULL_TUNNEL_ALLOWED_IPS
    return (
        f"[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {dns_ip}\n"
        f"MTU = 1420\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {settings.WG_SERVER_PUBLIC_KEY}\n"
        f"Endpoint = {settings.SERVER_PUBLIC_IP}:{settings.WG_SERVER_PORT}\n"
        f"AllowedIPs = {allowed}\n"
        f"PersistentKeepalive = 25\n"
    )


def build_qr_png(conf: str) -> bytes:
    img = qrcode.make(conf)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
