#!/bin/sh
# Primeiro boot do Azimuth: instala o painel, uma vez so.
#
# Roda pela azimuth-primeiro-boot.service, com a rede no ar. A placa da LAN e'
# a da rota padrao (por enquanto a unica ligada). O deploy/install-readonly.sh
# do agente instala o painel e o login pelo PAM. Nao aplica nada: nenhum
# servico de rede muda aqui.
#
# Ainda nao adota (deploy/adopt.sh): o importador le um firewall montado, com
# LAN, WAN e DHCP no /etc, e uma caixa recem-instalada nao tem nenhum dos tres.
# O config.yaml de uma caixa nova sai da configuracao da rede no painel (fase 2).
#
# Deu certo: a unidade se desliga. Falhou: fica ligada e tenta no proximo boot;
# o motivo esta em 'journalctl -u azimuth-primeiro-boot'.
set -eu

AGENTE=/opt/azimuth-agent

LAN=""
for _ in $(seq 1 60); do
    LAN=$(ip -4 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit } }')
    [ -n "$LAN" ] && ip -4 -o addr show dev "$LAN" | grep -q inet && break
    LAN=""
    sleep 2
done
[ -n "$LAN" ] || { echo "sem rota padrao com IPv4 depois de 2 minutos; tento no proximo boot"; exit 1; }
echo "LAN: $LAN ($(ip -4 -o addr show dev "$LAN" | awk '{ print $4; exit }'))"

LAN="$LAN" "$AGENTE/deploy/install-readonly.sh"
systemctl disable azimuth-primeiro-boot.service
echo "painel instalado; esta unidade foi desligada"
