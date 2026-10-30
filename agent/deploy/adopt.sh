#!/bin/bash
# Adocao: o motor completo numa maquina que ja estava rodando.
#
# O install.sh monta a caixa do zero: instala o config.yaml de exemplo, poe o
# nginx no lugar do portal, liga o timer de failover. Numa maquina montada a
# mao isso trocaria o que ela tem pelo que o exemplo tem. Este script, em vez
# disso, le a maquina:
#
#   1. o painel enxuto (install-readonly.sh), se ainda nao estiver;
#   2. /etc/fwadmin/config.yaml gerado pelo importador a partir do /etc vivo,
#      e o historico git comecando nele;
#   3. o sudoers completo (apply, confirm, rollback, seal);
#   4. a azimuth-nftables.service, que so carrega algo depois do 1o apply;
#   5. o painel deixa o modo somente leitura (continua em https://<LAN>:8443).
#
# NAO aplica nada: nenhum arquivo de configuracao do firewall muda aqui. O
# primeiro apply e' uma decisao a parte, e trava enquanto houver mudanca que
# ninguem marcou como intencional. Nao toca em nginx, crontab nem failover.
#
#   ./deploy/adopt.sh              adota
#   ./deploy/adopt.sh --desfazer   volta ao painel somente leitura
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "rode como root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DROPIN=/etc/systemd/system/fwadmin.service.d/readonly.conf
CONFIG=/etc/fwadmin/config.yaml

if [ "${1:-}" = "--desfazer" ]; then
    # So enquanto nenhum apply aconteceu: depois dele o /etc ja e' do motor, e
    # desfazer a adocao e' rollback, nao isto.
    if [ -e /var/lib/fwadmin/owned.json ]; then
        echo "o motor ja aplicou e selou esta maquina; use 'fwctl rollback' e o historico em /etc/fwadmin"
        exit 1
    fi
    rm -rf /etc/fwadmin
    install -m 0440 "$SRC/deploy/sudoers-fwadmin-readonly" /etc/sudoers.d/fwadmin
    systemctl disable azimuth-nftables.service 2>/dev/null || true
    rm -f /etc/systemd/system/azimuth-nftables.service
    sed -i -e 's/^Environment=FWADMIN_READONLY=.*/Environment=FWADMIN_READONLY=1/' \
           -e 's|^ReadWritePaths=/var/lib/fwadmin /etc /usr/local/bin$|ReadWritePaths=/var/lib/fwadmin|' "$DROPIN"
    systemctl daemon-reload
    systemctl restart fwadmin.service
    echo "de volta ao painel somente leitura; nada no firewall foi tocado"
    exit 0
fi

if [ -e "$CONFIG" ]; then
    echo "esta maquina ja foi adotada ($CONFIG existe)"
    exit 1
fi

echo "== 1. painel enxuto =="
"$SRC/deploy/install-readonly.sh" | grep -E "https://|versao|faltam|apt install" || true
systemctl is-active --quiet fwadmin.service || { echo "o painel nao subiu; pare aqui"; exit 1; }

echo "== 2. config a partir da maquina =="
install -d -m 0755 -o netadm -g netadm /etc/fwadmin
/usr/local/sbin/fwctl observe >/dev/null
GERADO="$(mktemp /etc/fwadmin/.config.XXXXXX)"
PYTHONPATH=/opt/fwadmin python3 - "$GERADO" <<'PY'
import sys
from pathlib import Path
from fwadmin import importer, observe
from fwadmin.render import dump
cfg, findings, changes = importer.run(observe.LIVE)
Path(sys.argv[1]).write_text(dump(
    cfg,
    header="# Config VIVA do fwadmin, importada da maquina na adocao. Alterada pela UI;\n"
           "# versionada em git. Ate o primeiro apply, o /etc ainda e' o de antes.\n",
))
print(f"   {len(cfg.interfaces)} interfaces · {len(cfg.dhcp.reservations)} reservas · "
      f"{len(cfg.firewall.forward_rules)} regras de encaminhamento · {len(changes)} mudancas na adocao")
PY
chown netadm:netadm "$GERADO"
chmod 0644 "$GERADO"
mv "$GERADO" "$CONFIG"

GIT="git -c safe.directory=/etc/fwadmin -C /etc/fwadmin"
[ -d /etc/fwadmin/.git ] || $GIT init -q
printf 'secrets.yaml\nsecrets.pending.yaml\nconfig.pending.yaml\napply-note\n' > /etc/fwadmin/.gitignore
$GIT add config.yaml .gitignore
$GIT -c user.name=fwadmin -c user.email=fwadmin@localhost commit -q -m "adocao: config importada da maquina em producao"
chown -R netadm:netadm /etc/fwadmin
echo "   $CONFIG e o primeiro commit"

echo "== 3. sudoers completo =="
install -m 0440 "$SRC/deploy/sudoers-fwadmin" /etc/sudoers.d/fwadmin
visudo -c -q || { install -m 0440 "$SRC/deploy/sudoers-fwadmin-readonly" /etc/sudoers.d/fwadmin; echo "   sudoers invalido — voltei ao enxuto"; exit 1; }
echo "   apply, confirm, rollback, seal, inventory"
install -m 0755 "$SRC/sbin/azimuth-agente-sessao" /usr/local/sbin/azimuth-agente-sessao
install -m 0644 "$SRC/deploy/azimuth-agente@.service" /etc/systemd/system/azimuth-agente@.service
install -m 0644 "$SRC/deploy/azimuth-agente.tmpfiles" /etc/tmpfiles.d/azimuth-agente.conf
systemd-tmpfiles --create /etc/tmpfiles.d/azimuth-agente.conf
echo "   agentes no navegador (AGENTES.md): sessao, unidade e registro de 30 dias"
if command -v fail2ban-client >/dev/null; then
    install -m 0644 "$SRC/deploy/fail2ban/azimuth-panel-filter.conf" /etc/fail2ban/filter.d/azimuth-panel.conf
    install -m 0644 "$SRC/deploy/fail2ban/azimuth-panel-jail.conf" /etc/fail2ban/jail.d/azimuth-panel.conf
    if fail2ban-client -t >/dev/null 2>&1; then
        fail2ban-client reload >/dev/null 2>&1 || true
        echo "   jail azimuth-panel no fail2ban (senha errada no painel)"
    else
        rm -f /etc/fail2ban/filter.d/azimuth-panel.conf /etc/fail2ban/jail.d/azimuth-panel.conf
        echo "   fail2ban recusou o jail do painel — ficou sem ele"
    fi
fi

echo "== 4. tabela do motor no nftables =="
install -d -m 0755 /etc/nftables.d
install -m 0644 "$SRC/deploy/azimuth-nftables.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable azimuth-nftables.service >/dev/null 2>&1
echo "   azimuth-nftables.service habilitada; fica quieta ate o primeiro apply"

echo "== 5. painel com acoes =="
# O drop-in do enxuto segue valendo (TLS direto no IP da LAN, origem filtrada);
# so o modo e os caminhos de escrita mudam, para o fwctl chamado pelo painel
# conseguir gravar em /etc.
sed -i -e 's/^Environment=FWADMIN_READONLY=.*/Environment=FWADMIN_READONLY=0/' \
       -e 's|^ReadWritePaths=/var/lib/fwadmin$|ReadWritePaths=/var/lib/fwadmin /etc /usr/local/bin|' "$DROPIN"
systemctl daemon-reload
systemctl restart fwadmin.service
sleep 1
systemctl is-active --quiet fwadmin.service || { echo "o painel nao voltou; rode '$0 --desfazer'"; exit 1; }
echo "   somente leitura desligado"

echo
echo "adotada. Nenhum arquivo de configuracao do firewall mudou."
echo "O que o primeiro apply trocaria:  fwctl check   ·  linha a linha:  fwctl diff"
echo "Mudancas da adocao e marcacoes:   fwctl ack"
