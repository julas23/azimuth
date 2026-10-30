#!/bin/bash
# Instala o fwadmin no firewall. Rodar COMO ROOT, no proprio HP.
#
# O que faz, na ordem:
#   1. cria o usuario netadm (sem shell, sem home util)
#   2. copia o codigo para /opt/fwadmin e o fwctl para /usr/local/sbin
#   3. instala o config.yaml em /etc/fwadmin e inicia o repositorio git
#   4. instala sudoers, units do systemd e o vhost do nginx
#   5. gera o certificado self-signed
#   6. APOSENTA a entrada de crontab do wan-failover.sh antiga
#
# O que NAO faz: aplicar configuracao. Depois de instalar, o /etc do firewall
# continua exatamente como estava — a primeira mudanca so acontece quando
# alguem clicar em Aplicar e confirmar.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "rode como root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "== 1. usuario de servico =="
if ! id netadm >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/fwadmin --create-home \
            --shell /usr/sbin/nologin netadm
    echo "   netadm criado"
else
    echo "   netadm ja existe"
fi
# Sem isto a tela de diagnostico enxerga so o proprio journal do servico.
usermod -aG systemd-journal netadm
echo "   netadm no grupo systemd-journal"

echo "== 2. codigo =="
install -d -m 0755 /opt/fwadmin
cp -r "$SRC/fwadmin" /opt/fwadmin/
install -m 0755 "$SRC/sbin/fwctl" /usr/local/sbin/fwctl
echo "   /opt/fwadmin e /usr/local/sbin/fwctl"

echo "== 3. estado e configuracao =="
install -d -m 0750 -o netadm -g netadm /var/lib/fwadmin
install -d -m 0755 -o netadm -g netadm /etc/fwadmin
install -d -m 0700 -o netadm -g netadm /etc/fwadmin/tls

if [ ! -e /etc/fwadmin/config.yaml ]; then
    install -m 0644 -o netadm -g netadm "$SRC/config/config.yaml" /etc/fwadmin/config.yaml
    echo "   config.yaml instalado"
else
    echo "   config.yaml ja existe — preservado"
fi

# O diretorio e' do netadm (ele precisa gravar a proposta), mas o git roda
# como root — dai o safe.directory. Sem isso o git recusa o repositorio.
GIT="git -c safe.directory=/etc/fwadmin -C /etc/fwadmin"

[ -d /etc/fwadmin/.git ] || $GIT init -q

# A condicao e' "ja tem commit", nao "ja tem .git": um init que deu certo com
# um commit que falhou deixaria o repositorio vazio para sempre.
if ! $GIT rev-parse HEAD >/dev/null 2>&1; then
    $GIT add config.yaml
    $GIT -c user.name=fwadmin -c user.email=fwadmin@localhost \
        commit -q -m "estado importado do firewall em producao"
    echo "   commit inicial do historico"
else
    echo "   historico git ja existe ($($GIT rev-list --count HEAD) commits)"
fi
chown -R netadm:netadm /etc/fwadmin/.git

echo "== 4. sudoers =="
install -m 0440 "$SRC/deploy/sudoers-fwadmin" /etc/sudoers.d/fwadmin
visudo -c -q || { rm -f /etc/sudoers.d/fwadmin; echo "sudoers invalido — removido"; exit 1; }
echo "   validado com visudo"
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

echo "== 5. systemd =="
install -m 0644 "$SRC/deploy/fwadmin.service"          /etc/systemd/system/
install -m 0644 "$SRC/deploy/azimuth-nftables.service" /etc/systemd/system/
install -d -m 0755 /etc/nftables.d
install -m 0644 "$SRC/deploy/fwadmin-failover.service" /etc/systemd/system/
install -m 0644 "$SRC/deploy/fwadmin-failover.timer"   /etc/systemd/system/
systemctl daemon-reload
echo "   units instaladas"

echo "== 6. certificado =="
if [ ! -e /etc/fwadmin/tls/fwadmin.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /etc/fwadmin/tls/fwadmin.key \
        -out    /etc/fwadmin/tls/fwadmin.crt \
        -subj "/CN=fw.home.lan" \
        -addext "subjectAltName=DNS:fw.home.lan,DNS:portal.home.lan,IP:10.0.0.1" 2>/dev/null
    chmod 0600 /etc/fwadmin/tls/fwadmin.key
    chown -R netadm:netadm /etc/fwadmin/tls
    echo "   self-signed gerado (valido por 10 anos)"
else
    echo "   certificado ja existe — preservado"
fi

echo "== 7. nginx =="
cp /etc/nginx/sites-available/portal /etc/nginx/sites-available/portal.bak-fwadmin 2>/dev/null || true
install -m 0644 "$SRC/deploy/nginx-fwadmin.conf" /etc/nginx/sites-available/fwadmin
ln -sf /etc/nginx/sites-available/fwadmin /etc/nginx/sites-enabled/fwadmin
rm -f /etc/nginx/sites-enabled/portal
nginx -t
echo "   vhost do fwadmin no lugar do portal (o antigo virou portal.bak-fwadmin)"

# O nginx passa a amarrar no IP da LAN, e bind em IP especifico exige que a
# interface ja tenha endereco quando o servico sobe.
install -d -m 0755 /etc/systemd/system/nginx.service.d
install -m 0644 "$SRC/deploy/nginx-dropin.conf" /etc/systemd/system/nginx.service.d/fwadmin.conf
systemctl daemon-reload
echo "   drop-in do nginx (espera a rede antes de subir)"

echo "== 8. aposentando o failover antigo =="
if crontab -l 2>/dev/null | grep -q wan-failover; then
    crontab -l 2>/dev/null | grep -v wan-failover | crontab -
    echo "   entrada de crontab removida — quem cuida agora e' o timer"
else
    echo "   nada no crontab"
fi
cp /usr/local/bin/wan-failover.sh /usr/local/bin/wan-failover.sh.pre-fwadmin 2>/dev/null || true

echo "== 9. subindo =="
systemctl enable --now fwadmin.service
# so habilita: a tabela do motor so existe depois do primeiro apply
systemctl enable azimuth-nftables.service
systemctl enable --now fwadmin-failover.timer

# restart, nao reload: o nginx antigo escuta em 0.0.0.0:80 e o novo vhost pede
# 10.0.0.1:80. Um reload nao consegue trocar o socket — ele falha o bind, segue
# rodando a config velha e da a falsa impressao de ter dado certo.
systemctl restart nginx

echo
echo "pronto. abra https://fw.home.lan e crie o usuario administrador."
echo "o /etc do firewall NAO foi alterado: nenhuma config foi aplicada ainda."
echo
echo "adocao de uma caixa que ja estava rodando, na ordem:"
echo "   fwctl inventory   o que o motor possui, e o que roda aqui sem dono"
echo "   fwctl seal        carimba como referencia o que ja bate com o modelo"
echo
echo "O 'seal' recusa todo arquivo que difere do que o motor escreveria, e diz"
echo "qual. Cada recusa e' uma diferenca real entre o /etc desta maquina e o"
echo "config.yaml — resolva-as antes de aplicar qualquer coisa, com 'fwctl diff'."
echo
systemctl --no-pager --lines=0 status fwadmin.service || true
