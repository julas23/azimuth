#!/bin/bash
# Instala o painel em modo somente leitura num firewall que NAO tem o motor.
#
# E' o caminho para olhar uma maquina de verdade sem mexer nela. Diferente do
# install.sh, este:
#   - nao instala config.yaml nem cria /etc/fwadmin: o painel le o sistema
#     vivo pelo `fwctl observe` e pelo importador;
#   - nao toca no nginx, no crontab nem no wan-failover.sh;
#   - nao instala o timer de failover;
#   - libera no sudoers so o `fwctl observe`.
#
# O que ele escreve, e nada alem disso:
#   /opt/fwadmin/                          codigo
#   /usr/local/sbin/fwctl
#   /var/lib/fwadmin/                      banco de usuarios e certificado
#   /etc/sudoers.d/fwadmin                 so o observe e o login
#   /etc/pam.d/azimuth                     login do painel pela senha do sistema
#   /etc/systemd/system/fwadmin.service    e o drop-in readonly.conf
#   o usuario de sistema netadm
#
# Uso, como root, com o diretorio agent/ do repositorio copiado para a maquina:
#
#   ./deploy/install-readonly.sh              detecta a LAN pelo dnsmasq
#   LAN=ens18 ./deploy/install-readonly.sh    escolhe a placa
#   PORT=9443 ./deploy/install-readonly.sh    outra porta (padrao 8443)
#   ./deploy/install-readonly.sh --remover    desfaz tudo o que esta lista diz
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "rode como root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8443}"
UNIT=/etc/systemd/system/fwadmin.service
DROPIN=/etc/systemd/system/fwadmin.service.d/readonly.conf

# O jail do painel no fail2ban. Validado com 'fail2ban-client -t' antes de
# recarregar; se nao passar, os arquivos anteriores voltam. Sem fail2ban na
# maquina, nao ha o que fazer.
install_f2b() {
    command -v fail2ban-client >/dev/null || return 0
    local filter=/etc/fail2ban/filter.d/azimuth-panel.conf jail=/etc/fail2ban/jail.d/azimuth-panel.conf
    if cmp -s "$SRC/deploy/fail2ban/azimuth-panel-filter.conf" "$filter" \
       && cmp -s "$SRC/deploy/fail2ban/azimuth-panel-jail.conf" "$jail"; then
        return 0
    fi
    for f in "$filter" "$jail"; do [ -e "$f" ] && cp -p "$f" "$f.anterior"; done
    install -m 0644 "$SRC/deploy/fail2ban/azimuth-panel-filter.conf" "$filter"
    install -m 0644 "$SRC/deploy/fail2ban/azimuth-panel-jail.conf" "$jail"
    if fail2ban-client -t >/dev/null 2>&1; then
        rm -f "$filter.anterior" "$jail.anterior"
        fail2ban-client reload >/dev/null && echo "   fail2ban: jail azimuth-panel atualizado"
    else
        for f in "$filter" "$jail"; do
            if [ -e "$f.anterior" ]; then mv "$f.anterior" "$f"; else rm -f "$f"; fi
        done
        echo "   fail2ban: config nova invalida — mantida a anterior"
    fi
}

# O login do painel e' o usuario do sistema, conferido pelo PAM (fwctl login).
install_pam() {
    cmp -s "$SRC/deploy/pam-azimuth" /etc/pam.d/azimuth && return 0
    install -m 0644 "$SRC/deploy/pam-azimuth" /etc/pam.d/azimuth
    echo "   PAM: /etc/pam.d/azimuth (login do painel pela senha do sistema)"
}

# Os agentes no navegador (AGENTES.md): o script que abre a sessao, a unidade
# do systemd e a limpeza de 30 dias do registro. Instala so o que mudou.
install_agentes() {
    local mudou=0
    if ! cmp -s "$SRC/sbin/azimuth-agente-sessao" /usr/local/sbin/azimuth-agente-sessao; then
        install -m 0755 "$SRC/sbin/azimuth-agente-sessao" /usr/local/sbin/azimuth-agente-sessao; mudou=1
    fi
    if ! cmp -s "$SRC/sbin/azimuth" /usr/local/bin/azimuth; then
        install -m 0755 "$SRC/sbin/azimuth" /usr/local/bin/azimuth; mudou=1
    fi
    if ! cmp -s "$SRC/deploy/azimuth-agente@.service" /etc/systemd/system/azimuth-agente@.service; then
        install -m 0644 "$SRC/deploy/azimuth-agente@.service" /etc/systemd/system/azimuth-agente@.service
        systemctl daemon-reload; mudou=1
    fi
    if ! cmp -s "$SRC/deploy/azimuth-agente.tmpfiles" /etc/tmpfiles.d/azimuth-agente.conf; then
        install -m 0644 "$SRC/deploy/azimuth-agente.tmpfiles" /etc/tmpfiles.d/azimuth-agente.conf
        systemd-tmpfiles --create /etc/tmpfiles.d/azimuth-agente.conf; mudou=1
    fi
    [ "$mudou" = 1 ] && echo "   agentes no navegador: sessao, unidade e registro atualizados"
    return 0
}

# Maquina adotada (adopt.sh): so o codigo e' atualizado. Sudoers, drop-in e
# config sao do motor; reescreve-los aqui voltaria o painel ao somente leitura.
if [ -e /etc/fwadmin/config.yaml ] && grep -q '^Environment=FWADMIN_READONLY=0' "$DROPIN" 2>/dev/null; then
    [ "${1:-}" = "--remover" ] && { echo "maquina adotada: use deploy/adopt.sh --desfazer antes"; exit 1; }
    echo "== maquina adotada: atualizando so o codigo =="
    rm -rf /opt/fwadmin/fwadmin
    cp -r "$SRC/fwadmin" /opt/fwadmin/
    find /opt/fwadmin -name __pycache__ -prune -exec rm -rf {} +
    install -m 0755 "$SRC/sbin/fwctl" /usr/local/sbin/fwctl
    # O sudoers do motor acompanha o fwctl: subcomando novo sem a linha dele
    # no sudoers e' botao que da erro de permissao. Validado antes de valer, e
    # o anterior volta se o novo nao passar no visudo.
    if ! cmp -s "$SRC/deploy/sudoers-fwadmin" /etc/sudoers.d/fwadmin; then
        cp -p /etc/sudoers.d/fwadmin /etc/sudoers.d/.fwadmin.anterior
        install -m 0440 "$SRC/deploy/sudoers-fwadmin" /etc/sudoers.d/fwadmin
        if visudo -c -q; then
            rm -f /etc/sudoers.d/.fwadmin.anterior
            echo "   sudoers atualizado"
        else
            mv /etc/sudoers.d/.fwadmin.anterior /etc/sudoers.d/fwadmin
            echo "   sudoers novo invalido — mantido o anterior"
        fi
    fi
    install_pam
    install_f2b
    install_agentes
    VERSION="$(git -C "$SRC" describe --always --dirty 2>/dev/null || cat "$SRC/VERSION" 2>/dev/null || echo dev)"
    echo "$VERSION" > /opt/fwadmin/VERSION
    echo "   versao $VERSION"
    systemctl restart fwadmin.service
    systemctl --no-pager --lines=0 status fwadmin.service | grep -E "Active:" || true
    exit 0
fi

# O motor completo do install.sh usa os mesmos caminhos. Instalar ou remover
# por cima dele trocaria o sudoers por um que nao aplica nada, ou apagaria o
# banco.
if [ -e /etc/fwadmin/config.yaml ]; then
    echo "esta maquina tem o motor completo (/etc/fwadmin/config.yaml); este instalador e' para quem nao tem"
    exit 1
fi

if [ "${1:-}" = "--remover" ]; then
    echo "== removendo o painel somente leitura =="
    systemctl disable --now fwadmin.service 2>/dev/null || true
    rm -f "$DROPIN" "$UNIT" /etc/sudoers.d/fwadmin /usr/local/sbin/fwctl /etc/pam.d/azimuth
    rmdir /etc/systemd/system/fwadmin.service.d 2>/dev/null || true
    systemctl daemon-reload
    rm -rf /opt/fwadmin /var/lib/fwadmin /run/fwadmin
    if id netadm >/dev/null 2>&1; then userdel netadm; fi
    echo "   removido. nada fora da lista do cabecalho foi tocado."
    exit 0
fi

echo "== 1. dependencias =="
missing=()
for mod in fastapi:python3-fastapi uvicorn:python3-uvicorn jinja2:python3-jinja2 \
           pydantic:python3-pydantic yaml:python3-yaml; do
    python3 -c "import ${mod%%:*}" 2>/dev/null || missing+=("${mod#*:}")
done
command -v sudo    >/dev/null || missing+=(sudo)
command -v openssl >/dev/null || missing+=(openssl)
if [ ${#missing[@]} -gt 0 ]; then
    echo "   faltam pacotes. Instale e rode de novo:"
    echo "   apt install ${missing[*]}"
    exit 1
fi
python3 -c 'import pydantic, sys; sys.exit(0 if pydantic.VERSION.startswith("2") else 1)' \
    || { echo "   o modelo exige pydantic 2"; exit 1; }
echo "   ok"

echo "== 2. onde o painel vai atender =="
if [ -z "${LAN:-}" ]; then
    LAN="$(sed -n 's/^interface=\([^ ,#]*\).*/\1/p' /etc/dnsmasq.conf 2>/dev/null | head -1)"
fi
[ -n "$LAN" ] || { echo "   nao achei a placa da LAN; rode com LAN=<placa>"; exit 1; }
CIDR="$(ip -4 -o addr show dev "$LAN" 2>/dev/null | awk '{print $4; exit}')"
[ -n "$CIDR" ] || { echo "   a placa $LAN nao tem IPv4"; exit 1; }
LAN_IP="${CIDR%/*}"
LAN_NET="$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$CIDR")"
# Numa reinstalacao quem ocupa a porta e' o proprio painel; ai segue.
ours=no
if systemctl is-active --quiet fwadmin.service && grep -q -- "--port $PORT " "$DROPIN" 2>/dev/null; then
    ours=yes
fi
if [ "$ours" = no ] && ss -Hltn "sport = :$PORT" | grep -q .; then
    echo "   a porta $PORT ja esta em uso; rode com PORT=<outra>"
    exit 1
fi
echo "   https://$LAN_IP:$PORT, aceitando so $LAN_NET (placa $LAN)"

echo "== 3. usuario de servico =="
if ! id netadm >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/fwadmin --no-create-home --shell /usr/sbin/nologin netadm
    echo "   netadm criado"
else
    echo "   netadm ja existe"
fi
# A tela de diagnostico le o journal dos servicos.
usermod -aG systemd-journal netadm

echo "== 4. codigo =="
install -d -m 0755 /opt/fwadmin
rm -rf /opt/fwadmin/fwadmin
cp -r "$SRC/fwadmin" /opt/fwadmin/
find /opt/fwadmin -name __pycache__ -prune -exec rm -rf {} +
install -m 0755 "$SRC/sbin/fwctl" /usr/local/sbin/fwctl
VERSION="$(git -C "$SRC" describe --always --dirty 2>/dev/null || cat "$SRC/VERSION" 2>/dev/null || echo dev)"
echo "$VERSION" > /opt/fwadmin/VERSION
echo "   versao $VERSION"

echo "== 5. estado e certificado =="
install -d -m 0750 -o netadm -g netadm /var/lib/fwadmin
install -d -m 0700 -o netadm -g netadm /var/lib/fwadmin/tls
if [ ! -e /var/lib/fwadmin/tls/fwadmin.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /var/lib/fwadmin/tls/fwadmin.key \
        -out    /var/lib/fwadmin/tls/fwadmin.crt \
        -subj "/CN=$(hostname)" \
        -addext "subjectAltName=DNS:$(hostname),IP:$LAN_IP" 2>/dev/null
    chmod 0600 /var/lib/fwadmin/tls/fwadmin.key
    chown -R netadm:netadm /var/lib/fwadmin/tls
    echo "   self-signed gerado"
else
    echo "   certificado ja existe — preservado"
fi

echo "== 6. sudoers =="
install -m 0440 "$SRC/deploy/sudoers-fwadmin-readonly" /etc/sudoers.d/fwadmin
visudo -c -q || { rm -f /etc/sudoers.d/fwadmin; echo "   sudoers invalido — removido"; exit 1; }
echo "   so o fwctl observe e o login"
install_pam

echo "== 7. systemd =="
install -m 0644 "$SRC/deploy/fwadmin.service" "$UNIT"
install -d -m 0755 "$(dirname "$DROPIN")"
sed -e "s|@LAN_IP@|$LAN_IP|" -e "s|@LAN_NET@|$LAN_NET|" -e "s|@PORT@|$PORT|" \
    "$SRC/deploy/fwadmin-readonly.conf" > "$DROPIN"
chmod 0644 "$DROPIN"
systemctl daemon-reload
systemctl enable fwadmin.service >/dev/null 2>&1
systemctl restart fwadmin.service
echo "   fwadmin.service com o drop-in readonly.conf"

echo "== 8. primeira fotografia =="
# Feita aqui, como root, para o painel abrir ja com dados. Depois ele mesmo
# pede outra ao fwctl, via sudo, quando a fotografia passa de 20 s.
/usr/local/sbin/fwctl observe || echo "   o observe falhou; o painel vai mostrar o motivo na tela"

echo
echo "pronto: https://$LAN_IP:$PORT — entra quem esta no grupo sudo, com a senha do sistema (root nao)."
echo "nenhum arquivo de configuracao do firewall foi alterado."
echo
systemctl --no-pager --lines=5 status fwadmin.service || true
