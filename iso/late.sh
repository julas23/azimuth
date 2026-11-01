#!/bin/sh
# Pos-instalacao do Azimuth, chamado pelo preseed (late_command).
#
# Roda no ambiente do debian-installer (busybox), com o sistema novo montado em
# /target. Instala os pacotes do repositorio da ISO, sem internet, e deixa a
# caixa num estado seguro para o primeiro boot: firewall de entrada fechado,
# e os servicos que o motor ainda vai configurar, desligados.
set -e

CD=/cdrom/azimuth
T=/target
LOG=$T/var/log/azimuth-instalacao.log

# So comandos do busybox do instalador: nao ha tee nem install aqui.
log() { echo "azimuth: $*"; echo "azimuth: $*" >> "$LOG"; }

mkdir -p "$T/var/log"
log "inicio $(date)"

# --- pacotes, do repositorio da ISO -----------------------------------------
mkdir -p "$T/var/lib/azimuth-iso"
cp -a "$CD/pool" "$T/var/lib/azimuth-iso/"
echo "deb [trusted=yes] file:/var/lib/azimuth-iso/pool ./" > "$T/etc/apt/sources.list.d/azimuth-iso.list"

PACOTES=$(grep -v '^#' "$CD/pacotes.txt" | tr '\n' ' ')

# Servico que o pacote liga ao instalar, e que o motor ainda nao configurou,
# nao pode subir agora: sobe com config padrao, numa caixa sem firewall.
# policy-rc.d segura todos durante a instalacao; depois cada um e' decidido.
cat > "$T/usr/sbin/policy-rc.d" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 755 "$T/usr/sbin/policy-rc.d"

# So o repositorio da ISO: o sources.list do sistema novo tem as entradas
# 'cdrom:' do instalador, e o CD nao esta montado dentro do /target — o
# apt-get update reprovaria por elas. A saida do in-target vai para o syslog
# do instalador (/var/log/installer/syslog no sistema instalado).
SO_ISO="-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/azimuth-iso.list -o Dir::Etc::sourceparts=-"
in-target apt-get $SO_ISO update
in-target env DEBIAN_FRONTEND=noninteractive apt-get $SO_ISO install -y --no-install-recommends \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $PACOTES
rm -f "$T/usr/sbin/policy-rc.d"
log "pacotes instalados"

# --- o que fica desligado ate o motor configurar ------------------------------
# dnsmasq: com a config padrao seria um resolvedor aberto em toda placa.
# unbound: briga com o dnsmasq pela porta 53.
# Samba: o nmbd anuncia NetBIOS na rede. NFS: nada a exportar ainda.
# Docker: subiria escrevendo regras no firewall (o motor o tira dele).
# rpcbind: o NFS daqui e' so v4, que nao precisa dele (STORAGE.md).
# nginx: o vhost do painel e' do instalador do agente.
for u in dnsmasq unbound smbd nmbd samba-ad-dc nfs-server docker.service docker.socket \
         containerd nginx inadyn; do
    in-target systemctl disable "$u" >>"$LOG" 2>&1 || true
done
# mask, e nao disable: as unidades do NFS puxam o socket do rpcbind por Wants.
# Um Wants para unidade mascarada nao impede o nfs-server (v4) de subir.
in-target systemctl mask rpcbind.service rpcbind.socket >>"$LOG" 2>&1 || true
log "servicos do motor desligados ate a configuracao"

# Se o Docker subir antes do motor, que suba sem tocar no firewall: o mesmo
# daemon.json que o motor gera (services/docker.py), sem o pool.
mkdir -p "$T/etc/docker"
cat > "$T/etc/docker/daemon.json" <<'EOF'
{
  "iptables": false,
  "ip6tables": false,
  "log-driver": "journald"
}
EOF

# --- firewall de entrada fechado desde o primeiro boot --------------------------
cp "$CD/nftables.conf" "$T/etc/nftables.conf"
in-target systemctl enable nftables.service >>"$LOG" 2>&1
log "nftables ligado com entrada fechada (SSH, painel e DHCP cliente)"

# --- o usuario do instalador ---------------------------------------------------
# O nome foi perguntado na instalacao: e' o primeiro usuario comum do passwd.
U=$(awk -F: '$3 >= 1000 && $3 < 60000 { print $1; exit }' "$T/etc/passwd")
[ -n "$U" ] || { log "nenhum usuario criado pelo instalador"; exit 1; }

# sudo sem senha: o painel e o console usam o mesmo usuario, e root nao tem
# senha. Validado com visudo antes de valer; invalido, sai e o grupo sudo
# continua pedindo a senha dele.
echo "$U ALL=(ALL:ALL) NOPASSWD: ALL" > "$T/etc/sudoers.d/azimuth-admin"
chmod 440 "$T/etc/sudoers.d/azimuth-admin"
if in-target visudo -cf /etc/sudoers.d/azimuth-admin >>"$LOG" 2>&1; then
    log "sudo sem senha para $U"
else
    rm -f "$T/etc/sudoers.d/azimuth-admin"
    log "sudoers invalido para $U: removido (sudo continua pedindo senha)"
fi

if [ -f "$CD/authorized_keys" ]; then
    H=$(awk -F: -v u="$U" '$1 == u { print $6 }' "$T/etc/passwd")
    mkdir -p "$T$H/.ssh"
    chmod 700 "$T$H/.ssh"
    cp "$CD/authorized_keys" "$T$H/.ssh/authorized_keys"
    chmod 600 "$T$H/.ssh/authorized_keys"
    in-target chown -R "$U:$U" "$H/.ssh"
    log "chave SSH autorizada para $U"
fi

# --- o codigo do agente e o painel ---------------------------------------------
# O painel nao se instala aqui: dentro do instalador nao ha systemd rodando,
# e o endereco da LAN e' o do primeiro boot. Quem instala e' a
# azimuth-primeiro-boot.service, uma vez so, com o deploy/install-readonly.sh.
cp -a "$CD/agent" "$T/opt/azimuth-agent"
cp "$CD/primeiro-boot.sh" "$T/usr/local/sbin/azimuth-primeiro-boot"
chmod 755 "$T/usr/local/sbin/azimuth-primeiro-boot"
cp "$CD/azimuth-primeiro-boot.service" "$T/etc/systemd/system/"
in-target systemctl enable azimuth-primeiro-boot.service >>"$LOG" 2>&1
log "codigo do agente em /opt/azimuth-agent ($(cat "$CD/agent/VERSION" 2>/dev/null || echo sem versao)); painel no primeiro boot"

# --- apt para depois: deb.debian.org -----------------------------------------------
rm -f "$T/etc/apt/sources.list.d/azimuth-iso.list"
sed -i '/^deb cdrom:/d' "$T/etc/apt/sources.list" 2>/dev/null || true
cat > "$T/etc/apt/sources.list.d/debian.sources" <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
# O repositorio da ISO fica no disco (uns 200 MB) ate o primeiro apt update de
# verdade; serve para reinstalar um pacote sem internet.

# --- idioma do sistema: pt_BR, seja qual for o do instalador ----------------------
sed -i 's/^# *pt_BR.UTF-8 UTF-8/pt_BR.UTF-8 UTF-8/; s/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' "$T/etc/locale.gen"
in-target locale-gen >>"$LOG" 2>&1 || true
in-target update-locale LANG=pt_BR.UTF-8 >>"$LOG" 2>&1 || true

# --- a tela do console ---------------------------------------------------------------
cat > "$T/etc/issue" <<EOF
Azimuth (Debian 13) \\n

  Painel:   https://\\4:8443  (usuario $U, a senha da instalacao)
  SSH:      ssh $U@\\4

EOF
log "fim $(date)"
