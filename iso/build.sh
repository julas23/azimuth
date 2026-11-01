#!/bin/bash
# Gera a ISO do Azimuth a partir da netinst oficial do Debian 13, sem root.
#
#   iso/build.sh [--teste] <netinst.iso> <saida.iso>
#
# O que faz:
#   1. baixa, com um apt isolado (sem tocar no apt da maquina), o fechamento de
#      dependencias de iso/pacotes.txt e monta um repositorio em /azimuth/pool;
#   2. copia o agente, o late.sh, o nftables.conf e as chaves SSH autorizadas;
#   3. embute o preseed no initrd (lido antes da primeira pergunta) e poe a
#      entrada "Instalar Azimuth" como padrao nos menus BIOS e UEFI;
#   4. reempacota com xorriso repetindo os registros de boot da original
#      (BIOS isolinux, UEFI grub, MBR hibrido para pendrive).
#
# --teste responde tambem o usuario (operador), a senha (azimuth-teste) e o
# disco (/dev/sda), poe o console na serial e desliga no fim: para instalar
# numa VM sem ninguem olhando.
#
# Precisa de: apt-get, dpkg-scanpackages (dpkg-dev), cpio, gzip e xorriso. Sem
# xorriso instalado, aponte XORRISO para um binario e XORRISO_LIBS para as libs.
#
# A netinst deve ser verificada antes (SHA256SUMS e SHA256SUMS.sign do
# cdimage.debian.org, chave DF9B 9C49 EAA9 2984 3258 9D76 DA87 E80D 6294 BE9B).
set -euo pipefail

TESTE=0
if [ "${1:-}" = "--teste" ]; then TESTE=1; shift; fi
BASE="$(realpath "${1:?uso: build.sh [--teste] <netinst.iso> <saida.iso>}")"
SAIDA="$(realpath -m "${2:?falta a saida}")"

AQUI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$AQUI/.." && pwd)"
W="${WORKDIR:-$(mktemp -d /tmp/azimuth-iso.XXXXXX)}"
mkdir -p "$W"
XORRISO="${XORRISO:-xorriso}"
if [ -n "${XORRISO_LIBS:-}" ]; then export LD_LIBRARY_PATH="$XORRISO_LIBS"; fi
CHAVES="${CHAVES:-$HOME/.ssh/id_rsa.pub}"

echo "== trabalho em $W"

# --- 1. pacotes ---------------------------------------------------------------
A="$W/apt"
mkdir -p "$A"/{etc/apt/sources.list.d,etc/apt/preferences.d,etc/apt/apt.conf.d} \
         "$A"/var/lib/apt/lists/partial "$A"/var/cache/apt/archives/partial "$A"/var/lib/dpkg
: > "$A/var/lib/dpkg/status"
cat > "$A/etc/apt/sources.list.d/debian.sources" <<'EOF'
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
cat > "$W/apt.conf" <<EOF
Dir "$A/";
Dir::State::status "$A/var/lib/dpkg/status";
APT::Architecture "amd64";
APT::Architectures "amd64";
Debug::NoLocking "true";
APT::Sandbox::User "$(id -un)";
APT::Install-Recommends "false";
EOF
PACOTES=$(grep -v '^#' "$AQUI/pacotes.txt" | tr '\n' ' ')
APT_CONFIG="$W/apt.conf" apt-get -q update >/dev/null
APT_CONFIG="$W/apt.conf" apt-get -q -y install --download-only $PACOTES >/dev/null

D="$W/cd/azimuth"
rm -rf "$W/cd"
mkdir -p "$D/pool"
cp "$A"/var/cache/apt/archives/*.deb "$D/pool/"
(cd "$D/pool" && dpkg-scanpackages -m . /dev/null 2>/dev/null > Packages && gzip -9k Packages \
    && apt-ftparchive -o APT::FTPArchive::Release::Origin=Azimuth release . > Release)
echo "== $(ls "$D"/pool/*.deb | wc -l) pacotes, $(du -sh "$D/pool" | cut -f1)"

# --- 2. o que vai junto -------------------------------------------------------
grep -v '^#' "$AQUI/pacotes.txt" | tr -s ' \n' '\n' | grep . > "$D/pacotes.txt"
cp "$AQUI/late.sh" "$AQUI/nftables.conf" "$AQUI/primeiro-boot.sh" "$AQUI/azimuth-primeiro-boot.service" "$D/"
cat $CHAVES > "$D/authorized_keys"
rsync -a --exclude build --exclude __pycache__ --exclude '*.pyc' "$REPO/agent/" "$D/agent/"
(cd "$REPO" && git describe --always --dirty) > "$D/agent/VERSION"
cp "$REPO/STACK.md" "$W/cd/STACK.md"   # o que a imagem empacota e de quem e' cada peca

# --- 3. preseed no initrd e menus ---------------------------------------------
P="$W/preseed"
rm -rf "$P"; mkdir -p "$P"
cp "$AQUI/preseed.cfg" "$P/preseed.cfg"
if [ "$TESTE" = 1 ]; then
    sed -i -e 's|^d-i debian-installer/locale string .*|d-i debian-installer/locale string en_US.UTF-8|' \
           -e 's|^d-i debian-installer/language string .*|d-i debian-installer/language string en|' "$P/preseed.cfg"
    HASH=$(python3 -c 'import crypt; print(crypt.crypt("azimuth-teste", crypt.mksalt(crypt.METHOD_SHA512)))' 2>/dev/null \
           || openssl passwd -6 azimuth-teste)
    cat >> "$P/preseed.cfg" <<EOF

# --- so na ISO de teste ---
d-i passwd/username string operador
d-i passwd/user-password-crypted password $HASH
d-i partman-auto/disk string /dev/sda
d-i grub-installer/bootdev string /dev/sda
d-i debian-installer/exit/poweroff boolean true
EOF
fi

"$XORRISO" -osirrox on -indev "$BASE" \
    -extract /install.amd/initrd.gz "$W/initrd.gz" \
    -extract /isolinux/gtk.cfg "$W/gtk.cfg" \
    -extract /isolinux/spkgtk.cfg "$W/spkgtk.cfg" \
    -extract /boot/grub/grub.cfg "$W/grub.cfg" 2>/dev/null
chmod u+w "$W/initrd.gz" "$W/gtk.cfg" "$W/spkgtk.cfg" "$W/grub.cfg"
# initramfs aceita arquivos cpio concatenados: o preseed entra como um a mais
(cd "$P" && echo preseed.cfg | cpio -o -H newc --quiet | gzip -9) >> "$W/initrd.gz"

# No console serial o d-i so oferece idiomas em ASCII, e pt_BR cai fora: a ISO de
# teste instala em ingles. O sistema instalado fica em pt_BR nas duas (late.sh).
if [ "$TESTE" = 1 ]; then
    CONSOLE="console=ttyS0,115200n8"; LOCALE="en_US.UTF-8"
else
    CONSOLE="vga=788"; LOCALE="pt_BR.UTF-8"
fi
ARGS="auto=true priority=critical locale=$LOCALE keymap=br hostname=azimuth domain=lan $CONSOLE"

cat > "$W/azimuth.cfg" <<EOF
label azimuth
	menu label ^Instalar Azimuth (apaga o disco escolhido)
	menu default
	kernel /install.amd/vmlinuz
	append initrd=/install.amd/initrd.gz $ARGS --- quiet
EOF
# a entrada grafica deixa de ser a padrao; o menu original continua inteiro
sed -i -e '/^default installgui/d' -e '/menu default/d' "$W/gtk.cfg"
# O Debian inicia a instalacao falada quando ninguem escolhe nada (spkgtk.cfg:
# timeout + ontimeout). Aqui, o que comeca sozinho e' o Azimuth; a entrada com
# voz continua no menu.
sed -i -e '/^timeout/d' -e '/^ontimeout/d' -e '/^menu autoboot/d' "$W/spkgtk.cfg"
cat > "$W/isolinux.cfg" <<'EOF'
# D-I config version 2.0, com a entrada do Azimuth como padrao
path
include azimuth.cfg
include menu.cfg
default vesamenu.c32
prompt 0
timeout 50
EOF
echo "ontimeout /install.amd/vmlinuz initrd=/install.amd/initrd.gz $ARGS --- quiet" >> "$W/isolinux.cfg"
echo "menu autoboot Instalando o Azimuth em # segundo{,s}. Qualquer tecla abre o menu." >> "$W/isolinux.cfg"
{
    echo "set default=0"
    echo "set timeout=5"
    echo "menuentry 'Instalar Azimuth (apaga o disco escolhido)' {"
    echo "    set background_color=black"
    echo "    linux    /install.amd/vmlinuz $ARGS --- quiet"
    echo "    initrd   /install.amd/initrd.gz"
    echo "}"
    cat "$W/grub.cfg"
} > "$W/grub-azimuth.cfg"

# --- 4. reempacotar ----------------------------------------------------------------
rm -f "$SAIDA"
"$XORRISO" -indev "$BASE" -outdev "$SAIDA" \
    -volid "AZIMUTH 13.7 amd64" \
    -map "$W/cd/azimuth" /azimuth \
    -map "$W/cd/STACK.md" /STACK.md \
    -map "$W/initrd.gz" /install.amd/initrd.gz \
    -map "$W/azimuth.cfg" /isolinux/azimuth.cfg \
    -map "$W/isolinux.cfg" /isolinux/isolinux.cfg \
    -map "$W/gtk.cfg" /isolinux/gtk.cfg \
    -map "$W/spkgtk.cfg" /isolinux/spkgtk.cfg \
    -map "$W/grub-azimuth.cfg" /boot/grub/grub.cfg \
    -boot_image any replay 2>&1 | grep -E "Writing to|Written to|FAILURE|SORRY" || true
ls -la "$SAIDA"
(cd "$(dirname "$SAIDA")" && sha256sum "$(basename "$SAIDA")" | tee "$(basename "$SAIDA").sha256")
