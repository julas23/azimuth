#!/bin/bash
# Exercita o ciclo completo do fwctl (check -> apply -> rollback) dentro de um
# sysroot descartavel. Nenhum arquivo real do sistema e' tocado: FWADMIN_SYSROOT
# redireciona /etc e /var, e os comandos que mudam o sistema viram no-op.
#
# Rodar no proprio firewall faz os validadores (nft -c, dnsmasq --test, ifquery)
# trabalharem de verdade — que e' o ponto do exercicio.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX="$(mktemp -d /tmp/fwadmin-test.XXXXXX)"
trap 'rm -rf "$SANDBOX"' EXIT

export FWADMIN_SYSROOT="$SANDBOX"
export FWADMIN_CODE="$REPO"
FWCTL="$REPO/sbin/fwctl"

pass=0
fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf '  \033[32mok\033[0m   %s\n' "$1"
        pass=$((pass + 1))
    else
        printf '  \033[31mFALHA\033[0m %s\n       esperado: %s\n       obtido:   %s\n' "$1" "$3" "$2"
        fail=$((fail + 1))
    fi
}

echo "sandbox: $SANDBOX"
echo

# --- estado inicial: o /etc que existe hoje no firewall ---------------------
mkdir -p "$SANDBOX/etc/network" "$SANDBOX/etc/ppp/peers" "$SANDBOX/etc/fwadmin" \
         "$SANDBOX/usr/local/bin" "$SANDBOX/var/lib/fwadmin"
cp "$REPO/legacy/live/interfaces"      "$SANDBOX/etc/network/interfaces"
cp "$REPO/legacy/live/dnsmasq.conf"    "$SANDBOX/etc/dnsmasq.conf"
cp "$REPO/legacy/live/nftables.conf"   "$SANDBOX/etc/nftables.conf"
cp "$REPO/legacy/live/ppp-peers-vivo"  "$SANDBOX/etc/ppp/peers/vivo"
cp "$REPO/config/config.yaml"          "$SANDBOX/etc/fwadmin/config.yaml"

echo "== 1. check com a config ja aplicada =="
"$FWCTL" check > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "validacao passa" "$(grep -c 'FALHOU' "$SANDBOX/out")" "0"
echo

# --- muda a config: um host novo + uma reserva DHCP -------------------------
echo "== 2. apply de uma mudanca (host novo) =="
python3 - "$SANDBOX" <<'PY'
import sys, os
sandbox = sys.argv[1]
os.environ["FWADMIN_SYSROOT"] = sandbox
sys.path.insert(0, os.environ["FWADMIN_CODE"])
from pathlib import Path
from fwadmin.render import load, dump
cfg = load(Path(sandbox) / "etc/fwadmin/config.yaml")
cfg.hosts.append(cfg.hosts[0].model_copy(update={"name": "testehost", "ip": "10.0.0.77", "services": []}))
Path(sandbox, "etc/fwadmin/config.pending.yaml").write_text(dump(cfg))
print("     config.pending.yaml escrita com host 'testehost' -> 10.0.0.77")
PY

"$FWCTL" apply --yes --note "teste automatizado" > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "dnsmasq.conf foi instalado"   "$(grep -c 'testehost' "$SANDBOX/etc/dnsmasq.conf")" "1"
check "config virou a viva"          "$(grep -c 'testehost' "$SANDBOX/etc/fwadmin/config.yaml")" "1"
check "pendente foi consumida"       "$([ -e "$SANDBOX/etc/fwadmin/config.pending.yaml" ] && echo sim || echo nao)" "nao"
check "estado aguarda confirmacao"   "$([ -e "$SANDBOX/var/lib/fwadmin/state.json" ] && echo sim || echo nao)" "sim"
check "nftables NAO foi tocado"      "$(grep -c 'testehost' "$SANDBOX/etc/nftables.conf" || true)" "0"
echo

echo "== 3. status =="
"$FWCTL" status 2>&1 | sed 's/^/     /'
echo

# --- rollback ---------------------------------------------------------------
echo "== 4. rollback (o que o watchdog faria) =="
"$FWCTL" rollback --auto > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "host novo sumiu do dnsmasq"   "$(grep -c 'testehost' "$SANDBOX/etc/dnsmasq.conf" || true)" "0"
check "config viva voltou"           "$(grep -c 'testehost' "$SANDBOX/etc/fwadmin/config.yaml" || true)" "0"
check "estado foi limpo"             "$([ -e "$SANDBOX/var/lib/fwadmin/state.json" ] && echo sim || echo nao)" "nao"
check "dnsmasq identico ao original" "$(cmp -s "$REPO/legacy/live/dnsmasq.conf" "$SANDBOX/etc/dnsmasq.conf" && echo sim || echo nao)" "sim"
echo

# --- config invalida nao pode passar ---------------------------------------
echo "== 5. config invalida e' rejeitada antes de tocar em /etc =="
# aponta o link primario para uma WAN que nao existe: o modelo tem de barrar
sed 's/^  primary: wan_vivo/  primary: wan_inexistente/' \
    "$SANDBOX/etc/fwadmin/config.yaml" > "$SANDBOX/etc/fwadmin/config.pending.yaml"
check "config de teste ficou mesmo invalida" \
      "$(grep -c 'wan_inexistente' "$SANDBOX/etc/fwadmin/config.pending.yaml")" "1"
sum_before="$(md5sum < "$SANDBOX/etc/dnsmasq.conf")"
"$FWCTL" apply --yes > "$SANDBOX/out" 2>&1 && rc=0 || rc=$?
sed 's/^/     /' "$SANDBOX/out"
check "apply falhou"       "$rc" "1"
check "/etc segue intacto" "$(md5sum < "$SANDBOX/etc/dnsmasq.conf")" "$sum_before"
check "erro cita o campo"  "$(grep -c 'wan_inexistente' "$SANDBOX/out")" "1"
rm -f "$SANDBOX/etc/fwadmin/config.pending.yaml"
echo

echo "== 6. wireguard: liga, aplica e revoga um peer =="
python3 - "$SANDBOX" <<'WG1'
import sys, os
sandbox = sys.argv[1]
os.environ["FWADMIN_SYSROOT"] = sandbox
sys.path.insert(0, os.environ["FWADMIN_CODE"])
from pathlib import Path
from fwadmin.render import load, dump
from fwadmin.models import WGPeer

cfg = load(Path(sandbox) / "etc/fwadmin/config.yaml")
cfg.wireguard.enabled = True
cfg.wireguard.address = "10.9.0.1/24"
cfg.wireguard.peers = [
    WGPeer(name="celular",  public_key="A"*42+"A=", allowed_ips=["10.9.0.2/32"], keepalive=25),
    WGPeer(name="revogado", public_key="B"*42+"A=", allowed_ips=["10.9.0.3/32"], enabled=False),
]
Path(sandbox, "etc/fwadmin/config.pending.yaml").write_text(dump(cfg))
print("     wireguard ligado com 1 peer ativo e 1 revogado")
WG1

"$FWCTL" apply --yes --note "wireguard" > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
WGCONF="$SANDBOX/etc/wireguard/wg0.conf"
check "wg0.conf foi criado"          "$([ -e "$WGCONF" ] && echo sim || echo nao)" "sim"
check "validador nativo aprovou"     "$(grep -c 'FALHOU.*wg-quick' "$SANDBOX/out" || true)" "0"
check "peer ativo entrou"            "$(grep -c 'celular' "$WGCONF" || true)" "1"
check "peer revogado ficou de fora"  "$(grep -c 'revogado' "$WGCONF" || true)" "0"
check "chave privada NAO esta no arquivo" "$(grep -c 'PrivateKey' "$WGCONF" || true)" "0"
check "o PostUp carrega a chave"     "$(grep -c 'PostUp = wg set %i private-key' "$WGCONF")" "1"
check "primeira subida recria"       "$(grep -c '\[OK\] WireGuard wg0 (recriar)' "$SANDBOX/out")" "1"
echo

echo "== 7. so mexer em peer nao derruba o tunel =="
"$FWCTL" confirm > /dev/null 2>&1 || true
python3 - "$SANDBOX" <<'WG2'
import sys, os
sandbox = sys.argv[1]
os.environ["FWADMIN_SYSROOT"] = sandbox
sys.path.insert(0, os.environ["FWADMIN_CODE"])
from pathlib import Path
from fwadmin.render import load, dump
from fwadmin.models import WGPeer
cfg = load(Path(sandbox) / "etc/fwadmin/config.yaml")
cfg.wireguard.peers.append(
    WGPeer(name="notebook", public_key="C"*42+"A=", allowed_ips=["10.9.0.4/32"])
)
Path(sandbox, "etc/fwadmin/config.pending.yaml").write_text(dump(cfg))
print("     peer 'notebook' acrescentado")
WG2

"$FWCTL" apply --yes --note "peer novo" > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "recarga foi syncconf"          "$(grep -c '\[OK\] WireGuard wg0 (syncconf)' "$SANDBOX/out")" "1"
check "syncconf nao derruba trafego"  "$(grep -c 'syncconf.*derruba trafego' "$SANDBOX/out" || true)" "0"
check "notebook entrou"               "$(grep -c 'notebook' "$WGCONF")" "1"
check "so o wg0.conf mudou"           "$(grep -c 'arquivos que mudam (1)' "$SANDBOX/out")" "1"
echo

printf '\033[1m%d passaram, %d falharam\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
