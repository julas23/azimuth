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
# O apply recusa PPPoE sem senha, e a do legacy/live nao vem no peer.
python3 -c 'import sys, yaml; cfg = yaml.safe_load(open(sys.argv[1]))
refs = [i["pppoe"]["password_ref"] for i in cfg["interfaces"] if (i.get("pppoe") or {}).get("password_ref")]
print(yaml.safe_dump({r: "senha-de-teste" for r in refs}), end="")' \
    "$SANDBOX/etc/fwadmin/config.yaml" > "$SANDBOX/etc/fwadmin/secrets.yaml"

echo "== 1. check com a config ja aplicada =="
"$FWCTL" check > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "validacao passa" "$(grep -c 'FALHOU' "$SANDBOX/out")" "0"
echo

# --- muda a config: um host novo + uma reserva DHCP -------------------------
echo "== 1b. a adocao trava ate as mudancas serem marcadas =="
"$FWCTL" apply --yes > "$SANDBOX/out" 2>&1 && rc=0 || rc=$?
check "apply de adocao recusado"        "$rc" "1"
check "e diz o que falta marcar"        "$(grep -c 'nao marcadas como intencionais' "$SANDBOX/out")" "1"
ids="$("$FWCTL" ack | awk '$1 == "pendente" {print $2}')"
check "fwctl ack lista a pendente"      "$([ -n "$ids" ] && echo sim || echo nao)" "sim"
"$FWCTL" ack $ids > /dev/null
check "depois de marcar, nada pendente" "$("$FWCTL" ack | grep -c 'nenhuma mudanca pendente')" "1"
check "id falso nao marca nada"         "$("$FWCTL" ack 000000000000 | grep -c 'nao e. uma mudanca pendente')" "1"
echo

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
check "nftables.conf do administrador NAO foi tocado"      "$(grep -c 'testehost' "$SANDBOX/etc/nftables.conf" || true)" "0"
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

echo "== 8. posse: selo, divergencia e o portao do apply =="
"$FWCTL" confirm > /dev/null 2>&1 || true

# O selo do confirm ja deve ter carimbado tudo que o motor escreveria.
"$FWCTL" inventory > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "nada divergente logo apos o confirm" \
      "$(grep -c 'editado a mao' "$SANDBOX/out" || true)" "0"
check "selo cobre os arquivos do motor" \
      "$(grep -c 'sem selo' "$SANDBOX/out" || true)" "0"

# Alguem edita /etc a mao — o caso que o selo existe para pegar.
echo "# editado a mao as 23h" >> "$SANDBOX/etc/dnsmasq.conf"
"$FWCTL" inventory > "$SANDBOX/out" 2>&1 || true
check "a edicao a mao e' detectada" \
      "$(grep -c 'editado a mao' "$SANDBOX/out")" "1"

# E um apply que passaria por cima dela e' barrado antes de tocar em /etc.
python3 - "$SANDBOX" <<'DRIFT'
import sys, os
sandbox = sys.argv[1]
os.environ["FWADMIN_SYSROOT"] = sandbox
sys.path.insert(0, os.environ["FWADMIN_CODE"])
from pathlib import Path
from fwadmin.render import load, dump
cfg = load(Path(sandbox) / "etc/fwadmin/config.yaml")
cfg.hosts.append(cfg.hosts[0].model_copy(update={"name": "outrohost", "ip": "10.0.0.78", "services": []}))
Path(sandbox, "etc/fwadmin/config.pending.yaml").write_text(dump(cfg))
print("     config.pending.yaml com host 'outrohost'")
DRIFT

sum_before="$(md5sum < "$SANDBOX/etc/dnsmasq.conf")"
"$FWCTL" apply --yes > "$SANDBOX/out" 2>&1 && rc=0 || rc=$?
sed 's/^/     /' "$SANDBOX/out"
check "apply barrado pela divergencia" "$rc" "1"
check "/etc segue intacto"             "$(md5sum < "$SANDBOX/etc/dnsmasq.conf")" "$sum_before"
check "a edicao a mao continua la"     "$(grep -c 'editado a mao as 23h' "$SANDBOX/etc/dnsmasq.conf")" "1"

# Com o descarte explicito ele passa — e guarda copia do que apagou.
"$FWCTL" apply --yes --discard-drift > "$SANDBOX/out" 2>&1 || true
sed 's/^/     /' "$SANDBOX/out"
check "apply passa com --discard-drift" "$(grep -c 'copia guardada em' "$SANDBOX/out")" "1"
check "a edicao a mao foi sobrescrita"  "$(grep -c 'editado a mao as 23h' "$SANDBOX/etc/dnsmasq.conf" || true)" "0"
check "a mudanca do modelo entrou"      "$(grep -c 'outrohost' "$SANDBOX/etc/dnsmasq.conf")" "1"
check "copia do descartado existe"      "$(cat "$SANDBOX"/var/lib/fwadmin/drift/*/dnsmasq.conf 2>/dev/null | grep -c 'editado a mao as 23h')" "1"
echo

echo "== 8b. edicao a mao que ja foi levada ao modelo nao barra =="
"$FWCTL" confirm > /dev/null 2>&1 || true

# O caso de 29/10: alguem poe um registro direto no dnsmasq.conf, depois
# leva o mesmo registro para o config.yaml junto com mais um. O arquivo novo
# contem a edicao, entao nao ha o que proteger.
python3 - "$SANDBOX" <<'ABSORB'
import sys, os
sandbox = sys.argv[1]
os.environ["FWADMIN_SYSROOT"] = sandbox
sys.path.insert(0, os.environ["FWADMIN_CODE"])
from pathlib import Path
from fwadmin.render import load, dump, render_all
cfg = load(Path(sandbox) / "etc/fwadmin/config.yaml")
base = render_all(cfg)["dnsmasq.conf"].splitlines()
novo = lambda n, ip: cfg.hosts[0].model_copy(update={"name": n, "ip": ip, "services": []})
cfg.hosts.append(novo("feitoamao", "10.0.0.81"))
linha = [l for l in render_all(cfg)["dnsmasq.conf"].splitlines() if l not in base]
assert len(linha) == 1, linha
with open(Path(sandbox) / "etc/dnsmasq.conf", "a") as fh:
    fh.write(linha[0] + "\n")
cfg.hosts.append(novo("maisum", "10.0.0.82"))
Path(sandbox, "etc/fwadmin/config.pending.yaml").write_text(dump(cfg))
print(f"     a mao: {linha[0]}; pendente: feitoamao + maisum")
ABSORB

"$FWCTL" apply --yes > "$SANDBOX/out" 2>&1 && rc=0 || rc=$?
sed 's/^/     /' "$SANDBOX/out"
check "apply passa sem --discard-drift"  "$rc" "0"
check "e diz que a edicao esta no modelo" "$(grep -c 'ja contida no modelo' "$SANDBOX/out")" "1"
check "o registro feito a mao continua"  "$(grep -c 'feitoamao' "$SANDBOX/etc/dnsmasq.conf")" "1"
check "e o novo entrou"                  "$(grep -c 'maisum' "$SANDBOX/etc/dnsmasq.conf")" "1"
check "o historico nao fala em descarte" "$(grep -c 'descartou' "$SANDBOX/out" || true)" "0"
"$FWCTL" confirm > /dev/null 2>&1 || true

# Mas se o modelo nao trouxer a edicao, continua barrando.
echo "address=/so-na-mao.home.lan/10.0.0.83" >> "$SANDBOX/etc/dnsmasq.conf"
python3 - "$SANDBOX" <<'NOTABSORB'
import sys, os
sandbox = sys.argv[1]
os.environ["FWADMIN_SYSROOT"] = sandbox
sys.path.insert(0, os.environ["FWADMIN_CODE"])
from pathlib import Path
from fwadmin.render import load, dump
cfg = load(Path(sandbox) / "etc/fwadmin/config.yaml")
cfg.hosts.append(cfg.hosts[0].model_copy(update={"name": "outromais", "ip": "10.0.0.84", "services": []}))
Path(sandbox, "etc/fwadmin/config.pending.yaml").write_text(dump(cfg))
NOTABSORB
"$FWCTL" apply --yes > "$SANDBOX/out" 2>&1 && rc=0 || rc=$?
check "edicao fora do modelo segue barrando" "$rc" "1"
"$FWCTL" apply --yes --discard-drift > /dev/null 2>&1 || true
echo

echo "== 9. o selo nunca afirma o que nao viu =="
"$FWCTL" confirm > /dev/null 2>&1 || true
mkdir -p "$SANDBOX/etc/nftables.d"
echo "# outra edicao a mao" >> "$SANDBOX/etc/nftables.d/azimuth.nft"
"$FWCTL" seal > "$SANDBOX/out" 2>&1 && rc=0 || rc=$?
sed 's/^/     /' "$SANDBOX/out"
check "seal recusa o arquivo divergente" "$rc" "1"
check "e diz qual foi"                   "$(grep -c 'nao selado azimuth.nft' "$SANDBOX/out")" "1"
check "os outros seguem selados"         "$(grep -c 'selado dnsmasq.conf' "$SANDBOX/out")" "1"
echo

printf '\033[1m%d passaram, %d falharam\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
