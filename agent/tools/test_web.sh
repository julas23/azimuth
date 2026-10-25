#!/bin/bash
# Sobe o app num sysroot descartavel, cria o usuario inicial e percorre todas
# as telas. Verifica tambem que uma edicao invalida e' recusada e que a
# proposta so aparece depois de uma edicao valida.
#
# Depois sobe de novo em modo somente leitura, sobre um /etc sintetico, e
# verifica que o painel le o sistema vivo, que nenhum POST de escrita passa e
# que nenhum segredo chega a fotografia.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX="$(mktemp -d /tmp/fwadmin-web.XXXXXX)"
PORT="${PORT:-8899}"
JAR="$SANDBOX/cookies"

cleanup() {
    [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null
    wait "${APP_PID:-}" 2>/dev/null
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

export FWADMIN_SYSROOT="$SANDBOX"
export FWADMIN_CODE="$REPO"
export PYTHONPATH="$REPO"
export FWADMIN_READONLY=0

pass=0; fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1))
    else
        printf '  \033[31mFALHA\033[0m %s\n       esperado: %s / obtido: %s\n' "$1" "$3" "$2"; fail=$((fail+1))
    fi
}
code() { curl -s -o "$SANDBOX/body" -w '%{http_code}' -b "$JAR" -c "$JAR" "$@"; }

mkdir -p "$SANDBOX/etc/fwadmin" "$SANDBOX/var/lib/fwadmin"
cp "$REPO/config/config.yaml" "$SANDBOX/etc/fwadmin/config.yaml"

echo "sandbox: $SANDBOX · porta $PORT"
python3 -m uvicorn fwadmin.web:app --host 127.0.0.1 --port "$PORT" --log-level warning &
APP_PID=$!

for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$PORT/login" >/dev/null 2>&1 && break
    sleep 0.2
done
echo

echo "== autenticacao =="
check "sem sessao redireciona"  "$(code "http://127.0.0.1:$PORT/")" "303"
code "http://127.0.0.1:$PORT/login" >/dev/null
check "tela de setup aparece"   "$(grep -qi 'primeiro acesso' "$SANDBOX/body" && echo sim || echo nao)" "sim"
code -X POST -d 'username=admin&password=curta' "http://127.0.0.1:$PORT/login" >/dev/null
check "senha curta e' recusada" "$(grep -qi '10 caracteres' "$SANDBOX/body" && echo sim || echo nao)" "sim"
check "cria usuario e entra"    "$(code -X POST -d 'username=admin&password=senha-bem-longa-123' "http://127.0.0.1:$PORT/login")" "303"
check "agora o painel abre"     "$(code "http://127.0.0.1:$PORT/")" "200"
echo

echo "== telas =="
TELAS="/ /services /network /firewall /fail2ban /dhcp /domain /dns /vpn /system"
for rota in $TELAS; do
    check "GET $rota" "$(code "http://127.0.0.1:$PORT$rota")" "200"
done
echo

echo "== nenhuma proposta ainda =="
check "config.pending nao existe" "$([ -e "$SANDBOX/etc/fwadmin/config.pending.yaml" ] && echo sim || echo nao)" "nao"
echo

echo "== edicao valida vira proposta =="
code -X POST -d 'name=nas&ip=10.0.0.60&group=&description=servidor de arquivos' \
     "http://127.0.0.1:$PORT/dns/host" >/dev/null
check "proposta foi criada"  "$([ -e "$SANDBOX/etc/fwadmin/config.pending.yaml" ] && echo sim || echo nao)" "sim"
check "host esta na proposta" "$(grep -c 'name: nas' "$SANDBOX/etc/fwadmin/config.pending.yaml")" "1"
check "config viva intocada"  "$(grep -c 'name: nas' "$SANDBOX/etc/fwadmin/config.yaml" || true)" "0"
code "http://127.0.0.1:$PORT/" >/dev/null
check "aviso aparece na UI"   "$(grep -qi 'aguardando aplicação' "$SANDBOX/body" && echo sim || echo nao)" "sim"
echo

echo "== edicao invalida e' recusada =="
code -X POST -d 'mac=nao-e-um-mac&ip=10.0.0.61&name=teste' \
     "http://127.0.0.1:$PORT/dns/reservation" >/dev/null
check "erro volta com 303"   "$(code -o /dev/null -X POST -d 'mac=zz&ip=1.2.3.4&name=x' "http://127.0.0.1:$PORT/dns/reservation")" "303"
check "MAC invalido nao entrou" "$(grep -c 'nao-e-um-mac' "$SANDBOX/etc/fwadmin/config.pending.yaml" || true)" "0"

code -X POST -d 'primary=wan_que_nao_existe&backup=&enabled=1' \
     "http://127.0.0.1:$PORT/routing" >/dev/null
check "WAN inexistente barrada" "$(grep -c 'wan_que_nao_existe' "$SANDBOX/etc/fwadmin/config.pending.yaml" || true)" "0"

code -X POST -d 'action=accept&source=lan&destination=wan&proto=tcp&dest_ports=99999&description=x' \
     "http://127.0.0.1:$PORT/firewall/rule/input" >/dev/null
check "porta fora da faixa barrada" "$(grep -c '99999' "$SANDBOX/etc/fwadmin/config.pending.yaml" || true)" "0"

code -X POST -d 'action=accept&source=lan&destination=wan&proto=tcp&dest_ports=22' \
     "http://127.0.0.1:$PORT/firewall/rule/naoexiste" >/dev/null
check "cadeia invalida barrada" "$(grep -c 'naoexiste' "$SANDBOX/etc/fwadmin/config.pending.yaml" || true)" "0"
echo

echo "== diagnostico =="
check "POST /system/diag rotas"      "$(code -X POST -d 'tool=routes' "http://127.0.0.1:$PORT/system/diag")" "200"
code -X POST -d 'tool=ping&target=127.0.0.1' "http://127.0.0.1:$PORT/system/diag" >/dev/null
check "ping local responde"   "$(grep -qi 'ping' "$SANDBOX/body" && echo sim || echo nao)" "sim"
code -X POST -d 'tool=ping&target=;rm -rf /' "http://127.0.0.1:$PORT/system/diag" >/dev/null
check "alvo com shell barrado" "$(grep -qi 'alvo inv' "$SANDBOX/body" && echo sim || echo nao)" "sim"
code -X POST -d 'tool=ping&target=--flag-injetada' "http://127.0.0.1:$PORT/system/diag" >/dev/null
check "alvo com flag barrado"  "$(grep -qi 'alvo inv' "$SANDBOX/body" && echo sim || echo nao)" "sim"
echo

echo "== descartar proposta =="
code -X POST "http://127.0.0.1:$PORT/system/discard" >/dev/null
check "proposta sumiu" "$([ -e "$SANDBOX/etc/fwadmin/config.pending.yaml" ] && echo sim || echo nao)" "nao"
echo

echo "== logout =="
check "logout redireciona"    "$(code -X POST "http://127.0.0.1:$PORT/logout")" "303"
check "painel bloqueia de novo" "$(code "http://127.0.0.1:$PORT/")" "303"
echo

echo "== somente leitura, sobre um /etc sintetico =="
kill "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null
rm -rf "$SANDBOX/etc" "$SANDBOX/run" "$JAR"
mkdir -p "$SANDBOX/etc"
# O /etc vem do mesmo firewall sintetico do teste do importador, com uma chave
# privada e uma senha de mentira para provar que elas nao chegam a fotografia.
python3 - "$REPO/tools/test_import_live.py" "$SANDBOX/etc" <<'EOF'
import sys
from pathlib import Path
source, etc = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(source.parent))
namespace = {"__name__": "fixture", "__file__": str(source)}
exec(source.read_text().split("with tempfile.TemporaryDirectory")[0], namespace)
where = {"interfaces": "network/interfaces", "ppp-peers-vivo": "ppp/peers/vivo"}
for name, text in namespace["LIVE"].items():
    target = etc / where.get(name, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    if name == "wireguard/wg0.conf":
        text = text.replace("[Interface]\n", "[Interface]\nPrivateKey = CHAVE-PRIVADA-DE-MENTIRA=\n", 1)
    target.write_text(text)
EOF

export FWADMIN_READONLY=1
python3 -m uvicorn fwadmin.web:app --host 127.0.0.1 --port "$PORT" --log-level warning &
APP_PID=$!
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$PORT/login" >/dev/null 2>&1 && break
    sleep 0.2
done
check "login vale no somente leitura" "$(code -X POST -d 'username=admin&password=senha-bem-longa-123' "http://127.0.0.1:$PORT/login")" "303"
for rota in $TELAS; do
    check "GET $rota" "$(code "http://127.0.0.1:$PORT$rota")" "200"
done
code "http://127.0.0.1:$PORT/dhcp" >/dev/null
check "DHCP lido do dnsmasq vivo" "$(grep -c '10.0.0.99' "$SANDBOX/body")" "1"
code "http://127.0.0.1:$PORT/vpn" >/dev/null
check "tunel fora do modelo aparece" "$(grep -qi 'wgsite' "$SANDBOX/body" && echo sim || echo nao)" "sim"
code "http://127.0.0.1:$PORT/firewall" >/dev/null
check "denuncia a lista negra viva" "$(grep -c 'trabalha com lista negra' "$SANDBOX/body")" "1"
code "http://127.0.0.1:$PORT/system" >/dev/null
check "lista o que o motor mudaria" "$(grep -qi 'O que o motor mudaria' "$SANDBOX/body" && echo sim || echo nao)" "sim"
cid="$(grep -o 'name="id" value="[0-9a-f]*"' "$SANDBOX/body" | head -1 | grep -o '[0-9a-f]\{12\}')"
check "cada mudanca tem botao de marcar" "$([ -n "$cid" ] && echo sim || echo nao)" "sim"
check "marcar vale no somente leitura" "$(code -X POST -d "id=$cid" "http://127.0.0.1:$PORT/system/ack")" "303"
check "marcacao gravada em /var/lib" "$(grep -c "\"$cid\"" "$SANDBOX/var/lib/fwadmin/intencionais.json")" "1"
code "http://127.0.0.1:$PORT/system" >/dev/null
check "aparece como intencional" "$(grep -c 'intencional · admin' "$SANDBOX/body")" "1"
code -X POST -d "id=ffffffffffff" "http://127.0.0.1:$PORT/system/ack" >/dev/null
check "id que nao esta na lista nao marca" "$(grep -c ffffffffffff "$SANDBOX/var/lib/fwadmin/intencionais.json")" "0"
code -X POST -d "id=$cid" "http://127.0.0.1:$PORT/system/unack" >/dev/null
check "desfazer tira a marcacao" "$(grep -c "\"$cid\"" "$SANDBOX/var/lib/fwadmin/intencionais.json")" "0"
check "template baixa" "$(code "http://127.0.0.1:$PORT/system/config")" "200"
check "template avisa que nao aplicou" "$(grep -c 'NAO aplicou' "$SANDBOX/body")" "1"
check "edicao recusada com 403" "$(code -X POST -d 'name=nas&ip=10.0.0.60' "http://127.0.0.1:$PORT/dns/host")" "403"
check "apply recusado com 403"  "$(code -X POST -d 'yes=1' "http://127.0.0.1:$PORT/system/apply")" "403"
check "nenhuma proposta gravada" "$([ -e "$SANDBOX/etc/fwadmin/config.pending.yaml" ] && echo sim || echo nao)" "nao"
check "diagnostico continua valendo" "$(code -X POST -d 'tool=routes' "http://127.0.0.1:$PORT/system/diag")" "200"
check "chave privada fora da fotografia" "$(grep -rc 'CHAVE-PRIVADA' "$SANDBOX/run/fwadmin/live" | grep -vc ':0$')" "0"
check "senha do PPP fora da fotografia" "$(grep -rc 'segredo' "$SANDBOX/run/fwadmin/live" | grep -vc ':0$')" "0"
code "http://127.0.0.1:$PORT/lang/de?back_to=/firewall" >/dev/null
code "http://127.0.0.1:$PORT/firewall" >/dev/null
check "idioma troca a moldura" "$(grep -c 'Netzwerk' "$SANDBOX/body")" "1"
check "idioma desconhecido cai no padrao" "$(code "http://127.0.0.1:$PORT/lang/xx?back_to=//evil.example")" "303"
echo

echo "== origem fora da LAN, sem nginx na frente =="
kill "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null
FWADMIN_ALLOW=10.9.9.0/24 python3 -m uvicorn fwadmin.web:app --host 127.0.0.1 --port "$PORT" --log-level warning &
APP_PID=$!
for _ in $(seq 1 50); do
    [ "$(code "http://127.0.0.1:$PORT/login")" != "000" ] && break
    sleep 0.2
done
check "origem fora da lista recusada" "$(code "http://127.0.0.1:$PORT/login")" "403"
echo

printf '\033[1m%d passaram, %d falharam\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
