#!/bin/bash
# Sobe o app num sysroot descartavel, cria o usuario inicial e percorre todas
# as telas. Verifica tambem que uma edicao invalida e' recusada e que a
# proposta so aparece depois de uma edicao valida.
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
for rota in / /interfaces /routing /dns /firewall /services /diag /system; do
    check "GET $rota" "$(code "http://127.0.0.1:$PORT$rota")" "200"
done
check "fragmento htmx das WANs" "$(code "http://127.0.0.1:$PORT/fragment/wans")" "200"
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
check "aviso aparece na UI"   "$(grep -qi 'não aplicadas' "$SANDBOX/body" && echo sim || echo nao)" "sim"
echo

echo "== edicao invalida e' recusada =="
code -X POST -d 'mac=nao-e-um-mac&ip=10.0.0.61&name=teste' \
     "http://127.0.0.1:$PORT/dns/reservation" >/dev/null
check "erro volta para /dns"   "$(code -o /dev/null -X POST -d 'mac=zz&ip=1.2.3.4&name=x' "http://127.0.0.1:$PORT/dns/reservation")" "303"
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
check "POST /diag rotas"      "$(code -X POST -d 'tool=routes' "http://127.0.0.1:$PORT/diag")" "200"
code -X POST -d 'tool=ping&target=127.0.0.1' "http://127.0.0.1:$PORT/diag" >/dev/null
check "ping local responde"   "$(grep -qi 'ping' "$SANDBOX/body" && echo sim || echo nao)" "sim"
code -X POST -d 'tool=ping&target=;rm -rf /' "http://127.0.0.1:$PORT/diag" >/dev/null
check "alvo com shell barrado" "$(grep -qi 'alvo inv' "$SANDBOX/body" && echo sim || echo nao)" "sim"
code -X POST -d 'tool=ping&target=--flag-injetada' "http://127.0.0.1:$PORT/diag" >/dev/null
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

printf '\033[1m%d passaram, %d falharam\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
