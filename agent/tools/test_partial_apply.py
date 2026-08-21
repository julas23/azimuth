#!/usr/bin/env python3
"""O manifesto sobrevive a um apply que morre no meio.

Regressao do incidente de 2026-08-21: o fwctl chamado pela interface web
levava EROFS ao gravar em /etc (ProtectSystem=full monta /etc read-only no
namespace do servico). O apply morreu no primeiro arquivo, entao nada foi
tocado — mas se tivesse morrido no terceiro, o /etc ficaria com arquivos ja
trocados e o MANIFEST.json nunca teria sido escrito, porque so era gravado
depois do laco. Sem manifesto o 'fwctl rollback' recusa reverter, e a rede de
seguranca some justo na hora em que ela e' necessaria.

Este teste falha em cima do codigo antigo e passa no corrigido.
"""

import os
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="fwadmin-partial.")
os.environ["FWADMIN_SYSROOT"] = SANDBOX
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fwadmin import apply as apply_mod  # noqa: E402
from fwadmin.render import TARGETS  # noqa: E402

pass_n = fail_n = 0


def check(label: str, got, want) -> None:
    global pass_n, fail_n
    if got == want:
        print(f"  \033[32mok\033[0m   {label}")
        pass_n += 1
    else:
        print(f"  \033[31mFALHA\033[0m {label}\n       esperado: {want}\n       obtido:   {got}")
        fail_n += 1


names = ["dnsmasq.conf", "nftables.conf", "interfaces", "wan-failover.sh"]
FAIL_AT = 2  # morre ao instalar o 3o arquivo, com dois ja trocados

# --- /etc de partida, com conteudo reconhecivel ----------------------------
for name in names:
    target = apply_mod.paths.sys_path(TARGETS[name])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"ORIGINAL {name}\n")

staging = Path(SANDBOX, "staging")
staging.mkdir()
for name in names:
    (staging / name).write_text(f"NOVO {name}\n")

backup = Path(SANDBOX, "backup")

# --- faz o 3o os.replace falhar como o kernel faria em /etc read-only ------
real_replace = apply_mod.os.replace
calls = {"n": 0}


def flaky_replace(src, dst):
    if calls["n"] == FAIL_AT:
        raise OSError(30, "Read-only file system", str(dst))
    calls["n"] += 1
    return real_replace(src, dst)


apply_mod.os.replace = flaky_replace

print(f"sandbox: {SANDBOX}\n")
print("== apply morre no meio ==")
raised = None
try:
    apply_mod.install(staging, backup, names)
except OSError as exc:
    raised = exc
apply_mod.os.replace = real_replace

check("install propagou o erro", raised is not None and raised.errno == 30, True)
check("dois arquivos ja foram trocados", calls["n"], FAIL_AT)

# --- o ponto do teste: da' para reverter? ----------------------------------
print("\n== o manifesto sobreviveu? ==")
manifest = backup / "MANIFEST.json"
check("MANIFEST.json existe", manifest.exists(), True)

if manifest.exists():
    import json

    entries = json.loads(manifest.read_text())["files"]
    listed = [e["name"] for e in entries]
    # precisa cobrir os instalados E aquele que falhou no meio da troca
    check("manifesto cobre os trocados + o que falhou", listed, names[: FAIL_AT + 1])

    print("\n== rollback devolve o /etc original ==")
    apply_mod.restore(backup)
    for name in names:
        target = apply_mod.paths.sys_path(TARGETS[name])
        check(f"{name} voltou ao original", target.read_text(), f"ORIGINAL {name}\n")

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
sys.exit(1 if fail_n else 0)
