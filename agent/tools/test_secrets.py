#!/usr/bin/env python3
"""A senha do PPPoE: so o fwctl a ve, e ela nunca sai de arquivo 0600.

Roda num sysroot descartavel, sem root: o build_plan e o install sao os de
verdade, so o /etc e' de mentira.
"""

import os
import stat
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="fwadmin-secrets.")
os.environ["FWADMIN_SYSROOT"] = SANDBOX
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fwadmin import paths, secretstore  # noqa: E402
from fwadmin.apply import build_plan, install  # noqa: E402
from fwadmin.render import load, render_all  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
pass_n = fail_n = 0


def check(label: str, got, want) -> None:
    global pass_n, fail_n
    if got == want:
        print(f"  \033[32mok\033[0m   {label}")
        pass_n += 1
    else:
        print(f"  \033[31mFALHA\033[0m {label}\n       esperado: {want}\n       obtido:   {got}")
        fail_n += 1


def mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


cfg = load(ROOT / "config" / "config.yaml")
peer = next(w.pppoe for w in cfg.wans if w.pppoe)
SECRET = f"ppp-secret-{peer.peer}"
staging = paths.STAGING

print("== sem senha em lugar nenhum, o plano reprova ==")
plan = build_plan(cfg, None, staging)
check("nenhum arquivo de senha no plano", SECRET in plan.rendered, False)
check("e o plano nao e' valido", plan.valid, False)
check("dizendo qual peer", any(peer.peer in c.command and not c.ok for c in plan.checks), True)

print("\n== adocao: a senha que esta dentro do peer vivo ==")
live_peer = paths.sys_path(f"/etc/ppp/peers/{peer.peer}")
live_peer.parent.mkdir(parents=True, exist_ok=True)
live_peer.write_text('plugin rp-pppoe.so\nuser "fulano"\npassword "segredo-de-teste"\n')
plan = build_plan(cfg, None, staging)
check("a senha foi para o secrets.yaml", secretstore.current().get(peer.password_ref), "segredo-de-teste")
check("secrets.yaml 0600", mode(paths.SECRETS), "0o600")
check("o arquivo de senha entra no plano", SECRET in plan.secret, True)
check("no staging, 0600", mode(staging / SECRET), "0o600")
check("e o staging fechado", mode(staging), "0o700")
check("com a senha dentro", 'password "segredo-de-teste"' in (staging / SECRET).read_text(), True)
check("mas nada que o painel renderiza a tem",
      any("segredo-de-teste" in v for v in render_all(cfg).values()), False)

print("\n== instalado no /etc, 0600 desde a criacao ==")
backup = Path(SANDBOX, "backup")
install(staging, backup, [SECRET], plan.targets, plan.executable, plan.secret)
target = paths.sys_path(plan.targets[SECRET])
check("o arquivo existe", target.exists(), True)
check("0600", mode(target), "0o600")

print("\n== senha nova pelo painel: espera o apply ==")
secretstore.propose(peer.password_ref, "senha-nova")
check("pendente vale no proximo apply", secretstore.current()[peer.password_ref], "senha-nova")
check("a definitiva nao mudou ainda", "senha-nova" in paths.SECRETS.read_text(), False)
secretstore.discard()
check("descartar volta a antiga", secretstore.current()[peer.password_ref], "segredo-de-teste")
secretstore.propose(peer.password_ref, "senha-nova")
secretstore.commit()
check("confirm torna definitiva", secretstore.current()[peer.password_ref], "senha-nova")
check("e some a pendente", secretstore.PENDING.exists(), False)

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
raise SystemExit(1 if fail_n else 0)
