#!/usr/bin/env python3
"""O DDNS do usuario: o token so existe em arquivo 0600, e desligar para a unidade.

Roda num sysroot descartavel, sem root: o build_plan e as recargas sao os de
verdade, so o /etc e' de mentira. Com o inadyn no PATH, a validacao nativa
roda de verdade; sem ele, o plano reprova pedindo a instalacao.
"""

import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="fwadmin-ddns.")
os.environ["FWADMIN_SYSROOT"] = SANDBOX
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import ValidationError  # noqa: E402

from fwadmin import paths, secretstore  # noqa: E402
from fwadmin.apply import build_plan  # noqa: E402
from fwadmin.models import DDNS, Config  # noqa: E402
from fwadmin.render import load, render_all  # noqa: E402
from fwadmin.services import ddns  # noqa: E402

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


def with_ddns(**kw) -> Config:
    data = load(ROOT / "config" / "config.yaml").model_dump()
    data["ddns"] = kw
    return Config.model_validate(data)


def failed(plan, text: str) -> bool:
    return any(text in c.command and not c.ok for c in plan.checks)


staging = paths.STAGING
TOKEN = 'tok-"de"-teste\\1'

print("== schema ==")
for label, kw in [
    ("ligado sem nome e' recusado", {"enabled": True}),
    ("Cloudflare sem zona e' recusado", {"enabled": True, "provider": "cloudflare.com", "hostname": "casa.exemplo.com"}),
    ("provedor fora da lista e' recusado", {"enabled": True, "provider": "x.com", "hostname": "a.x.com"}),
]:
    try:
        DDNS(**kw)
        check(label, "aceito", "recusado")
    except ValidationError:
        check(label, "recusado", "recusado")
check("nome vai para minusculas, sem ponto final",
      DDNS(enabled=True, hostname="Casa.DuckDNS.org.").hostname, "casa.duckdns.org")

print("\n== nunca configurado: nada no plano ==")
cfg = load(ROOT / "config" / "config.yaml")
check("sem alvos", ddns.targets(cfg), {})
check("sem unidade", ddns.units(cfg), frozenset())

print("\n== ligado, sem token: o plano reprova ==")
cfg = with_ddns(enabled=True, hostname="casa.duckdns.org")
plan = build_plan(cfg, None, staging)
check("nenhum arquivo de segredo", ddns.SECRET in plan.rendered, False)
check("e o plano diz que falta o token", failed(plan, "token do DDNS"), True)

print("\n== com token (DuckDNS: o token vai como usuario) ==")
secretstore.propose("ddns", TOKEN)
plan = build_plan(cfg, None, staging)
conf = plan.rendered[ddns.FILE]
sec = plan.rendered[ddns.SECRET]
check("o segredo entra no plano como segredo", ddns.SECRET in plan.secret, True)
check("no staging, 0600", mode(staging / ddns.SECRET), "0o600")
check("o token vai como usuario, escapado", 'username = "tok-\\"de\\"-teste\\\\1"' in sec, True)
check("o conf traz o nome e o include", 'hostname = "casa.duckdns.org"' in conf and ddns.SECRET_PATH in conf, True)
check("mas nao o token", "tok-" in conf, False)
check("nada que o painel renderiza tem o token",
      any("tok-" in v for v in render_all(cfg).values()), False)
check("recarga habilita e reinicia a unidade",
      [r.argv[-1] for r in plan.reloads if r.label.startswith("DDNS")],
      [f"systemctl enable {ddns.UNIT} && systemctl restart {ddns.UNIT}"])

if shutil.which("inadyn"):
    check("inadyn --check-config aprova", failed(plan, "inadyn"), False)
else:
    check("sem inadyn, o plano pede a instalacao", failed(plan, "inadyn"), True)

print("\n== com usuario (No-IP): o token vai como senha ==")
cfg_user = with_ddns(enabled=True, provider="noip.com", hostname="casa.ddns.net", username="fulano")
plan = build_plan(cfg_user, None, staging)
check("senha no segredo", plan.rendered[ddns.SECRET].count("password = "), 1)
check("usuario no conf", 'username = "fulano"' in plan.rendered[ddns.FILE], True)

print("\n== desligado depois de configurado ==")
off = with_ddns(enabled=False, hostname="casa.duckdns.org")
plan = build_plan(off, cfg, staging)
check("os alvos continuam (o motor nao apaga)", set(ddns.targets(off)), {ddns.FILE})
check("o conf vira comentario", "provider" in plan.rendered[ddns.FILE], False)
check("o segredo perde o token", "tok-" in plan.rendered[ddns.SECRET], False)
check("sem token nao reprova", failed(plan, "token do DDNS"), False)
check("recarga para e desabilita",
      [r.argv for r in plan.reloads if r.label.startswith("DDNS")],
      [["systemctl", "disable", "--now", ddns.UNIT]])
check("rollback para a config ligada reinicia",
      [r.label for r in ddns.rollback(cfg, [ddns.FILE])], ["DDNS (inadyn)"])

print("\n== so o token mudou: a recarga acontece ==")
check("segredo sozinho no 'changed' recarrega",
      [r.label for r in ddns.reloads(cfg, cfg, [ddns.SECRET])], ["DDNS (inadyn)"])

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
raise SystemExit(1 if fail_n else 0)
