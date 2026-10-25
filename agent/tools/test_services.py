#!/usr/bin/env python3
"""Quais botoes da tela de Servicos valem em cada estado do servico.

A regra e' do pedido de 25/10: instalar so se nao instalado; reiniciar nao
vale parado nem no meio de uma transicao; parar e recarregar nao valem
parado. Iniciar entrou para o servico parado ter como voltar.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fwadmin.status import UnitInfo  # noqa: E402
from fwadmin.web import service_buttons  # noqa: E402

pass_n = fail_n = 0


def check(label: str, got, want) -> None:
    global pass_n, fail_n
    if got == want:
        print(f"  \033[32mok\033[0m   {label}")
        pass_n += 1
    else:
        print(f"  \033[31mFALHA\033[0m {label}\n       esperado: {want}\n       obtido:   {got}")
        fail_n += 1


def allowed(**state) -> list[str]:
    info = UnitInfo(unit="x.service", package="x", **state)
    return sorted(k for k, why in service_buttons(info).items() if not why)


print("== botoes por estado ==")
check("nao instalado: so instalar", allowed(installed=False), ["install"])
check("rodando: reiniciar, recarregar, parar",
      allowed(installed=True, active="active", can_reload=True), ["reload", "restart", "stop"])
check("rodando sem suporte a reload",
      allowed(installed=True, active="active", can_reload=False), ["restart", "stop"])
check("parado: so iniciar", allowed(installed=True, active="inactive", can_reload=True), ["start"])
check("falhou: so iniciar", allowed(installed=True, active="failed", can_reload=True), ["start"])
for state in ("activating", "deactivating", "reloading"):
    check(f"{state}: nada", allowed(installed=True, active=state, can_reload=True), [])

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
raise SystemExit(1 if fail_n else 0)
