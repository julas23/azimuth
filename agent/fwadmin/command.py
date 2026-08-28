"""Execucao de comandos externos.

Modulo de baixo nivel, sem dependencia de nada mais do fwadmin alem do
paths: e' o que permite os modulos de servico e o pipeline de apply usarem o
mesmo 'run' sem import circular.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from fwadmin import paths


class ApplyError(RuntimeError):
    """Erro que aborta o apply antes de qualquer escrita em /etc."""


@dataclass
class Result:
    ok: bool
    command: str
    output: str


def run(*args: str, check: bool = False, timeout: int = 60, mutating: bool = True) -> Result:
    """Executa um comando. Nunca via shell — argumentos sao sempre uma lista.

    Em sandbox os comandos que mexem no sistema sao apenas registrados; os de
    verificacao (nft -c, dnsmasq --test) continuam rodando de verdade, senao o
    teste nao provaria nada.
    """
    if mutating and paths.sandboxed():
        return Result(True, " ".join(args), "(sandbox: nao executado)")
    if shutil.which(args[0]) is None:
        return Result(
            not mutating,
            " ".join(args),
            f"ferramenta ausente nesta maquina: {args[0]}",
        )
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result = Result(False, " ".join(args), str(exc))
    else:
        result = Result(
            proc.returncode == 0,
            " ".join(args),
            (proc.stdout + proc.stderr).strip(),
        )
    if check and not result.ok:
        raise ApplyError(f"comando falhou: {result.command}\n{result.output}")
    return result
