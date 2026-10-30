"""Notificacoes dispensadas: o "limpar" do sino.

As notificacoes nao sao guardadas; o painel as calcula a cada pagina a partir
do estado da maquina. Dispensar, portanto, e' lembrar quais textos a pessoa
ja viu. Vale pelo texto exato, como a marcacao de intencional em acks.py: se
o servico parado passa a ser outro, o texto muda e a notificacao volta.

E vale enquanto a notificacao existir. A que sumiu sai da lista na proxima
leitura (`prune`), de modo que, se o problema voltar amanha, ele aparece de
novo no sino — um "limpar" de ontem nunca esconde o problema de hoje.

Mora em /var/lib/fwadmin, como intencionais.json: nao muda nada no firewall,
entao vale tambem no somente leitura.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

from fwadmin import paths

FILE = paths.VAR / "dispensadas.json"


def alert_id(alert: dict[str, str]) -> str:
    text = "\x1f".join(alert.get(k, "") for k in ("level", "title", "detail"))
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def load() -> dict[str, dict]:
    """{id: {by, at}}. Arquivo ilegivel = nada dispensado, nunca excecao."""
    try:
        data = json.loads(FILE.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict[str, dict]) -> None:
    FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_name(f".{FILE.name}.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(FILE)


def dismiss(ids: list[str], by: str) -> None:
    data = load()
    for cid in ids:
        data[cid] = {"by": by, "at": time.time()}
    _save(data)


def restore() -> None:
    _save({})


def prune(current: list[str]) -> set[str]:
    """Esquece o que nao esta mais na lista e devolve o que segue dispensado.

    So grava se algo saiu: isto roda em toda pagina, e a pagina nao precisa
    de uma escrita em disco para mostrar o sino.
    """
    data = load()
    kept = {cid: v for cid, v in data.items() if cid in current}
    if len(kept) != len(data):
        try:
            _save(kept)
        except OSError:
            pass
    return set(kept)
