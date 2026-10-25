"""Mudancas marcadas como intencionais: a trava do primeiro apply.

O importador lista o que o primeiro apply faria diferente do que a maquina
faz hoje. Algumas dessas diferencas sao o objetivo (a entrada fechada);
outras sao acidente (uma regra que o modelo ainda nao sabe dizer). Ninguem
precisa decorar qual e' qual: enquanto houver mudanca que uma pessoa nao
marcou como intencional, o `fwctl apply` de adocao se recusa.

A marcacao vale para o texto exato da mudanca. Se a maquina mudar e a
mesma linha passar a dizer outra coisa, o id muda e a marcacao antiga deixa
de cobrir — e' o comportamento certo: o que foi aceito foi aquele texto.

Mora em /var/lib/fwadmin, e nao em /etc/fwadmin: marcar nao muda nada no
firewall, entao vale tambem no painel somente leitura, que nao tem /etc.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import time

from fwadmin import paths

FILE = paths.VAR / "intencionais.json"
PANEL_USER = "netadm"


def change_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def load() -> dict[str, dict]:
    """{id: {text, by, at}}. Arquivo ilegivel = nada marcado, nunca excecao."""
    try:
        data = json.loads(FILE.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict[str, dict]) -> None:
    FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_name(f".{FILE.name}.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False))
    # O 'fwctl ack' roda como root; o arquivo tem de continuar do usuario do
    # painel, senao a proxima marcacao pela tela falha.
    if os.geteuid() == 0:
        try:
            owner = pwd.getpwnam(PANEL_USER)
            os.chown(tmp, owner.pw_uid, owner.pw_gid)
        except KeyError:
            pass
    tmp.replace(FILE)


def mark(text: str, by: str) -> str:
    cid = change_id(text)
    data = load()
    data[cid] = {"text": text, "by": by, "at": time.time()}
    _save(data)
    return cid


def unmark(cid: str) -> bool:
    data = load()
    if data.pop(cid, None) is None:
        return False
    _save(data)
    return True


def split(changes: list[str]) -> tuple[list[tuple[str, str]], list[tuple[str, str, dict]]]:
    """(pendentes, intencionais): pendentes = [(id, texto)], intencionais =
    [(id, texto, marcacao)], na ordem do importador."""
    marked = load()
    pending, accepted = [], []
    for text in changes:
        cid = change_id(text)
        if cid in marked:
            accepted.append((cid, text, marked[cid]))
        else:
            pending.append((cid, text))
    return pending, accepted
