"""Senhas que o motor precisa escrever, fora do config e do git.

O config.yaml so guarda a referencia (pppoe.password_ref); o valor mora em
/etc/fwadmin/secrets.yaml, modo 0600. O painel grava a senha nova em
secrets.pending.yaml, ao lado da config pendente: ela so vale no apply, e
'descartar' a leva junto. O apply (root) renderiza o arquivo de segredo a
partir das duas e, confirmado, funde a pendente na definitiva.

Nada daqui passa pelo render_all: o painel e o importador renderizam para
mostrar e comparar, e senha nao pode estar em nada que se mostra. So o fwctl
chama render_secrets, no build_plan.
"""

from __future__ import annotations

import os
import pwd
import re
from pathlib import Path

import yaml

from fwadmin import paths

PENDING = paths.ETC / "secrets.pending.yaml"
PANEL_USER = "netadm"

PEER_PASSWORD = re.compile(r'^\s*password\s+"?([^"\n]*)"?\s*$', re.MULTILINE)


def _read(path: Path) -> dict[str, str]:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _write(path: Path, data: dict[str, str]) -> None:
    """0600 e do usuario do painel: e' ele quem recebe a senha pela tela."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(yaml.safe_dump(data, allow_unicode=True))
    if os.geteuid() == 0:
        try:
            owner = pwd.getpwnam(PANEL_USER)
            os.chown(tmp, owner.pw_uid, owner.pw_gid)
        except KeyError:
            pass
    tmp.replace(path)


def current() -> dict[str, str]:
    """As senhas que valem no proximo apply: a pendente por cima da aplicada."""
    return _read(paths.SECRETS) | _read(PENDING)


def has(ref: str) -> bool:
    return ref in current()


def propose(ref: str, value: str) -> None:
    """Pelo painel: a senha nova espera o apply, como a config."""
    data = _read(PENDING)
    data[ref] = value
    _write(PENDING, data)


def discard() -> None:
    PENDING.unlink(missing_ok=True)


def commit() -> None:
    """No confirm: a pendente vira a definitiva."""
    pending = _read(PENDING)
    if pending:
        _write(paths.SECRETS, _read(paths.SECRETS) | pending)
    PENDING.unlink(missing_ok=True)


def adopt_from_peer(ref: str, peer: str) -> bool:
    """Na adocao: a senha que hoje esta dentro do /etc/ppp/peers/<peer> vai
    para o secrets.yaml. Root, no fwctl. Devolve True se achou."""
    if has(ref):
        return True
    try:
        text = paths.sys_path(f"/etc/ppp/peers/{peer}").read_text()
    except OSError:
        return False
    found = PEER_PASSWORD.search(text)
    if not found or not found.group(1):
        return False
    data = _read(paths.SECRETS)
    data[ref] = found.group(1)
    _write(paths.SECRETS, data)
    return True
