"""O pipeline de apply: staging, validacao, instalacao atomica e rollback.

A regra que orienta todo este modulo: **nunca deixar o firewall num estado que
so pode ser consertado indo fisicamente ate a maquina**. Dai o watchdog de
confirmacao — se o apply derrubar a LAN, ninguem clica em "Confirmar" e o
sistema volta sozinho.

Ordem das operacoes, sempre a mesma:

    validar modelo -> renderizar -> validar sintaxe -> backup -> instalar
    -> recarregar -> PROVAR -> armar watchdog

Qualquer falha antes de "instalar" aborta sem ter tocado em /etc. Falha da
prova de funcao, depois disso, reverte na hora: esperar os 90 segundos do
watchdog so faria sentido se ninguem soubesse que quebrou — e a prova sabe.

Este modulo nao conhece nenhum servico em particular. Quem sabe o que
renderizar, validar, recarregar e provar e' o registro em fwadmin.services.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from fwadmin import paths, services
from fwadmin.command import ApplyError, Result, run
from fwadmin.models import Config
from fwadmin.render import render_all
from fwadmin.services import pppoe
from fwadmin.services.base import Prova, Reload

__all__ = [
    "ApplyError",
    "Plan",
    "Prova",
    "Reload",
    "Result",
    "State",
    "arm_watchdog",
    "build_plan",
    "disarm_watchdog",
    "install",
    "restore",
    "run",
]


# ---------------------------------------------------------------------------
# instalacao atomica
# ---------------------------------------------------------------------------


def install(
    staging: Path,
    backup: Path,
    names: list[str],
    targets: dict[str, str],
    executable: set[str] | None = None,
    secret: set[str] | None = None,
) -> list[str]:
    """Copia o staging para /etc, guardando antes o que estava la.

    A escrita e' atomica (arquivo temporario + os.replace no mesmo filesystem),
    entao nenhum daemon jamais le um arquivo pela metade.

    O manifesto guarda o caminho de destino de cada arquivo e se ele existia
    antes. E' de proposito: o rollback e' a rede de seguranca e nao pode
    depender de conseguir ler ou validar a config para funcionar.

    O manifesto e' regravado ANTES de cada os.replace, e nao no fim do laco.
    Se o apply morre no meio (disco cheio, EROFS, permissao), o que ja foi
    trocado em /etc precisa estar registrado, senao o rollback fica sem mapa
    justo na hora em que ele e' necessario. Registrar antes e' seguro: a
    entrada aponta para o backup que ja foi copiado, e restaurar um arquivo
    que ainda nao chegou a ser trocado apenas reescreve conteudo identico.
    """
    backup.mkdir(parents=True, exist_ok=True)
    manifest_path = backup / "MANIFEST.json"
    installed = []
    manifest = []

    def write_manifest() -> None:
        manifest_path.write_text(
            json.dumps({"files": manifest, "at": datetime.now().isoformat()}, indent=2)
        )

    write_manifest()

    for name in names:
        target = paths.sys_path(targets[name])
        target.parent.mkdir(parents=True, exist_ok=True)
        existed = target.exists()

        if existed:
            shutil.copy2(target, backup / name)

        # registra a intencao antes de tocar no alvo
        manifest.append({"name": name, "target": str(target), "existed": existed})
        write_manifest()

        tmp = target.with_name(f".{target.name}.fwadmin-new")
        mode = 0o600 if name in (secret or set()) else 0o755 if name in (executable or set()) else 0o644
        # o modo vai na criacao: um chmod depois deixaria a senha legivel por
        # um instante
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fh:
            fh.write((staging / name).read_text())
        os.chmod(tmp, mode)
        os.replace(tmp, target)

        installed.append(name)

    return installed


def restore(backup: Path) -> list[str]:
    """Devolve os arquivos do backup para /etc. Caminho do rollback.

    Usa apenas o manifesto: nenhuma leitura de config, nenhum template, nenhum
    import pesado. Se o rollback tambem falhar, nao sobra saida.
    """
    manifest = json.loads((backup / "MANIFEST.json").read_text())
    restored = []

    for entry in manifest["files"]:
        name = entry["name"]
        target = Path(entry["target"])
        source = backup / name

        if not entry.get("existed", True) or not source.exists():
            # nao existia antes do apply: o certo e' remover, nao restaurar
            target.unlink(missing_ok=True)
            restored.append(f"{name} (removido)")
            continue

        tmp = target.with_name(f".{target.name}.fwadmin-new")
        shutil.copy2(source, tmp)
        os.replace(tmp, target)
        restored.append(name)

    return restored


# ---------------------------------------------------------------------------
# estado do apply pendente de confirmacao
# ---------------------------------------------------------------------------


@dataclass
class State:
    backup: str = ""
    at: float = 0.0
    timeout: int = 90
    files: list[str] = field(default_factory=list)
    reloads: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def deadline(self) -> float:
        return self.at + self.timeout

    @property
    def remaining(self) -> int:
        return max(0, int(self.deadline - time.time()))

    def save(self) -> None:
        paths.STATE.parent.mkdir(parents=True, exist_ok=True)
        paths.STATE.write_text(json.dumps(self.__dict__, indent=2))

    @classmethod
    def load(cls) -> State | None:
        if not paths.STATE.exists():
            return None
        return cls(**json.loads(paths.STATE.read_text()))

    @classmethod
    def clear(cls) -> None:
        paths.STATE.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# watchdog de confirmacao
# ---------------------------------------------------------------------------


def arm_watchdog(timeout: int) -> Result:
    """Agenda o rollback automatico com uma unidade transiente do systemd.

    Transiente de proposito: se a maquina reiniciar no meio, o timer some junto
    e o firewall sobe com o que estiver em /etc — que e' o comportamento certo,
    ja que o boot em si e' a prova de que a config funciona.
    """
    return run(
        "systemd-run",
        f"--unit={paths.REVERT_UNIT}",
        f"--on-active={timeout}s",
        "--description=fwadmin: reverter apply nao confirmado",
        "/usr/local/sbin/fwctl",
        "rollback",
        "--auto",
    )


def disarm_watchdog() -> Result:
    result = run("systemctl", "stop", f"{paths.REVERT_UNIT}.timer")
    run("systemctl", "reset-failed", f"{paths.REVERT_UNIT}.timer")
    run("systemctl", "reset-failed", f"{paths.REVERT_UNIT}.service")
    return result


# ---------------------------------------------------------------------------
# operacoes de alto nivel
# ---------------------------------------------------------------------------


@dataclass
class Plan:
    """O que um apply faria. Produzido sem escrever nada."""

    cfg: Config
    rendered: dict[str, str]
    changed: list[str]
    reloads: list[Reload]
    targets: dict[str, str] = field(default_factory=dict)
    executable: set[str] = field(default_factory=set)
    secret: set[str] = field(default_factory=set)
    """Arquivos com senha: modo 0600 no staging e no /etc, conteudo nunca
    mostrado (fwctl diff so diz que mudou)."""

    checks: list[Result] = field(default_factory=list)

    @property
    def disruptive(self) -> bool:
        return any(r.disruptive for r in self.reloads)

    @property
    def valid(self) -> bool:
        return all(c.ok for c in self.checks)


def diff_against_live(rendered: dict[str, str], targets: dict[str, str]) -> list[str]:
    """Nomes dos arquivos cujo conteudo difere do que esta em /etc."""
    changed = []
    for name, content in rendered.items():
        target = paths.sys_path(targets[name])
        if not target.exists() or target.read_text() != content:
            changed.append(name)
    return changed


def build_plan(cfg: Config, previous: Config | None, staging: Path) -> Plan:
    """Renderiza, escreve o staging e valida — tudo fora de /etc."""
    rendered = render_all(cfg)
    targets = services.targets(cfg)
    executable = services.executables(cfg)

    # As senhas entram so aqui, no fwctl: render_all e' o que painel e
    # importador usam para mostrar, e senha nao pode estar no que se mostra.
    secrets, missing = pppoe.render_secrets(cfg)
    rendered |= secrets
    targets |= pppoe.secret_targets(cfg)
    secret = set(secrets)

    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, mode=0o700)
    for name, content in rendered.items():
        path = staging / name
        mode = 0o600 if name in secret else 0o755 if name in executable else 0o644
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)

    changed = diff_against_live(rendered, targets)
    plan = Plan(
        cfg=cfg,
        rendered=rendered,
        changed=changed,
        reloads=services.reloads(cfg, previous, changed),
        targets=targets,
        executable=executable,
        secret=secret,
    )
    plan.checks = services.validate_syntax(staging, changed or list(rendered), cfg)
    for peer in missing:
        plan.checks.append(
            Result(
                False,
                f"senha do PPPoE '{peer}'",
                "nenhuma senha em secrets.yaml, nem dentro do /etc/ppp/peers vivo: "
                "informe a senha em Rede antes de aplicar",
            )
        )
    return plan
