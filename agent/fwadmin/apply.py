"""O pipeline de apply: staging, validacao, instalacao atomica e rollback.

A regra que orienta todo este modulo: **nunca deixar o firewall num estado que
so pode ser consertado indo fisicamente ate a maquina**. Dai o watchdog de
confirmacao — se o apply derrubar a LAN, ninguem clica em "Confirmar" e o
sistema volta sozinho.

Ordem das operacoes, sempre a mesma:

    validar modelo -> renderizar -> validar sintaxe -> backup -> instalar
    -> recarregar -> armar watchdog

Qualquer falha antes de "instalar" aborta sem ter tocado em /etc.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from fwadmin import paths
from fwadmin.models import Config, IfRole
from fwadmin.render import EXECUTABLE, TARGETS, render_all


class ApplyError(RuntimeError):
    """Erro que aborta o apply antes de qualquer escrita em /etc."""


# ---------------------------------------------------------------------------
# execucao de comandos
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# validadores de sintaxe (rodam sobre o staging, nunca sobre /etc)
# ---------------------------------------------------------------------------

VALIDATORS: dict[str, list[str]] = {
    "nftables.conf": ["nft", "-c", "-f"],
    "dnsmasq.conf": ["dnsmasq", "--test", "-C"],
    "interfaces": ["ifquery", "-l", "-a", "-i"],
}


def validate_syntax(staging: Path, names: list[str]) -> list[Result]:
    """Passa cada arquivo gerado pela ferramenta nativa dele."""
    results = []
    for name in names:
        argv = VALIDATORS.get(name)
        if not argv:
            continue
        results.append(run(*argv, str(staging / name), mutating=False))
    return results


# ---------------------------------------------------------------------------
# quais servicos recarregar para cada arquivo alterado
# ---------------------------------------------------------------------------


@dataclass
class Reload:
    """Uma acao de recarga, com o peso que ela tem na conectividade."""

    label: str
    argv: list[str]
    disruptive: bool = False
    """True = derruba trafego enquanto roda (WAN ou LAN cai por instantes)."""


def _peer_device(cfg: Config | None, peer: str) -> str | None:
    """Interface fisica por baixo de um peer PPPoE."""
    if cfg is None:
        return None
    for iface in cfg.interfaces:
        if iface.pppoe is not None and iface.pppoe.peer == peer:
            return iface.device
    return None


def _pppoe_restart(peer: str, device: str | None) -> Reload:
    """Reinicia um peer PPPoE e confirma que ele voltou.

    A verificacao do ppp0 no fim e' o ponto principal. No incidente de
    2026-08-21 o 'pon' falhou (o seccomp da unit bloqueava AF_PACKET, que o
    rp-pppoe usa para validar o nome da interface) e mesmo assim o apply
    reportou sucesso: 'pon' devolve 0 porque quem morre e' o pppd que ele
    lanca. Resultado, a WAN primaria caiu em silencio e so o failover, um
    minuto depois, denunciou. Agora um peer que nao sobe faz a recarga falhar,
    que e' quando o rollback automatico tem serventia.

    A espera pela interface de baixo cobre o caminho do rollback, onde as
    interfaces sao mesmo derrubadas e resubidas antes do PPPoE: o rp-pppoe
    recusa o nome com 'unrecognized option <dev>' se ela nao estiver up na
    hora do parse.
    """
    steps = [f"poff {peer} || true"]
    if device:
        steps.append(
            f"for i in $(seq 1 20); do "
            f"ip link show {device} 2>/dev/null | grep -q LOWER_UP && break; sleep 1; done"
        )
    steps.append(f"pon {peer}")
    steps.append(
        "for i in $(seq 1 30); do "
        "ip -4 addr show ppp0 2>/dev/null | grep -q 'inet ' && exit 0; sleep 1; done"
    )
    steps.append(f'echo "ppp0 nao subiu depois do pon {peer}" >&2; exit 1')
    return Reload(f"PPPoE {peer}", ["sh", "-c", "; ".join(steps)], disruptive=True)


def reloads_for(changed: list[str], cfg: Config, previous: Config | None) -> list[Reload]:
    """Deriva as recargas necessarias — so para o que realmente mudou."""
    actions: list[Reload] = []

    if "nftables.conf" in changed:
        actions.append(
            Reload("firewall (nft -f)", ["nft", "-f", str(paths.sys_path("/etc/nftables.conf"))])
        )

    if "dnsmasq.conf" in changed:
        # reload do dnsmasq so rele /etc/hosts e leases; mudanca de conf exige restart
        actions.append(Reload("dnsmasq", ["systemctl", "restart", "dnsmasq"]))

    if "interfaces" in changed and previous is not None:
        for iface in _ifaces_changed(cfg, previous):
            actions.append(
                Reload(
                    f"interface {iface}",
                    ["sh", "-c", f"ifdown {iface} || true; ifup {iface}"],
                    disruptive=True,
                )
            )

    for name in changed:
        if name.startswith("ppp-peers-"):
            peer = name.removeprefix("ppp-peers-")
            actions.append(_pppoe_restart(peer, _peer_device(cfg, peer)))

    if "wan-failover.sh" in changed:
        # o script e' lido a cada disparo do timer; nada a recarregar
        actions.append(Reload("failover (rearmar timer)", ["systemctl", "restart", "fwadmin-failover.timer"]))

    return actions


def rollback_reloads(files: list[str], cfg: Config | None) -> list[Reload]:
    """Recargas do rollback.

    Diferente do apply, aqui nao ha diff em que confiar: o objetivo e' fazer o
    sistema voltar a obedecer o /etc restaurado, entao tudo que foi tocado e'
    reaplicado sem perguntar.
    """
    actions: list[Reload] = []

    if "nftables.conf" in files:
        actions.append(
            Reload("firewall (nft -f)", ["nft", "-f", str(paths.sys_path("/etc/nftables.conf"))])
        )
    if "dnsmasq.conf" in files:
        actions.append(Reload("dnsmasq", ["systemctl", "restart", "dnsmasq"]))
    if "interfaces" in files and cfg is not None:
        for iface in cfg.interfaces:
            if iface.role is not IfRole.unused:
                actions.append(
                    Reload(
                        f"interface {iface.device}",
                        ["sh", "-c", f"ifdown {iface.device} || true; ifup {iface.device}"],
                        disruptive=True,
                    )
                )
    for name in files:
        if name.startswith("ppp-peers-"):
            peer = name.removeprefix("ppp-peers-")
            actions.append(_pppoe_restart(peer, _peer_device(cfg, peer)))
    if "wan-failover.sh" in files:
        actions.append(
            Reload("failover (rearmar timer)", ["systemctl", "restart", "fwadmin-failover.timer"])
        )
    return actions


def _ifaces_changed(cfg: Config, previous: Config) -> list[str]:
    """Devices cuja configuracao de camada 3 mudou de fato."""
    old = {i.device: i.ipv4.model_dump() for i in previous.interfaces}
    changed = []
    for iface in cfg.interfaces:
        if old.get(iface.device) != iface.ipv4.model_dump():
            changed.append(iface.device)
    return changed


# ---------------------------------------------------------------------------
# instalacao atomica
# ---------------------------------------------------------------------------


def install(staging: Path, backup: Path, names: list[str]) -> list[str]:
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
        target = paths.sys_path(TARGETS[name])
        target.parent.mkdir(parents=True, exist_ok=True)
        existed = target.exists()

        if existed:
            shutil.copy2(target, backup / name)

        # registra a intencao antes de tocar no alvo
        manifest.append({"name": name, "target": str(target), "existed": existed})
        write_manifest()

        tmp = target.with_name(f".{target.name}.fwadmin-new")
        tmp.write_text((staging / name).read_text())
        os.chmod(tmp, 0o755 if name in EXECUTABLE else 0o644)
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
    checks: list[Result] = field(default_factory=list)

    @property
    def disruptive(self) -> bool:
        return any(r.disruptive for r in self.reloads)

    @property
    def valid(self) -> bool:
        return all(c.ok for c in self.checks)


def diff_against_live(rendered: dict[str, str]) -> list[str]:
    """Nomes dos arquivos cujo conteudo difere do que esta em /etc."""
    changed = []
    for name, content in rendered.items():
        target = paths.sys_path(TARGETS[name])
        if not target.exists() or target.read_text() != content:
            changed.append(name)
    return changed


def build_plan(cfg: Config, previous: Config | None, staging: Path) -> Plan:
    """Renderiza, escreve o staging e valida — tudo fora de /etc."""
    rendered = render_all(cfg)

    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for name, content in rendered.items():
        path = staging / name
        path.write_text(content)
        path.chmod(0o755 if name in EXECUTABLE else 0o644)

    changed = diff_against_live(rendered)
    plan = Plan(
        cfg=cfg,
        rendered=rendered,
        changed=changed,
        reloads=reloads_for(changed, cfg, previous),
    )
    plan.checks = validate_syntax(staging, changed or list(rendered))
    return plan
