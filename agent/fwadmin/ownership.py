"""Posse: o que em /etc e' do motor, e o que roda nesta caixa sem dono.

O motor escreve seis arquivos e ate aqui nao sabia que eram dele.
`diff_against_live` responde "este arquivo vai mudar" e nao distingue as duas
causas possiveis: **o modelo mudou**, ou **alguem editou /etc a mao desde o
ultimo apply**. Nos dois casos o apply sobrescrevia, em silencio. Numa caixa
de cliente isso e' raro; numa caixa administrada por quem tambem sabe abrir o
vi, e' certo — e a primeira vez que o motor apaga um ajuste sem avisar e' a
ultima vez que alguem confia nele.

O selo fecha a lacuna. Quando um estado passa a ser oficial — o `confirm`, e
tambem o fim de um rollback — grava-se o sha256 de cada arquivo possuido.
No apply seguinte, comparar o arquivo vivo com o selo separa as duas causas.

**O selo nunca afirma o que nao viu.** So e' selado o arquivo cujo conteudo e'
exatamente o que o motor escreveria agora. Isso e' o que permite selar uma
caixa que ja estava rodando sem inventar historia: se o /etc dela bate com o
render, o selo e' constatacao; se nao bate, ele se recusa e diz o que sobrou.

Tres estados, e nao dois, pela mesma razao da Prova: "nunca foi selado" e'
diferente de "foi selado e mudou". Caixa recem-instalada, servico recem-ligado
e instalacao anterior a este modulo caem no primeiro caso, e nenhum deles e'
motivo para barrar coisa nenhuma.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fwadmin import paths, services
from fwadmin.command import run
from fwadmin.models import Config
from fwadmin.render import render_all

__all__ = [
    "AUSENTE",
    "DIVERGENTE",
    "ILEGIVEL",
    "INTACTO",
    "SEM_SELO",
    "Posse",
    "Unidade",
    "digest",
    "divergentes",
    "read_seal",
    "seal",
    "stash",
    "survey",
    "territory",
]

INTACTO = "intacto"
"""O arquivo vivo e' byte a byte o que o motor selou."""

DIVERGENTE = "divergente"
"""Selado, e mudou depois. Alguem editou /etc a mao."""

AUSENTE = "ausente"
"""Selado, e sumiu. Divergencia, e das graves."""

ILEGIVEL = "ilegivel"
"""Existe, e este processo nao consegue ler.

O terceiro estado da Prova aparece aqui pelo mesmo motivo. O painel roda como
netadm, sem privilegio: um arquivo que ele nao consegue abrir nao virou
divergente — ele so nao foi visto. Tratar isso como divergencia encheria a
tela de alarme falso e, pior, ensinaria a ignorar o alarme.
"""

SEM_SELO = "sem selo"
"""Possuido, nunca selado. Nao e' divergencia — e' desconhecimento."""


# ---------------------------------------------------------------------------
# arquivos possuidos
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Posse:
    """O que o motor sabe sobre um arquivo que e' dele."""

    name: str
    """Nome do render — o mesmo que aparece no manifesto e no plano."""

    target: str
    service: str
    state: str
    sealed: str = ""
    live: str = ""

    @property
    def divergiu(self) -> bool:
        return self.state in (DIVERGENTE, AUSENTE)


def digest(path: Path) -> str:
    """sha256 do arquivo, ou string vazia se ele nao puder ser lido."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def read_seal() -> dict[str, dict]:
    """O selo gravado. Selo ilegivel e' selo ausente, nunca uma excecao.

    Este modulo e' consultado no caminho do apply, que e' justamente o caminho
    que nao pode morrer por causa de um arquivo de metadado corrompido.
    """
    try:
        data = json.loads(paths.OWNED.read_text())
    except (OSError, ValueError):
        return {}
    files = data.get("files")
    return files if isinstance(files, dict) else {}


def _write_seal(files: dict[str, dict]) -> None:
    paths.OWNED.parent.mkdir(parents=True, exist_ok=True)
    tmp = paths.OWNED.with_name(f".{paths.OWNED.name}.new")
    tmp.write_text(
        json.dumps(
            {"files": files, "at": datetime.now().isoformat(timespec="seconds")},
            indent=2,
            sort_keys=True,
        )
    )
    tmp.replace(paths.OWNED)


def survey(cfg: Config) -> list[Posse]:
    """Estado de posse de cada arquivo gerenciado.

    Nao renderiza nada: compara o arquivo vivo com o selo, e so. E' de
    proposito — o levantamento precisa funcionar mesmo quando o render esta
    quebrado, que e' exatamente uma das horas em que se quer saber quem mexeu
    em que.
    """
    selo = read_seal()
    out = []
    for name, target in sorted(services.targets(cfg).items()):
        dono = services.owner(name, cfg)
        path = paths.sys_path(target)
        entry = selo.get(name)
        vivo = digest(path)

        if entry is None:
            state = SEM_SELO
        elif not path.exists():
            state = AUSENTE
        elif not vivo:
            state = ILEGIVEL
        elif vivo == entry.get("sha256"):
            state = INTACTO
        else:
            state = DIVERGENTE

        out.append(
            Posse(
                name=name,
                target=target,
                service=dono.name if dono else "?",
                state=state,
                sealed=(entry or {}).get("sha256", ""),
                live=vivo,
            )
        )
    return out


def divergentes(cfg: Config) -> list[Posse]:
    return [p for p in survey(cfg) if p.divergiu]


def seal(cfg: Config) -> tuple[list[str], list[tuple[str, str]]]:
    """Sela o que estiver identico ao render. Devolve (selados, recusados).

    Recusado nao e' erro: e' o motor dizendo que aquele arquivo nao e' o que
    ele escreveria, e que portanto ele nao vai carimbar como se fosse.

    Entrada de selo de arquivo que deixou de ser possuido — WireGuard
    desligado, WAN discada removida — sai do mapa. Selo de arquivo que o motor
    nao gerencia mais nao e' informacao, e' lixo que um dia vira falso alarme.
    """
    rendered = render_all(cfg)
    anterior = read_seal()
    novo: dict[str, dict] = {}
    selados: list[str] = []
    recusados: list[tuple[str, str]] = []
    agora = datetime.now().isoformat(timespec="seconds")

    for name, target in sorted(services.targets(cfg).items()):
        path = paths.sys_path(target)
        esperado = rendered.get(name)

        if esperado is None:
            motivo = "o motor nao renderizou este arquivo nesta rodada"
        elif not path.exists():
            motivo = "arquivo ausente do sistema"
        else:
            try:
                igual = path.read_text() == esperado
            except OSError as exc:
                igual, motivo = False, f"nao consegui ler: {exc}"
            else:
                motivo = "" if igual else "conteudo difere do que o motor escreveria"

        if not motivo:
            novo[name] = {"target": target, "sha256": digest(path), "at": agora}
            selados.append(name)
        else:
            if name in anterior:
                novo[name] = anterior[name]
            recusados.append((name, motivo))

    _write_seal(novo)
    return selados, recusados


def stash(posses: list[Posse]) -> Path | None:
    """Guarda copia dos divergentes antes de eles serem sobrescritos.

    Edicao a mao pode estar errada, mas nunca e' descartavel: alguem a
    escreveu por um motivo, e as vezes o motivo era a casa estar fora do ar as
    onze da noite. Descartar sem guardar transforma o motor no acidente contra
    o qual ele deveria proteger.
    """
    alvos = [p for p in posses if p.state == DIVERGENTE and paths.sys_path(p.target).exists()]
    if not alvos:
        return None

    dest = paths.DRIFT / datetime.now().strftime("%Y%m%d-%H%M%S")
    dest.mkdir(parents=True, exist_ok=True)
    for p in alvos:
        shutil.copy2(paths.sys_path(p.target), dest / p.name)
    (dest / "ONDE.json").write_text(
        json.dumps({p.name: p.target for p in alvos}, indent=2, sort_keys=True)
    )
    return dest


# ---------------------------------------------------------------------------
# territorio: o que roda aqui e nao tem dono
# ---------------------------------------------------------------------------


DO_APPLIANCE = frozenset(
    {
        "fwadmin.service",
        "fwadmin-failover.service",
        "fwadmin-failover.timer",
        "nginx.service",
    }
)
"""Unidades do proprio produto. Tem dono — so nao e' um modulo de servico."""

IGNORAR_PREFIXO = (
    "systemd-",
    "getty@",
    "user@",
    "dbus",
    "apt-daily",
    "e2scrub",
    "dpkg-db-backup",
    "man-db",
    "console-setup",
    "keyboard-setup",
    "logrotate",
    "fstrim",
    "rsyslog",
    "cron",
    "anacron",
    "ntpsec",
    "chrony",
)
"""Encanamento do Debian, que nunca vai virar modulo de servico.

Deliberadamente curto, e o `ssh` nao esta nele: sshd numa caixa de borda e'
justamente o tipo de coisa que precisa ou entrar no motor, ou ser declarada
fora dele por escrito. Um inventario que esconde o que incomoda nao serve.
"""


@dataclass(frozen=True)
class Unidade:
    unit: str
    active: str = "unknown"
    enabled: str = "unknown"
    service: str = ""
    """Modulo dono, '' quando nao ha nenhum."""

    @property
    def orfa(self) -> bool:
        return not self.service


def _habilitadas() -> list[str]:
    saida = run(
        "systemctl", "list-unit-files", "--state=enabled", "--no-legend", "--no-pager",
        mutating=False,
    )
    if not saida.ok:
        return []
    nomes = []
    for linha in saida.output.splitlines():
        campos = linha.split()
        if campos and (campos[0].endswith(".service") or campos[0].endswith(".timer")):
            nomes.append(campos[0])
    return nomes


def _relevante(unit: str) -> bool:
    return not unit.startswith(IGNORAR_PREFIXO)


def territory(cfg: Config) -> list[Unidade]:
    """Unidades habilitadas nesta maquina, com o modulo dono de cada uma.

    O que sobra sem dono e' o roteiro de adocao da caixa: cada linha ali ou
    vira um modulo de servico, ou vira uma decisao escrita de deixar de fora.
    Enquanto essa lista nao estiver resolvida, o config.yaml afirma ser fonte
    da verdade de um sistema onde metade do /etc e' escrita a mao.

    Em sandbox devolve vazio: perguntar ao systemd ali mediria a maquina de
    quem esta testando, e nao a caixa em questao.
    """
    if paths.sandboxed():
        return []

    dono = dict(services.units(cfg))
    for unit in DO_APPLIANCE:
        dono.setdefault(unit, "appliance")

    out = []
    for unit in _habilitadas():
        if not _relevante(unit) and unit not in dono:
            continue
        out.append(
            Unidade(
                unit=unit,
                active=run("systemctl", "is-active", unit, mutating=False).output.strip(),
                enabled=run("systemctl", "is-enabled", unit, mutating=False).output.strip(),
                service=dono.get(unit, ""),
            )
        )

    # Unidade reivindicada por um modulo mas nao habilitada aparece assim
    # mesmo: WireGuard ligado no modelo e desabilitado no systemd e' um
    # descompasso que o inventario existe para mostrar.
    vistas = {u.unit for u in out}
    for unit, service in sorted(dono.items()):
        if unit not in vistas:
            out.append(
                Unidade(
                    unit=unit,
                    active=run("systemctl", "is-active", unit, mutating=False).output.strip(),
                    enabled=run("systemctl", "is-enabled", unit, mutating=False).output.strip(),
                    service=service,
                )
            )
    return sorted(out, key=lambda u: (u.orfa, u.unit))
