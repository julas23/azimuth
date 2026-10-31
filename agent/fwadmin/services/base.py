"""A forma de um servico integrado.

O contrato de cinco passos — modelo, gerador, validador, recarga e
prova de funcao — deixa de ser combinado de prosa e vira estrutura: cada
servico e' um modulo que declara os campos abaixo, e o motor nao sabe mais
nada sobre servico nenhum em particular.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from pathlib import Path

from fwadmin.command import Result
from fwadmin.models import Config


@dataclass
class Reload:
    """Uma acao de recarga, com o peso que ela tem na conectividade."""

    label: str
    argv: list[str]
    disruptive: bool = False
    """True = derruba trafego enquanto roda (WAN ou LAN cai por instantes)."""


@dataclass(frozen=True)
class Prova:
    """Evidencia de que o servico voltou. Codigo de retorno nao conta.

    Tres estados, e nao dois. 'Nao consegui verificar' e' diferente de
    'verifiquei e esta quebrado': a primeira nao pode disparar rollback, senao
    uma caixa sem a ferramenta de diagnostico reverte um apply que deu certo.
    """

    service: str
    expected: str
    observed: str = ""
    ok: bool = False
    conclusive: bool = True

    @classmethod
    def passou(cls, service: str, expected: str, observed: str = "") -> Prova:
        return cls(service, expected, observed, ok=True)

    @classmethod
    def falhou(cls, service: str, expected: str, observed: str) -> Prova:
        return cls(service, expected, observed, ok=False)

    @classmethod
    def inconclusiva(cls, service: str, expected: str, motivo: str) -> Prova:
        return cls(service, expected, motivo, ok=False, conclusive=False)

    @property
    def fatal(self) -> bool:
        """So prova conclusiva e negativa derruba o apply."""
        return not self.ok and self.conclusive


def until(seconds: int, check: Callable[[], Prova], interval: float = 1.0) -> Prova:
    """Repete a verificacao ate o teto de tempo.

    Prova precisa de janela, nao de tiro unico: interface leva segundos para
    subir, lease de DHCP idem, e PPPoE negocia. Foi essa demora que produziu o
    incidente de 2026-08-21. Prova inconclusiva nao e' repetida — se a
    ferramenta nao existe, ela nao vai passar a existir esperando.
    """
    prova = check()
    deadline = time.monotonic() + seconds
    while prova.fatal and time.monotonic() < deadline:
        time.sleep(interval)
        prova = check()
    return prova


Targets = Callable[[Config], dict[str, str]]
Units = Callable[[Config], frozenset[str]]
Reloads = Callable[[Config, "Config | None", list[str]], list[Reload]]
Rollback = Callable[["Config | None", list[str]], list[Reload]]
Probe = Callable[[Config, "Config | None", list[str]], "Prova | None"]
Validate = Callable[["Path", list[str], Config], "list[Result]"]


@dataclass(frozen=True)
class ServiceModule:
    """Tudo que o motor precisa saber sobre um servico."""

    name: str
    """Identificador estavel: aparece no manifesto, no log e na UI."""

    order: int
    """Posicao na sequencia de aplicacao.

    Campo, e nao acaso. Antes deste registro a ordem existia na sequencia em
    que os 'if' tinham sido escritos — interface antes de nftables, nftables
    antes de dnsmasq, PPPoE depois da interface fisica porque o rp-pppoe
    recusa o nome enquanto o link nao subiu. Um registro que perdesse isso
    quebraria em silencio, e o sintoma so apareceria na caixa do usuario.
    """

    section: str
    """O pedaco do modelo que este servico le. Documental."""

    targets: Targets
    """Config -> {nome_do_render: caminho_no_sistema}."""

    reloads: Reloads
    """O que recarregar, dado o que mudou de fato."""

    rollback: Rollback
    """Recargas do caminho de volta: nao ha diff, reaplica o que foi tocado."""

    secret_targets: Targets | None = None
    """Config -> {nome: caminho} dos arquivos de segredo deste servico.

    Ficam fora de 'targets' porque o render_all (o que o painel mostra) nao
    pode produzi-los: so o fwctl, no build_plan. Mas sao do servico: token
    trocado sozinho tambem precisa de recarga e de prova de funcao.
    """

    units: Units = lambda cfg: frozenset()  # noqa: E731
    """Config -> unidades do systemd que este servico reivindica.

    Existe para o inventario poder responder "o que roda nesta caixa e nao tem
    dono". Antes disso a resposta era uma tupla WATCHED escrita a mao no
    status.py — exatamente o tipo de lista paralela que o registro de servicos
    foi criado para matar, e que envelhece calada.

    E' funcao do config, e nao constante, porque o nome da unidade as vezes
    depende do modelo: o WireGuard reivindica wg-quick@<device>, e o device e'
    escolhido pelo usuario.
    """

    probe: Probe | None = None
    """A prova de funcao.

    Recebe o mesmo contexto das recargas — config, config anterior e o que
    mudou — porque prova precisa saber o que foi mexido. Provar o que nao
    mudou faria uma WAN reserva ja desconectada derrubar um apply de DNS.
    Devolve None quando nao ha nada a provar nesta rodada.
    """

    validator: tuple[str, ...] | None = None
    """Ferramenta nativa que aprova o arquivo, aplicada ao staging."""

    validate: Validate | None = None
    """Validacao propria, no lugar do 'validator', para quem precisa de mais
    que o arquivo sozinho: o unbound valida tambem a arvore do conf.d inteira,
    porque o erro mais provavel e' duplicata com um arquivo vizinho."""

    quiet: frozenset[str] = field(default_factory=frozenset)
    """Unidades sem dono que mexem neste servico sozinhas e que o fwctl pausa
    da recarga ate o confirm ou o rollback. Um healthcheck que reinicia o
    unbound no meio da prova de funcao faria a prova medir o restart dele."""

    executable: frozenset[str] = field(default_factory=frozenset)
    """Renders que vao para o disco com bit de execucao."""

    template_for: Callable[[str], str] | None = None
    """Nome do template Jinja, quando nao e' '<render>.j2'."""

    context_for: Callable[[Config, str], dict] | None = None
    """Variaveis extras do template, para servicos com um arquivo por item."""

    def template(self, name: str) -> str:
        return self.template_for(name) if self.template_for else f"{name}.j2"

    def context(self, cfg: Config, name: str) -> dict:
        return self.context_for(cfg, name) if self.context_for else {}
