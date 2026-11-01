"""O resolvedor recursivo, atras do dnsmasq. O desenho esta no UNBOUND.md."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from fwadmin import paths, status
from fwadmin.command import Result, run
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule, until

FILE = "unbound.conf"
CONFD = "/etc/unbound/unbound.conf.d"
PATH = f"{CONFD}/azimuth.conf"
ABSORVIDO = "unbound-absorvido-"
"""Prefixo do render de cada arquivo que a adocao absorveu."""

TEMPLATE = Path(__file__).resolve().parent.parent / "etc_templates" / "unbound.conf.j2"


def _ours(changed: list[str]) -> bool:
    return any(n == FILE or n.startswith(ABSORVIDO) for n in changed)


def _tool(name: str) -> str:
    """As ferramentas do unbound ficam em /usr/sbin, fora do PATH de quem nao e' root."""
    return shutil.which(name) or (f"/usr/sbin/{name}" if Path(f"/usr/sbin/{name}").exists() else name)


def versao(cfg: Config) -> str:
    """O que o unbound responde em versao.azimuth TXT.

    Hash da secao do modelo e do texto do template, e nao do arquivo: o arquivo
    contem o proprio TXT, e o hash dele seria circular. Mudou o modelo ou o
    template, mudou a versao, e a prova sabe se o unbound carregou a nova.
    """
    data = json.dumps(cfg.resolver.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256((data + TEMPLATE.read_text()).encode()).hexdigest()[:12]


def targets(cfg: Config) -> dict[str, str]:
    if not cfg.resolver.enabled:
        return {}
    out = {FILE: PATH}
    for name in cfg.resolver.absorbed:
        out[f"{ABSORVIDO}{name}"] = f"{CONFD}/{name}"
    return out


def units(cfg: Config) -> frozenset[str]:
    return frozenset({"unbound.service"}) if cfg.resolver.enabled else frozenset()


def template_for(name: str) -> str:
    return "unbound-absorvido.conf.j2" if name.startswith(ABSORVIDO) else f"{name}.j2"


def context_for(cfg: Config, name: str) -> dict:
    return {"r": cfg.resolver, "versao": versao(cfg)}


def _restart() -> Reload:
    # enable junto: numa caixa nova o pacote veio desligado da ISO, e um
    # restart sem enable some no proximo boot.
    return Reload("unbound (restart)", ["sh", "-c", "systemctl enable unbound && systemctl restart unbound"])


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    """reload_keep_cache, que rele a config sem jogar o cache fora.

    Restart so para o que o unbound nao rele (escuta, threads, EDNS) e na
    primeira vez, quando ele ainda nao tinha esta config. Mudar o tamanho do
    cache tambem passa pelo reload_keep_cache: ele aplica e descarta o cache
    sozinho, sem restart (verificado no 1.26 do Debian 13).
    """
    if not _ours(changed):
        return []
    antes = previous.resolver if previous else None
    agora = cfg.resolver
    if (
        antes is None
        or not antes.enabled
        or (antes.listen, antes.threads, antes.edns_buffer_size)
        != (agora.listen, agora.threads, agora.edns_buffer_size)
    ):
        return [_restart()]
    return [Reload("unbound (reload_keep_cache)", [_tool("unbound-control"), "reload_keep_cache"])]


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    # Na volta, restart: o arquivo restaurado pode ser o absorvido de volta,
    # e o caminho de volta prefere o que funciona sempre ao que poupa cache.
    return [_restart()] if _ours(files) else []


def validate(staging: Path, names: list[str], cfg: Config) -> list[Result]:
    """O arquivo sozinho e a arvore que vai subir.

    Duas linhas 'interface:' iguais, uma aqui e outra num arquivo vizinho do
    conf.d, fazem o unbound nao subir, e o arquivo sozinho passa limpo. Por
    isso a segunda checagem monta, no staging, um unbound.conf que inclui o
    azimuth.conf novo mais o que continua no conf.d: exatamente o que vai
    valer. Os absorvidos entram como vao ficar, so com o aviso.
    """
    checkconf = _tool("unbound-checkconf")
    out = []
    if FILE in names:
        out.append(run(checkconf, str(staging / FILE), mutating=False))

    nossos = {"azimuth.conf", *cfg.resolver.absorbed}
    confd = paths.sys_path(CONFD)
    vizinhos = sorted(c for c in confd.glob("*.conf") if c.name not in nossos) if confd.is_dir() else []
    arvore = staging / "_unbound-arvore.conf"
    linhas = [f'include-toplevel: "{staging / FILE}"']
    linhas += [f'include-toplevel: "{c}"' for c in vizinhos]
    arvore.write_text("\n".join(linhas) + "\n")
    result = run(checkconf, str(arvore), mutating=False)
    out.append(
        Result(result.ok, f"unbound-checkconf (arvore: azimuth.conf + {len(vizinhos)} do conf.d)", result.output)
    )
    return out


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """O unbound responde, na porta certa, com a versao desta config.

    Nada aqui depende da internet: a versao e os bloqueios sao respondidos pelo
    proprio unbound. O DNSSEC precisa da WAN, entao entra so como informacao —
    WAN fora nao pode reverter uma mudanca de DNS.
    """
    if not _ours(changed):
        return None
    r = cfg.resolver
    esperado = versao(cfg)
    alvo = f"versao {esperado} em {r.listen}"

    def olhar() -> Prova:
        reply = status.dns_query("versao.azimuth", r.ip, r.port, "TXT")
        if reply is None:
            return Prova.falhou("unbound", alvo, f"sem resposta em {r.listen}")
        if esperado not in reply.txt:
            return Prova.falhou("unbound", alvo, f"responde, com a versao {', '.join(reply.txt) or '(nenhuma)'}")
        return Prova.passou("unbound", alvo, "carregou esta config")

    prova = until(10, olhar)
    if prova.fatal:
        return prova

    anteriores = {b.domain for b in previous.resolver.blocked if b.enabled} if previous else set()
    for b in r.blocked:
        if b.enabled and b.domain not in anteriores:
            reply = status.dns_query(b.domain, r.ip, r.port)
            if reply is None or reply.rcode != 3:
                return Prova.falhou("unbound", f"{b.domain} bloqueado", "nao respondeu NXDOMAIN")

    nota = "carregou esta config"
    if r.dnssec:
        ruim = status.dns_query("dnssec-failed.org", r.ip, r.port, timeout=4)
        bom = status.dns_query("cloudflare.com", r.ip, r.port, timeout=4)
        if ruim and bom and ruim.rcode == 2 and bom.authentic:
            nota += "; DNSSEC validando"
        else:
            nota += "; DNSSEC nao verificado (sem internet?)"
    return Prova.passou("unbound", alvo, nota)


SERVICE = ServiceModule(
    name="unbound",
    order=15,  # antes do dnsmasq, que pergunta a ele
    section="resolver",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validate=validate,
    template_for=template_for,
    context_for=context_for,
    quiet=frozenset({"dns-healthcheck.timer"}),
)
