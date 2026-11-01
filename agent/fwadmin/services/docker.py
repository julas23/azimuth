"""O Docker como substrato dos aplicativos, sem escrever no firewall.

O motor gera o /etc/docker/daemon.json com 'iptables: false' e o pool de
redes declarado; o nftables do motor (azimuth.nft) deixa os containers
sairem para a internet com NAT. O porque esta em models.Containers e no
STACK.md.

Desligar nao apaga o daemon.json: o Docker continua fora do firewall, que e'
o estado certo para esta caixa mesmo sem aplicativo nenhum. O que some e' a
regra de saida dos containers no nftables.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
from pathlib import Path

from fwadmin.command import Result, run
from fwadmin.models import Config, Containers
from fwadmin.services.base import Prova, Reload, ServiceModule, until

FILE = "daemon.json"
PATH = "/etc/docker/daemon.json"
UNIT = "docker.service"


def _on(cfg: Config | None) -> Containers | None:
    if cfg is None or not cfg.containers.enabled:
        return None
    return cfg.containers


def _tool(name: str) -> str | None:
    """dockerd mora em /usr/sbin, fora do PATH de quem nao e' root."""
    found = shutil.which(name)
    if found:
        return found
    for base in ("/usr/sbin", "/usr/bin"):
        if Path(base, name).exists():
            return f"{base}/{name}"
    return None


def daemon_config(c: Containers) -> dict:
    """O daemon.json inteiro. Cada chave tem dono aqui:

    iptables / ip6tables: o Docker nao escreve regra; o firewall e' do motor.
    ip-forward fica no padrao (o Docker liga o net.ipv4.ip_forward): na
      topologia atras do roteador a caixa pode nao encaminhar, e sem isso os
      containers nao saem. Ligar e' seguro porque o forward do motor e' drop.
    bip / default-address-pools: as redes saem do pool declarado, para a regra
      do firewall casar por endereco.
    userland-proxy: e' ele que publica a porta do container em 127.0.0.1 sem
      DNAT — sem iptables, o unico caminho do nginx ate o container.
    log-driver / log-opts: journald, para os logs dos aplicativos aparecerem
      onde os do resto da caixa ja estao, com a rotacao do journal.
    """
    return {
        "iptables": False,
        "ip6tables": False,
        "bip": c.bridge_ip,
        "default-address-pools": [{"base": c.pool, "size": c.subnet_size}],
        "userland-proxy": True,
        "log-driver": "journald",
    }


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH} if _on(cfg) else {}


def units(cfg: Config) -> frozenset[str]:
    return frozenset({UNIT}) if _on(cfg) else frozenset()


def context(cfg: Config, name: str) -> dict:
    return {"body": json.dumps(daemon_config(cfg.containers), indent=2)}


def _restart() -> Reload:
    # Reinicia os containers junto (voltam pela restart policy deles), mas
    # nao mexe na rede da casa: nao e' disruptivo no sentido do motor.
    # enable junto: a ISO deixa o Docker desligado ate o motor configurar.
    return Reload("Docker (restart)", ["sh", "-c", f"systemctl enable {UNIT} && systemctl restart {UNIT}"])


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    if not _on(cfg) or FILE not in changed:
        return []
    return [_restart()]


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    if FILE not in files:
        return []
    return [_restart()]


def validate(staging: Path, names: list[str], cfg: Config) -> list[Result]:
    """dockerd --validate: o proprio daemon le o arquivo e diz se aceita."""
    if not _on(cfg):
        return []
    tool = _tool("dockerd")
    if tool is None:
        return [
            Result(
                False,
                "dockerd --validate",
                "o Docker nao esta instalado: instale pela tela de Servicos (Containers) antes de aplicar",
            )
        ]
    result = run(tool, "--validate", "--config-file", str(staging / FILE), mutating=False)
    return [Result(result.ok, f"dockerd --validate --config-file {staging / FILE}", result.output)]


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """O Docker voltou, fora do firewall, com a rede no pool declarado.

    Tres coisas, e as tres conclusivas: o daemon responde; nenhuma cadeia
    DOCKER apareceu no ruleset (se aparecer, o daemon.json nao foi lido, e o
    Docker voltou a disputar o firewall); e o docker0 esta no endereco
    declarado, que e' a prova de que o pool vale.
    """
    c = _on(cfg)
    if c is None or FILE not in changed:
        return None
    esperado = f"Docker no ar, sem regra no firewall, docker0 em {c.bridge_ip}"
    docker = _tool("docker")
    if docker is None:
        return Prova.inconclusiva("docker", esperado, "cliente docker ausente")

    def olhar() -> Prova:
        versao = run(docker, "version", "--format", "{{.Server.Version}}", mutating=False, timeout=15)
        if not versao.ok:
            return Prova.falhou("docker", esperado, f"o daemon nao respondeu: {versao.output[-200:]}")
        ruleset = run("nft", "list", "ruleset", mutating=False, timeout=15)
        if not ruleset.ok:
            return Prova.inconclusiva("docker", esperado, "nao consegui ler o ruleset")
        if "chain DOCKER" in ruleset.output:
            return Prova.falhou("docker", esperado, "o Docker escreveu regras no firewall: o daemon.json nao valeu")
        rede = run(
            docker, "network", "inspect", "bridge",
            "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
            mutating=False, timeout=15,
        )
        gateway = rede.output.strip()
        if not rede.ok or not gateway:
            return Prova.inconclusiva("docker", esperado, "nao consegui ler a rede bridge")
        declarado = str(ipaddress.IPv4Interface(c.bridge_ip).ip)
        if gateway != declarado:
            return Prova.falhou("docker", esperado, f"docker0 em {gateway}, declarado {declarado}")
        return Prova.passou("docker", esperado, f"Docker {versao.output.strip()}, docker0 em {gateway}")

    return until(30, olhar, interval=2)


SERVICE = ServiceModule(
    name="docker",
    order=60,  # depois do nftables (regra de saida pronta) e da WAN
    section="containers",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validate=validate,
    template_for=lambda name: "daemon.json.j2",
    context_for=context,
)
