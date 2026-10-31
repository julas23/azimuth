"""O DDNS do proprio usuario, mantido pelo inadyn.

O projeto nao fornece nome nenhum: o usuario cadastra a conta dele num
provedor (DuckDNS, Cloudflare, No-IP...) e este modulo mantem o nome
apontando para o IP publico da WAN ativa.

O token fica num arquivo a parte, 0600, que o azimuth.conf puxa com
include(). Pelo mesmo motivo da senha do PPPoE: o arquivo principal aparece
no staging, no 'fwctl diff' e no backup, e segredo nao pode estar no que se
mostra.

Desligar nao apaga os arquivos (o motor nunca apaga): o azimuth.conf vira um
comentario, o arquivo de segredo perde o token, e a unidade e' parada e
desabilitada. Por isso os alvos existem desde que o DDNS foi configurado uma
vez, ligado ou nao.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import tempfile
from pathlib import Path

from fwadmin import paths, secretstore, status
from fwadmin.command import Result, run
from fwadmin.models import Config, DDNS
from fwadmin.services.base import Prova, Reload, ServiceModule

FILE = "inadyn.conf"
PATH = "/etc/inadyn/azimuth.conf"
SECRET = "inadyn-secret"
SECRET_PATH = "/etc/inadyn/azimuth.secret"
UNIT = "azimuth-ddns.service"

CURRENT_IP = re.compile(r"Current IP# (\S+)")


def _configured(cfg: Config | None) -> DDNS | None:
    """A secao, se o DDNS ja foi configurado alguma vez; None se nunca foi."""
    if cfg is None:
        return None
    d = cfg.ddns
    return d if (d.enabled or d.hostname) else None


def _on(cfg: Config | None) -> bool:
    d = _configured(cfg)
    return d is not None and d.enabled


def _ours(changed: list[str]) -> bool:
    return FILE in changed or SECRET in changed


def _inadyn() -> str | None:
    return shutil.which("inadyn") or ("/usr/bin/inadyn" if Path("/usr/bin/inadyn").exists() else None)


def targets(cfg: Config) -> dict[str, str]:
    return {FILE: PATH} if _configured(cfg) else {}


def secret_targets(cfg: Config) -> dict[str, str]:
    return {SECRET: SECRET_PATH} if _configured(cfg) else {}


def _quote(value: str) -> str:
    """String do libconfuse: entre aspas, com barra e aspas escapadas."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_secrets(cfg: Config) -> tuple[dict[str, str], list[str]]:
    """(conteudo do arquivo de segredo, ['ddns'] se o token falta).

    So o fwctl chama, como root, no build_plan. Sem usuario (DuckDNS), o token
    vai como usuario e a senha e' um enchimento que o provedor ignora.
    """
    d = _configured(cfg)
    if d is None:
        return {}, []
    head = "# gerado pelo fwadmin a partir de /etc/fwadmin/secrets.yaml\n"
    if not d.enabled:
        return {SECRET: head + "# DDNS desligado: nenhum segredo aqui\n"}, []
    token = secretstore.current().get(d.secret_ref)
    if not token:
        return {}, ["ddns"]
    if d.username:
        body = f"password = {_quote(token)}\n"
    else:
        body = f"username = {_quote(token)}\npassword = \"x\"\n"
    return {SECRET: head + body}, []


def units(cfg: Config) -> frozenset[str]:
    return frozenset({UNIT}) if _configured(cfg) else frozenset()


def context(cfg: Config, name: str) -> dict:
    return {"d": cfg.ddns, "secret_path": SECRET_PATH}


def _apply_state(cfg: Config | None) -> list[Reload]:
    if _on(cfg):
        return [
            Reload(
                "DDNS (inadyn)",
                ["sh", "-c", f"systemctl enable {UNIT} && systemctl restart {UNIT}"],
            )
        ]
    return [Reload("DDNS (desligar)", ["systemctl", "disable", "--now", UNIT])]


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    if not _configured(cfg) or not _ours(changed):
        return []
    return _apply_state(cfg)


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    """Volta ao estado da config anterior: ligado reinicia, desligado para."""
    if not _ours(files):
        return []
    return _apply_state(cfg)


def validate(staging: Path, names: list[str], cfg: Config) -> list[Result]:
    """inadyn --check-config, com o include apontado para o segredo do staging.

    O include do arquivo gerado aponta para /etc, onde o segredo novo ainda
    nao esta (ou nem existe, no primeiro apply). Validar contra ele mediria o
    arquivo velho, ou reprovaria por arquivo ausente.
    """
    d = _configured(cfg)
    if d is None or not d.enabled:
        return []
    tool = _inadyn()
    if tool is None:
        return [
            Result(
                False,
                "inadyn --check-config",
                "o inadyn nao esta instalado: instale pela tela de Servicos (DDNS) antes de aplicar",
            )
        ]
    conf = (staging / FILE).read_text()
    secret = staging / SECRET
    if not secret.exists():
        # Sem token o build_plan ja reprova com a mensagem certa.
        return []
    with tempfile.TemporaryDirectory(prefix="fwadmin-ddns.") as tmp:
        test = Path(tmp) / FILE
        test.write_text(conf.replace(SECRET_PATH, str(secret)))
        result = run(tool, "--check-config", "-f", str(test), mutating=False)
    return [Result(result.ok, f"inadyn --check-config {staging / FILE}", result.output)]


def _private(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return addr.is_private or addr in ipaddress.IPv4Network("100.64.0.0/10")


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """O provedor aceitou a atualizacao com as credenciais declaradas.

    Uma atualizacao forcada, de uma vez so (inadyn -1 --force), e nao uma
    consulta DNS: resolver o nome num servidor publico mediria o cache dele, e
    um TTL antigo reverteria uma configuracao correta. O inadyn sai com erro
    quando o provedor recusa (token errado, nome que nao e' da conta), e isso
    e' prova conclusiva. Falta de internet nao e': fica inconclusiva.

    IP da WAN privado (CGNAT ou modem roteando) entra como observacao: o nome
    aponta para o IP publico de quem esta na frente, e a VPN direta nao chega.
    """
    if not _ours(changed) or not _on(cfg):
        return None
    d = cfg.ddns
    esperado = f"{d.provider} aceitou a atualizacao de {d.hostname}"
    tool = _inadyn()
    if tool is None:
        return Prova.inconclusiva("ddns", esperado, "inadyn ausente")
    with tempfile.TemporaryDirectory(prefix="fwadmin-ddns.") as cache:
        result = run(
            tool, "-1", "--force", "-n", "-l", "info", f"--cache-dir={cache}",
            "-f", str(paths.sys_path(PATH)),
            timeout=60, mutating=False,
        )
    out = result.output
    if result.ok:
        ip = CURRENT_IP.search(out)
        visto = f"{d.hostname} -> {ip.group(1)}" if ip else "atualizado"
        wan = status.links().get(cfg.iface(cfg.routing.primary).ppp_device)
        if wan is not None and wan.address and _private(wan.address):
            visto += f"; a WAN tem IP privado ({wan.address}): CGNAT ou modem roteando, a VPN direta nao chega"
        return Prova.passou("ddns", esperado, visto)
    ultima = out.strip().splitlines()[-1] if out.strip() else "sem saida"
    if "Error response from DDNS server" in out or "response not OK" in out:
        return Prova.falhou("ddns", esperado, f"o provedor recusou: {ultima}")
    return Prova.inconclusiva("ddns", esperado, f"nao consegui falar com o provedor: {ultima}")


SERVICE = ServiceModule(
    name="ddns",
    order=50,  # depois da WAN e do WireGuard: precisa de saida para a internet
    section="ddns",
    targets=targets,
    secret_targets=secret_targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validate=validate,
    template_for=lambda name: "inadyn.conf.j2",
    context_for=context,
)
