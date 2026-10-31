"""Os aplicativos do catalogo, cada um em container, atras do nginx.

Para cada aplicativo configurado o motor escreve tres arquivos:

  /etc/azimuth/apps/<app>/compose.yaml        o container, por digest
  /etc/systemd/system/azimuth-app-<app>.service  quem sobe e derruba
  /etc/nginx/sites-enabled/azimuth-app-<app>  o nome na LAN e na VPN

O container escuta so em 127.0.0.1; quem fala com a LAN e' o nginx, por nome
(<app>.<dominio>), e o dnsmasq aponta esse nome para o firewall. A unidade e'
gerada, e nao um template unico, porque cada aplicativo cria diretorios
proprios com dono proprio antes de subir.

Desligar nao apaga nada: o compose e o vhost viram comentario e a unidade e'
parada e desabilitada. Os dados em /var/lib/aionas/<app> ficam.
"""

from __future__ import annotations

import grp
import ipaddress
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from fwadmin.apps import CATALOG, AppSpec
from fwadmin import paths
from fwadmin.command import Result, run
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule, until

COMPOSE = "app-compose-"
UNIT = "app-unit-"
VHOST = "app-vhost-"
PREFIXES = (COMPOSE, UNIT, VHOST)


def compose_path(key: str) -> str:
    return f"/etc/azimuth/apps/{key}/compose.yaml"


def unit_name(key: str) -> str:
    return f"azimuth-app-{key}.service"


def fqdn(cfg: Config, key: str) -> str:
    return f"{key}.{cfg.dns.domain}"


def lan_ip(cfg: Config) -> str:
    return str(ipaddress.IPv4Interface(cfg.lan.ipv4.address).ip)


def records(cfg: Config) -> list[tuple[str, str]]:
    """(nome, ip) de cada aplicativo ligado, para o dnsmasq."""
    return [(fqdn(cfg, k), lan_ip(cfg)) for k, a in cfg.apps.items() if a.enabled]


def _key(name: str) -> str | None:
    for prefix in PREFIXES:
        if name.startswith(prefix):
            return name.removeprefix(prefix)
    return None


def _on(cfg: Config | None, key: str) -> bool:
    return cfg is not None and key in cfg.apps and cfg.apps[key].enabled


def targets(cfg: Config) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in cfg.apps:
        out[f"{COMPOSE}{key}"] = compose_path(key)
        out[f"{UNIT}{key}"] = f"/etc/systemd/system/{unit_name(key)}"
        out[f"{VHOST}{key}"] = f"/etc/nginx/sites-enabled/azimuth-app-{key}"
    return out


def units(cfg: Config) -> frozenset[str]:
    return frozenset(unit_name(k) for k in cfg.apps)


def template_for(name: str) -> str:
    if name.startswith(COMPOSE):
        return "app-compose.yaml.j2"
    if name.startswith(UNIT):
        return "app.service.j2"
    return "app-nginx.conf.j2"


def gpu_groups() -> list[int]:
    """GIDs dos grupos que abrem o /dev/dri no host (render e video).

    Numericos, e lidos do host: um nome no group_add seria resolvido no
    /etc/group de dentro da imagem, onde o gid do render e' outro.
    """
    out = []
    for name in ("render", "video"):
        try:
            out.append(grp.getgrnam(name).gr_gid)
        except KeyError:
            pass
    return out


def compose(spec: AppSpec, hwaccel: bool = False) -> dict:
    """O compose inteiro, montado como dado e serializado — nao texto colado."""
    body = _compose(spec)
    if spec.env:
        body["services"][spec.key]["environment"] = dict(spec.env)
    if hwaccel and spec.gpu:
        svc = body["services"][spec.key]
        svc["devices"] = ["/dev/dri:/dev/dri"]
        svc["group_add"] = [str(g) for g in gpu_groups()]
    return body


def _compose(spec: AppSpec) -> dict:
    return {
        "name": f"azimuth-{spec.key}",
        "services": {
            spec.key: {
                "image": spec.image,
                "user": f"{spec.uid}:{spec.uid}",
                # Quem reinicia e' o systemd: duas politicas brigariam.
                "restart": "no",
                "ports": [f"127.0.0.1:{spec.port}:{spec.port}"],
                "volumes": [
                    f"{m.host}:{m.container}{':ro' if m.readonly else ''}" for m in spec.mounts
                ],
                "security_opt": ["no-new-privileges:true"],
                "cap_drop": ["ALL"],
            }
        },
    }


def context_for(cfg: Config, name: str) -> dict:
    key = _key(name) or ""
    spec = CATALOG[key]
    allow = [str(ipaddress.IPv4Interface(cfg.lan.ipv4.address).network)] if cfg.lan.ipv4.address else []
    if cfg.wireguard.enabled and cfg.wireguard.address:
        allow.append(str(ipaddress.IPv4Interface(cfg.wireguard.address).network))
    return {
        "spec": spec,
        "on": _on(cfg, key),
        "compose_file": compose_path(key),
        "compose_body": yaml.safe_dump(
            compose(spec, key in cfg.apps and cfg.apps[key].hwaccel), sort_keys=False, allow_unicode=True
        ),
        "server_name": fqdn(cfg, key),
        "listen_ip": lan_ip(cfg) if cfg.lan.ipv4.address else "127.0.0.1",
        "allow": allow,
    }


def _keys(changed: list[str]) -> list[str]:
    out: list[str] = []
    for n in changed:
        k = _key(n)
        if k is not None and k not in out:
            out.append(k)
    return out


def _state(cfg: Config | None, key: str, files: set[str]) -> list[Reload]:
    """O que fazer com um aplicativo, dado o que mudou dele."""
    out: list[Reload] = []
    if f"{UNIT}{key}" in files:
        out.append(Reload("systemd (daemon-reload)", ["systemctl", "daemon-reload"]))
    unit = unit_name(key)
    if _on(cfg, key):
        if f"{COMPOSE}{key}" in files or f"{UNIT}{key}" in files:
            # A imagem ja esta na caixa: o validate exige. Baixar aqui faria o
            # apply depender da velocidade da internet, e uma imagem de
            # centenas de MB estouraria o tempo do painel no meio da transacao.
            out.append(
                Reload(
                    f"{CATALOG[key].name} (subir)",
                    ["sh", "-c", f"systemctl enable {unit} && systemctl restart {unit}"],
                )
            )
    else:
        out.append(Reload(f"{CATALOG[key].name} (desligar)", ["systemctl", "disable", "--now", unit]))
    if f"{VHOST}{key}" in files:
        out.append(Reload("nginx (reload)", ["systemctl", "reload", "nginx"]))
    return out


def _dedupe(reloads: list[Reload]) -> list[Reload]:
    seen: set[tuple[str, ...]] = set()
    out = []
    for r in reloads:
        if tuple(r.argv) not in seen:
            seen.add(tuple(r.argv))
            out.append(r)
    return out


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    files = set(changed)
    out: list[Reload] = []
    for key in _keys(changed):
        out.extend(_state(cfg, key, files))
    return _dedupe(out)


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    touched = set(files)
    out: list[Reload] = []
    for key in _keys(files):
        out.extend(_state(cfg, key, touched))
    return _dedupe(out)


def _nginx_test(vhost: Path) -> Result:
    """nginx -t de um vhost sozinho, dentro de uma config minima descartavel.

    O 'nginx -t' do sistema leria o vhost velho em /etc, e nao o do staging.
    """
    nginx = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)
    if nginx is None:
        return Result(False, f"nginx -t {vhost}", "o nginx nao esta instalado")
    with tempfile.TemporaryDirectory(prefix="fwadmin-nginx.") as tmp:
        conf = Path(tmp) / "nginx.conf"
        conf.write_text(
            f"pid {tmp}/nginx.pid;\nerror_log {tmp}/error.log;\n"
            f"events {{}}\nhttp {{\n  access_log off;\n  include {vhost};\n}}\n"
        )
        result = run(nginx, "-t", "-q", "-p", tmp, "-c", str(conf), mutating=False)
    return Result(result.ok, f"nginx -t {vhost}", result.output)


def _image_present(key: str) -> list[Result]:
    """A imagem precisa estar na caixa antes do apply.

    Quem baixa e' o 'fwctl servico baixar', disparado em segundo plano quando
    o aplicativo e' ligado no painel. Em sandbox nao se pergunta ao Docker da
    maquina de quem testa.
    """
    docker = shutil.which("docker")
    if docker is None or paths.sandboxed():
        return []
    spec = CATALOG[key]
    r = run(docker, "image", "inspect", "--format", "{{.Id}}", spec.image, mutating=False, timeout=15)
    if r.ok:
        return []
    if "Cannot connect" in r.output:
        why = "o Docker nao esta rodando: inicie-o em Servicos (Containers)"
    else:
        why = (
            f"a imagem do {spec.name} ainda nao esta nesta caixa. Ela comeca a baixar quando o "
            "aplicativo e' ligado; aguarde alguns minutos e aplique de novo"
        )
    return [Result(False, f"imagem do {spec.name}", why)]


def validate(staging: Path, names: list[str], cfg: Config) -> list[Result]:
    out: list[Result] = []
    for key in _keys(names):
        if not _on(cfg, key):
            continue
        if cfg.apps[key].hwaccel and not Path("/dev/dri").is_dir():
            out.append(Result(False, f"{CATALOG[key].name}: /dev/dri",
                              "aceleracao de hardware ligada, mas esta caixa nao tem /dev/dri (GPU Intel ou AMD)"))
        out.extend(_image_present(key))
        compose_file = staging / f"{COMPOSE}{key}"
        if compose_file.exists():
            docker = shutil.which("docker")
            if docker is None:
                out.append(Result(False, "docker compose config",
                                  "o Docker nao esta instalado: instale pela tela de Servicos (Containers)"))
            else:
                r = run(docker, "compose", "-f", str(compose_file), "config", "--quiet", mutating=False)
                if not r.ok and "is not a docker command" in r.output:
                    r = Result(False, r.command, "falta o docker-compose: apt install docker-compose")
                out.append(Result(r.ok, f"docker compose config {compose_file}", r.output))
        vhost = staging / f"{VHOST}{key}"
        if vhost.exists():
            out.append(_nginx_test(vhost))
    return out


def _get(url: str, host: str | None = None) -> tuple[int, str]:
    """(status, corpo) — ou (0, motivo) quando nem conectou."""
    req = urllib.request.Request(url, headers={"Host": host} if host else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - URL montada aqui
            return resp.status, resp.read(256).decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except (urllib.error.URLError, OSError) as exc:
        return 0, str(getattr(exc, "reason", exc))


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """Cada aplicativo ligado responde, direto e pelo nginx, pelo nome.

    Direto prova o container; pelo nginx, com o Host do aplicativo, prova o
    vhost — e' o caminho que o usuario usa. Um 200 so do container com o vhost
    quebrado deixaria o painel dizendo que funciona o que ninguem alcanca.
    """
    keys = [k for k in _keys(changed) if _on(cfg, k)]
    if not keys:
        return None
    esperado = "; ".join(f"{fqdn(cfg, k)} responde em {CATALOG[k].health}" for k in keys)

    def olhar() -> Prova:
        vistos, quebrados = [], []
        for k in keys:
            spec = CATALOG[k]
            code, body = _get(f"http://127.0.0.1:{spec.port}{spec.health}")
            if code != 200:
                quebrados.append(f"{spec.name} direto: {code or body}")
                continue
            if spec.health_body and body != spec.health_body:
                quebrados.append(f"{spec.name} direto: respondeu {body!r}, ainda nao {spec.health_body!r}")
                continue
            code, body = _get(f"http://{lan_ip(cfg)}{spec.health}", host=fqdn(cfg, k))
            if code != 200:
                quebrados.append(f"{spec.name} pelo nginx: {code or body}")
                continue
            vistos.append(f"{spec.name} 200 direto e pelo nginx")
        if quebrados:
            return Prova.falhou("apps", esperado, "; ".join(quebrados))
        return Prova.passou("apps", esperado, "; ".join(vistos))

    # 90s: o Jellyfin roda as migracoes do banco na primeira subida.
    return until(90, olhar, interval=3)


SERVICE = ServiceModule(
    name="apps",
    order=70,  # depois do Docker, que precisa estar no ar
    section="apps",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validate=validate,
    template_for=template_for,
    context_for=context_for,
)
