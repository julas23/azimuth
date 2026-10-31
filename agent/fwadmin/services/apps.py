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

from fwadmin.apps import CATALOG, MEDIA_FOLDERS, AppSpec
from fwadmin import paths, secretstore
from fwadmin.command import Result, run
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule, until

COMPOSE = "app-compose-"
UNIT = "app-unit-"
VHOST = "app-vhost-"
SECRET = "app-secret-"
FILE = "app-file-"
PREFIXES = (COMPOSE, UNIT, VHOST, SECRET, FILE)


def compose_path(key: str) -> str:
    return f"/etc/azimuth/apps/{key}/compose.yaml"


def file_path(key: str, name: str) -> str:
    return f"/etc/azimuth/apps/{key}/{name}"


def secret_path(key: str) -> str:
    return f"/etc/azimuth/apps/{key}/secrets.env"


def secret_ref(key: str) -> str:
    return f"app-{key}"


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
    """O aplicativo dono de um render. Os de arquivo sao app-file-<app>-<nome>."""
    for prefix in PREFIXES:
        if name.startswith(prefix):
            rest = name.removeprefix(prefix)
            return rest.split("-", 1)[0] if prefix == FILE else rest
    return None


def _config_file(name: str):
    key = _key(name)
    for f in CATALOG[key].config_files:
        if name == f"{FILE}{key}-{f.name}":
            return f
    return None


def _on(cfg: Config | None, key: str) -> bool:
    return cfg is not None and key in cfg.apps and cfg.apps[key].enabled


def targets(cfg: Config) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in cfg.apps:
        out[f"{COMPOSE}{key}"] = compose_path(key)
        out[f"{UNIT}{key}"] = f"/etc/systemd/system/{unit_name(key)}"
        out[f"{VHOST}{key}"] = f"/etc/nginx/sites-enabled/azimuth-app-{key}"
        for f in CATALOG[key].config_files:
            out[f"{FILE}{key}-{f.name}"] = file_path(key, f.name)
    return out


def units(cfg: Config) -> frozenset[str]:
    return frozenset(unit_name(k) for k in cfg.apps)


def template_for(name: str) -> str:
    if name.startswith(FILE):
        return _config_file(name).template
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


def options(cfg: Config | None, key: str) -> set[str]:
    """As opcoes ligadas de um aplicativo (hoje so 'ml')."""
    if cfg is None or key not in cfg.apps:
        return set()
    return {"ml"} if cfg.apps[key].ml else set()


def _volumes(mounts) -> list[str]:
    return [f"{m.host}:{m.container}{':ro' if m.readonly else ''}" for m in mounts]


def _hardened(spec: AppSpec) -> dict:
    return {
        "user": f"{spec.uid}:{spec.uid}",
        # Quem reinicia e' o systemd: duas politicas brigariam.
        "restart": "no",
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
    }


def _files_for(spec: AppSpec, service: str) -> list[str]:
    return [
        f"{file_path(spec.key, f.name)}:{f.target}:ro" for f in spec.config_files if f.service == service
    ]


def _subst(env: dict[str, str], values: dict[str, str]) -> dict[str, str]:
    """{fqdn} e {pool} nos valores: o que depende da caixa, e nao do catalogo."""
    out = {}
    for k, v in env.items():
        for name, value in values.items():
            v = v.replace("{" + name + "}", value)
        out[k] = v
    return out


def compose(
    spec: AppSpec,
    hwaccel: bool = False,
    enabled: set[str] | frozenset[str] = frozenset(),
    values: dict[str, str] | None = None,
) -> dict:
    """O compose inteiro, montado como dado e serializado — nao texto colado."""
    values = values or {}
    main: dict = {"image": spec.image, **_hardened(spec)}
    main["ports"] = [f"127.0.0.1:{spec.port}:{spec.port}"]
    main["volumes"] = _volumes(spec.mounts) + _files_for(spec, spec.key)
    groups: list[int] = []
    env = _subst(spec.env, values)
    for opt, extra in spec.off_env.items():
        if opt not in enabled:
            env.update(extra)
    if env:
        main["environment"] = env
    if spec.secret:
        main["env_file"] = [secret_path(spec.key)]
    if hwaccel and spec.gpu:
        main["devices"] = ["/dev/dri:/dev/dri"]
        groups += gpu_groups()
    if groups:
        main["group_add"] = [str(g) for g in groups]

    services: dict = {spec.key: main}
    for side in spec.sidecars:
        if side.optional and side.optional not in enabled:
            continue
        svc: dict = {"image": side.image, **_hardened(spec)}
        if side.command:
            svc["command"] = list(side.command)
        volumes = _volumes(side.mounts) + _files_for(spec, side.name)
        if volumes:
            svc["volumes"] = volumes
        if side.env:
            svc["environment"] = _subst(side.env, values)
        if side.secret:
            svc["env_file"] = [secret_path(spec.key)]
        if side.shm_size:
            svc["shm_size"] = side.shm_size
        services[side.name] = svc
    if len(services) > 1:
        main["depends_on"] = [n for n in services if n != spec.key]
    return {"name": f"azimuth-{spec.key}", "services": services}


def secret_targets(cfg: Config) -> dict[str, str]:
    return {f"{SECRET}{k}": secret_path(k) for k in cfg.apps if CATALOG[k].secret_vars}


def render_secrets(cfg: Config) -> dict[str, str]:
    """O env_file de cada aplicativo que tem senha, gerando-a na primeira vez.

    So o fwctl chama, como root, no build_plan. A senha so circula entre os
    containers do proprio aplicativo; ninguem precisa digita-la, entao ela
    nasce aleatoria e fica em secrets.yaml, para o banco continuar abrindo
    depois de um reinstall do compose.
    """
    out = {}
    for key in cfg.apps:
        spec = CATALOG[key]
        if not spec.secret_vars:
            continue
        value = secretstore.ensure(secret_ref(key))
        lines = "".join(f"{var}={value}\n" for var in spec.secret_vars)
        out[f"{SECRET}{key}"] = "# gerado pelo fwadmin a partir de /etc/fwadmin/secrets.yaml\n" + lines
    return out


def context_for(cfg: Config, name: str) -> dict:
    key = _key(name) or ""
    spec = CATALOG[key]
    allow = [str(ipaddress.IPv4Interface(cfg.lan.ipv4.address).network)] if cfg.lan.ipv4.address else []
    if cfg.wireguard.enabled and cfg.wireguard.address:
        allow.append(str(ipaddress.IPv4Interface(cfg.wireguard.address).network))
    return {
        "spec": spec,
        "media_folders": MEDIA_FOLDERS,
        "on": _on(cfg, key),
        "compose_file": compose_path(key),
        "compose_body": yaml.safe_dump(
            compose(
                spec,
                key in cfg.apps and cfg.apps[key].hwaccel,
                options(cfg, key),
                {"fqdn": fqdn(cfg, key), "pool": cfg.containers.pool},
            ),
            sort_keys=False,
            allow_unicode=True,
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
        mine = {f"{COMPOSE}{key}", f"{UNIT}{key}", f"{SECRET}{key}"}
        mine |= {f"{FILE}{key}-{f.name}" for f in CATALOG[key].config_files}
        if mine & files:
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


def _image_present(key: str, enabled: set[str]) -> list[Result]:
    """A imagem precisa estar na caixa antes do apply.

    Quem baixa e' o 'fwctl servico baixar', disparado em segundo plano quando
    o aplicativo e' ligado no painel. Em sandbox nao se pergunta ao Docker da
    maquina de quem testa.
    """
    docker = shutil.which("docker")
    if docker is None or paths.sandboxed():
        return []
    spec = CATALOG[key]
    r = run(docker, "image", "inspect", "--format", "{{.Id}}", *spec.images(enabled),
            mutating=False, timeout=15)
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


def _compose_config(docker: str, compose_file: Path, secret: Path, key: str) -> Result:
    """docker compose config, com o env_file apontado para o segredo do staging.

    O compose gerado aponta para /etc, onde o segredo ainda nao existe no
    primeiro apply — e o compose recusa env_file ausente.
    """
    text = compose_file.read_text()
    if not secret.exists() or secret_path(key) not in text:
        return run(docker, "compose", "-f", str(compose_file), "config", "--quiet", mutating=False)
    with tempfile.TemporaryDirectory(prefix="fwadmin-compose.") as tmp:
        test = Path(tmp) / "compose.yaml"
        test.write_text(text.replace(secret_path(key), str(secret)))
        return run(docker, "compose", "-f", str(test), "config", "--quiet", mutating=False)


def validate(staging: Path, names: list[str], cfg: Config) -> list[Result]:
    out: list[Result] = []
    for key in _keys(names):
        if not _on(cfg, key):
            continue
        if cfg.apps[key].hwaccel and not Path("/dev/dri").is_dir():
            out.append(Result(False, f"{CATALOG[key].name}: /dev/dri",
                              "aceleracao de hardware ligada, mas esta caixa nao tem /dev/dri (GPU Intel ou AMD)"))
        out.extend(_image_present(key, options(cfg, key)))
        compose_file = staging / f"{COMPOSE}{key}"
        if compose_file.exists():
            docker = shutil.which("docker")
            if docker is None:
                out.append(Result(False, "docker compose config",
                                  "o Docker nao esta instalado: instale pela tela de Servicos (Containers)"))
            else:
                r = _compose_config(docker, compose_file, staging / f"{SECRET}{key}", key)
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
    secret_targets=secret_targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    validate=validate,
    template_for=template_for,
    context_for=context_for,
)
