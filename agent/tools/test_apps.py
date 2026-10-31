#!/usr/bin/env python3
"""Os aplicativos do catalogo: o motor escreve compose, unidade, vhost e o nome.

Roda num sysroot descartavel, sem root. Com o docker (e o plugin compose) no
PATH, o 'docker compose config' roda de verdade; o nginx -t, se houver nginx.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="fwadmin-apps.")
os.environ["FWADMIN_SYSROOT"] = SANDBOX
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from fwadmin import paths  # noqa: E402
from fwadmin.apply import build_plan  # noqa: E402
from fwadmin.models import Config  # noqa: E402
from fwadmin.render import load, render_all  # noqa: E402
from fwadmin.services import apps  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
pass_n = fail_n = 0


def check(label: str, got, want) -> None:
    global pass_n, fail_n
    if got == want:
        print(f"  \033[32mok\033[0m   {label}")
        pass_n += 1
    else:
        print(f"  \033[31mFALHA\033[0m {label}\n       esperado: {want}\n       obtido:   {got}")
        fail_n += 1


def build(apps_state: dict, containers: bool = True, keep_host: bool = False) -> Config:
    data = load(ROOT / "config" / "config.yaml").model_dump()
    if not keep_host:
        data["hosts"] = [h for h in data["hosts"] if h["name"] not in ("navidrome", "jellyfin")]
    data["containers"] = {"enabled": containers}
    data["apps"] = apps_state
    return Config.model_validate(data)


def refused(fn, text: str = "") -> bool:
    try:
        fn()
    except (ValidationError, ValueError) as exc:
        return text in str(exc)
    return False


ON = {"navidrome": {"enabled": True}}
OFF = {"navidrome": {"enabled": False}}

print("== schema ==")
check("fora do catalogo e' recusado", refused(lambda: build({"plex": {"enabled": True}}), "catalogo"), True)
check("sem containers e' recusado", refused(lambda: build(ON, containers=False), "containers"), True)
check("nome ja usado por um host da LAN e' recusado",
      refused(lambda: build(ON, keep_host=True), "navidrome.home.lan ja"), True)
check("desligado, o nome nao e' conferido", refused(lambda: build(OFF, keep_host=True)), False)

print("\n== nunca configurado: nada ==")
base = load(ROOT / "config" / "config.yaml")
check("sem alvos", apps.targets(base), {})

print("\n== ligado ==")
cfg = build(ON)
out = render_all(cfg)
comp = yaml.safe_load(out["app-compose-navidrome"])
svc = comp["services"]["navidrome"]
check("imagem por digest", "@sha256:" in svc["image"], True)
check("porta so em loopback", svc["ports"], ["127.0.0.1:4533:4533"])
check("musica so leitura", "/srv/aionas/Music:/music:ro" in svc["volumes"], True)
check("estado em /var/lib/aionas", "/var/lib/aionas/navidrome:/data" in svc["volumes"], True)
check("sem root, sem capability", (svc["user"], svc["cap_drop"]), ("2001:2001", ["ALL"]))
check("quem reinicia e' o systemd", svc["restart"], "no")
unit = out["app-unit-navidrome"]
check("unidade espera o Docker", "Requires=docker.service" in unit, True)
check("cria o estado com o dono certo",
      "install -d -m 0750 -o 2001 -g 2001 /var/lib/aionas/navidrome" in unit, True)
vhost = out["app-vhost-navidrome"]
check("vhost no IP da LAN, pelo nome",
      "listen 10.0.0.1:80;" in vhost and "server_name navidrome.home.lan;" in vhost, True)
check("so a LAN entra", ("allow 10.0.0.0/24;" in vhost, "deny all;" in vhost), (True, True))
check("o dnsmasq aponta o nome para o firewall",
      "address=/navidrome.home.lan/10.0.0.1" in out["dnsmasq.conf"], True)

vpn = build(ON)
data = vpn.model_dump()
data["wireguard"] = {"enabled": True, "address": "10.9.0.1/24"}
check("com a VPN, os peers entram tambem",
      "allow 10.9.0.0/24;" in render_all(Config.model_validate(data))["app-vhost-navidrome"], True)

plan = build_plan(cfg, None, paths.STAGING)
labels = [r.label for r in plan.reloads]
check("recarga: daemon-reload, subir, nginx (a imagem nao baixa no apply)",
      [lb for lb in labels if lb.startswith(("systemd", "Navidrome", "nginx"))],
      ["systemd (daemon-reload)", "Navidrome (subir)", "nginx (reload)"])
check("e o Docker antes do aplicativo",
      labels.index("Docker (restart)") < labels.index("Navidrome (subir)"), True)

compose_checks = [c for c in plan.checks if c.command.startswith("docker compose")]
if shutil.which("docker"):
    check("docker compose config aprova", [c.ok for c in compose_checks], [True])
nginx_checks = [c for c in plan.checks if c.command.startswith("nginx -t")]
if shutil.which("nginx"):
    check("nginx -t aprova o vhost", [c.ok for c in nginx_checks], [True])
else:
    check("sem nginx, o plano reprova dizendo isso",
          [("nao esta instalado" in c.output) for c in nginx_checks], [True])

print("\n== Jellyfin, com aceleracao de hardware ==")
check("aceleracao em aplicativo sem GPU e' recusada",
      refused(lambda: build({"navidrome": {"enabled": True, "hwaccel": True}}), "aceleracao"), True)
jf = build({"jellyfin": {"enabled": True, "hwaccel": True}, "navidrome": {"enabled": True}})
data = jf.model_dump()
out = render_all(jf)
svc = yaml.safe_load(out["app-compose-jellyfin"])["services"]["jellyfin"]
check("videos e musica so leitura",
      [v for v in svc["volumes"] if v.endswith(":ro")],
      ["/srv/aionas/Videos:/media/videos:ro", "/srv/aionas/Music:/media/music:ro"])
check("o /dev/dri entra", svc["devices"], ["/dev/dri:/dev/dri"])
check("com os gids numericos do host", svc["group_add"], [str(g) for g in apps.gpu_groups()])
unit = out["app-unit-jellyfin"]
check("config e cache criados com o dono do processo",
      ("-o 2002 -g 2002 /var/lib/aionas/jellyfin/config" in unit,
       "-o 2002 -g 2002 /var/lib/aionas/jellyfin/cache" in unit), (True, True))
sem = Config.model_validate({**data, "apps": {"jellyfin": {"enabled": True}}})
check("sem aceleracao, nada de /dev/dri",
      "devices" in yaml.safe_load(render_all(sem)["app-compose-jellyfin"])["services"]["jellyfin"], False)
check("dois aplicativos, dois nomes no DNS",
      sorted(n for n, _ in apps.records(jf)), ["jellyfin.home.lan", "navidrome.home.lan"])

print("\n== desligado depois de ligado ==")
off = build(OFF)
out = render_all(off)
check("os alvos continuam (o motor nao apaga)", len(apps.targets(off)), 3)
check("compose vira comentario", "services:" in out["app-compose-navidrome"], False)
check("vhost vira comentario", "server {" in out["app-vhost-navidrome"], False)
check("o nome sai do DNS", "navidrome.home.lan" in out["dnsmasq.conf"], False)
check("recarga para e desabilita, e recarrega o nginx",
      [r.argv for r in apps.reloads(off, cfg, ["app-compose-navidrome", "app-vhost-navidrome"])],
      [["systemctl", "disable", "--now", "azimuth-app-navidrome.service"],
       ["systemctl", "reload", "nginx"]])
check("rollback para a config ligada sobe de novo",
      "Navidrome (subir)" in [r.label for r in apps.rollback(cfg, ["app-compose-navidrome"])], True)

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
shutil.rmtree(SANDBOX, ignore_errors=True)
raise SystemExit(1 if fail_n else 0)
