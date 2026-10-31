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

import stat  # noqa: E402

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
        data["hosts"] = [
            h for h in data["hosts"] if h["name"] not in ("navidrome", "jellyfin", "immich", "nextcloud")
        ]
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
check("como aionas-data, sem capability", (svc["user"], svc["cap_drop"]), ("2000:2000", ["ALL"]))
check("quem reinicia e' o systemd", svc["restart"], "no")
unit = out["app-unit-navidrome"]
check("unidade espera o Docker", "Requires=docker.service" in unit, True)
check("cria o estado com o dono certo",
      "install -d -m 0750 -o 2000 -g 2000 /var/lib/aionas/navidrome" in unit, True)
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
check("com os gids numericos da GPU do host",
      svc["group_add"], [str(g) for g in apps.gpu_groups()])
unit = out["app-unit-jellyfin"]
check("config e cache criados com o dono do processo",
      ("-o 2000 -g 2000 /var/lib/aionas/jellyfin/config" in unit,
       "-o 2000 -g 2000 /var/lib/aionas/jellyfin/cache" in unit), (True, True))
sem = Config.model_validate({**data, "apps": {"jellyfin": {"enabled": True}}})
check("sem aceleracao, nada de /dev/dri",
      "devices" in yaml.safe_load(render_all(sem)["app-compose-jellyfin"])["services"]["jellyfin"], False)
check("dois aplicativos, dois nomes no DNS",
      sorted(n for n, _ in apps.records(jf)), ["jellyfin.home.lan", "navidrome.home.lan"])

print("\n== Immich: varios containers e senha gerada ==")
check("ML em aplicativo sem inferencia e' recusado",
      refused(lambda: build({"navidrome": {"enabled": True, "ml": True}}), "inferencia"), True)
im = build({"immich": {"enabled": True}})
out = render_all(im)
comp = yaml.safe_load(out["app-compose-immich"])["services"]
check("servidor, banco e cache; sem ML por padrao", sorted(comp), ["database", "immich", "redis"])
check("o servidor sabe que o ML esta desligado",
      comp["immich"]["environment"].get("IMMICH_MACHINE_LEARNING_ENABLED"), "false")
check("so o servidor publica porta", [n for n, v in comp.items() if "ports" in v], ["immich"])
check("todos como aionas-data e sem capability",
      {(v["user"], tuple(v["cap_drop"])) for v in comp.values()}, {("2000:2000", ("ALL",))})
check("biblioteca e' o Pictures", "/srv/aionas/Pictures:/data/library" in comp["immich"]["volumes"], True)
check("miniaturas no estado, nao no Pictures",
      "/var/lib/aionas/immich/thumbs:/data/thumbs" in comp["immich"]["volumes"], True)
check("a senha nao esta no compose", "PASSWORD=" in out["app-compose-immich"], False)
check("servidor e banco leem o env_file",
      [n for n, v in comp.items() if "env_file" in v], ["immich", "database"])
unit = out["app-unit-immich"]
check("Pictures e' de aionas-data, 2775 com setgid (STORAGE.md)",
      "install -d -m 2775 -o 2000 -g 2000 /srv/aionas/Pictures" in unit, True)
check("sem ACL", "setfacl" in unit, False)
check("o banco tem o diretorio dele", "-o 2000 -g 2000 /var/lib/aionas/immich/postgres" in unit, True)
check("tres imagens sem ML", len(apps.CATALOG["immich"].images()), 3)
check("quatro com ML", len(apps.CATALOG["immich"].images({"ml"})), 4)
ml = build({"immich": {"enabled": True, "ml": True}})
comp_ml = yaml.safe_load(render_all(ml)["app-compose-immich"])["services"]
check("com ML, o container de inferencia sobe", "machine-learning" in comp_ml, True)
check("e o servidor nao o desliga",
      "IMMICH_MACHINE_LEARNING_ENABLED" in comp_ml["immich"].get("environment", {}), False)
check("containers conversam entre si no firewall",
      "ip saddr 172.30.0.0/16 ip daddr 172.30.0.0/16 counter accept" in out["azimuth.nft"], True)

plan = build_plan(im, None, paths.STAGING)
sec = plan.rendered.get("app-secret-immich", "")
pw = sec.split("DB_PASSWORD=")[1].split("\n")[0] if "DB_PASSWORD=" in sec else ""
check("a senha nasce no primeiro plano, como segredo", ("app-secret-immich" in plan.secret, len(pw)), (True, 32))
check("a mesma senha para o servidor e o banco", f"POSTGRES_PASSWORD={pw}" in sec, True)
check("no staging, 0600", oct(stat.S_IMODE((paths.STAGING / "app-secret-immich").stat().st_mode)), "0o600")
check("nada que o painel renderiza a tem", any(pw in v for v in render_all(im).values()), False)
plan2 = build_plan(im, None, paths.STAGING)
check("e ela nao muda no plano seguinte", pw in plan2.rendered["app-secret-immich"], True)
if shutil.which("docker"):
    check("docker compose config aprova, com o segredo do staging",
          [c.ok for c in plan.checks if c.command.startswith("docker compose") and "immich" in c.command], [True])
check("so a senha mudou: o aplicativo reinicia",
      [r.label for r in apps.reloads(im, im, ["app-secret-immich"])], ["Immich (subir)"])

print("\n== Nextcloud ==")
nc = build({"nextcloud": {"enabled": True}})
out = render_all(nc)
comp = yaml.safe_load(out["app-compose-nextcloud"])["services"]
check("nginx, php-fpm, banco e cron; sem Redis", sorted(comp), ["app", "cron", "database", "nextcloud"])
check("so o nginx publica porta", [n for n, v in comp.items() if "ports" in v], ["nextcloud"])
check("o nginx le o codigo so para leitura",
      "/var/lib/aionas/nextcloud/html:/var/www/html:ro" in comp["nextcloud"]["volumes"], True)
check("e recebe o server block gerado",
      "/etc/azimuth/apps/nextcloud/nginx.conf:/etc/nginx/conf.d/default.conf:ro" in comp["nextcloud"]["volumes"], True)
check("php-fpm e cron montam as quatro pastas",
      [sorted(v for v in comp[s]["volumes"] if v.startswith("/srv/aionas/")) for s in ("app", "cron")],
      [sorted(f"/srv/aionas/{f}:/media/{f}" for f in ("Pictures", "Videos", "Music", "Documents"))] * 2)
check("todos como aionas-data", {v["user"] for v in comp.values()}, {"2000:2000"})
check("o nome e o pool da caixa entram no ambiente",
      (comp["app"]["environment"]["NEXTCLOUD_TRUSTED_DOMAINS"], comp["app"]["environment"]["TRUSTED_PROXIES"]),
      ("nextcloud.home.lan", "172.30.0.0/16"))
check("o cron roda o laco gerado", comp["cron"]["command"], ["sh", "/azimuth-cron.sh"])
check("os arquivos de configuracao sao alvos do motor",
      sorted(k for k in apps.targets(nc) if k.startswith("app-file-")),
      ["app-file-nextcloud-azimuth-cron.sh", "app-file-nextcloud-nginx.conf"])
check("o server block escuta na 8080 e passa o PHP ao app",
      ("listen 8080;" in out["app-file-nextcloud-nginx.conf"], "server app:9000 resolve;" in out["app-file-nextcloud-nginx.conf"]),
      (True, True))
check("o laco monta as quatro pastas",
      "for pasta in Pictures Videos Music Documents; do" in out["app-file-nextcloud-azimuth-cron.sh"], True)
check("tres imagens (php-fpm e cron dividem uma)", len(apps.CATALOG["nextcloud"].images()), 3)
check("Documents tambem e' criado de aionas-data",
      "install -d -m 2775 -o 2000 -g 2000 /srv/aionas/Documents" in out["app-unit-nextcloud"], True)
check("mudou so o server block: o Nextcloud reinicia",
      [r.label for r in apps.reloads(nc, nc, ["app-file-nextcloud-nginx.conf"])], ["Nextcloud (subir)"])
plan = build_plan(nc, None, paths.STAGING)
check("a senha do banco nasce e vai para o env_file",
      "POSTGRES_PASSWORD=" in plan.rendered.get("app-secret-nextcloud", ""), True)
if shutil.which("docker"):
    check("docker compose config aprova",
          [c.ok for c in plan.checks if c.command.startswith("docker compose") and "nextcloud" in c.command], [True])

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
