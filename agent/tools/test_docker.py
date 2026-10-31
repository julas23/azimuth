#!/usr/bin/env python3
"""O Docker fora do firewall: o motor escreve o daemon.json e a regra de saida.

Roda num sysroot descartavel, sem root. Com o dockerd no PATH (ou em
/usr/sbin), a validacao nativa roda de verdade; sem ele, o plano reprova
pedindo a instalacao.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="fwadmin-docker.")
os.environ["FWADMIN_SYSROOT"] = SANDBOX
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import ValidationError  # noqa: E402

from fwadmin import paths  # noqa: E402
from fwadmin.apply import build_plan  # noqa: E402
from fwadmin.models import Config, Containers  # noqa: E402
from fwadmin.render import load, render_all  # noqa: E402
from fwadmin.services import docker  # noqa: E402

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


def refused(fn) -> bool:
    try:
        fn()
    except (ValidationError, ValueError):
        return True
    return False


def with_containers(**kw) -> Config:
    data = load(ROOT / "config" / "config.yaml").model_dump()
    data["containers"] = kw
    return Config.model_validate(data)


base = load(ROOT / "config" / "config.yaml")
lan_net = base.lan.ipv4.address

print("== schema ==")
check("pool publico e' recusado", refused(lambda: Containers(pool="8.8.0.0/16")), True)
check("rede maior que o pool e' recusada", refused(lambda: Containers(pool="172.30.0.0/24", subnet_size=16)), True)
check("pool que cruza a LAN e' recusado", refused(lambda: with_containers(enabled=True, pool=lan_net)), True)
check("docker0 no primeiro host do pool", Containers().bridge_ip, "172.30.0.1/24")
check("desligado, o pool nao e' conferido", refused(lambda: with_containers(enabled=False, pool=lan_net)), False)

print("\n== desligado: nada do Docker ==")
check("sem daemon.json", docker.targets(base), {})
nft = render_all(base)["azimuth.nft"]
check("sem regra de container no nftables", "containers" in nft, False)

print("\n== ligado ==")
cfg = with_containers(enabled=True)
out = render_all(cfg)
conf = json.loads(out[docker.FILE])
check("daemon.json e' JSON valido, sem iptables", conf["iptables"], False)
check("nem ip6tables", conf["ip6tables"], False)
check("redes do pool declarado", conf["default-address-pools"], [{"base": "172.30.0.0/16", "size": 24}])
check("docker0 declarado", conf["bip"], "172.30.0.1/24")
nft = out["azimuth.nft"]
check("forward deixa os containers sairem pela WAN",
      'ip saddr 172.30.0.0/16 oifname $WAN counter accept' in nft, True)
check("com NAT na WAN", 'oifname $WAN ip saddr 172.30.0.0/16 masquerade' in nft, True)
check("e so na WAN: nenhuma regra para a LAN",
      sum(1 for line in nft.splitlines() if "172.30.0.0/16" in line), 2)

plan = build_plan(cfg, None, paths.STAGING)
check("recarga reinicia o Docker",
      [r.argv for r in plan.reloads if r.label.startswith("Docker")],
      [["systemctl", "restart", "docker.service"]])
check("e o nftables antes dele",
      [r.label for r in plan.reloads].index("Docker (restart)")
      > min(i for i, r in enumerate(plan.reloads) if "nft" in " ".join(r.argv)), True)
docker_checks = [c for c in plan.checks if "dockerd" in c.command]
if docker._tool("dockerd"):
    check("dockerd --validate aprova", [c.ok for c in docker_checks], [True])
else:
    check("sem Docker, o plano pede a instalacao", [c.ok for c in docker_checks], [False])

print("\n== desligado depois de ligado ==")
check("daemon.json fica (o Docker continua fora do firewall)", docker.reloads(base, cfg, []), [])
check("a regra de saida some", "172.30.0.0/16" in render_all(base)["azimuth.nft"], False)

print(f"\n\033[1m{pass_n} passaram, {fail_n} falharam\033[0m")
shutil.rmtree(SANDBOX, ignore_errors=True)
raise SystemExit(1 if fail_n else 0)
