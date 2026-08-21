#!/usr/bin/env python3
"""Renderiza o config.yaml num diretorio de staging e compara com o vivo.

    python3 tools/render.py                    # renderiza em build/
    python3 tools/render.py --diff             # renderiza e compara com legacy/live

A comparacao e' semantica, nao textual: comentarios e ordem nao importam, o
que importa e' o conjunto de diretivas efetivas. Se este diff sair limpo, o
modelo representa fielmente o firewall que ja esta rodando.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fwadmin.render import TARGETS, load, render_all  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def effective(text: str, comment: str = "#") -> list[str]:
    """Linhas que realmente contam: sem comentarios, sem branco, sem indentacao."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(comment):
            continue
        line = re.sub(r"\s+", " ", line)
        out.append(line)
    return out


def compare(name: str, generated: str, live_path: Path) -> tuple[int, list[str]]:
    """Diff semantico. Devolve (numero de diferencas, linhas do relatorio)."""
    if not live_path.exists():
        return 0, [f"  {name}: sem baseline viva para comparar (arquivo novo)"]

    new = effective(generated)
    old = effective(live_path.read_text())

    only_new = [line for line in new if line not in old]
    only_old = [line for line in old if line not in new]

    report = []
    if not only_new and not only_old:
        report.append(f"  {name}: identico ({len(new)} diretivas)")
    else:
        report.append(f"  {name}: {len(only_old)} a menos, {len(only_new)} a mais")
        for line in only_old:
            report.append(f"      - {line}")
        for line in only_new:
            report.append(f"      + {line}")
    return len(only_new) + len(only_old), report


def main() -> int:
    cfg = load(ROOT / "config" / "config.yaml")
    files = render_all(cfg)

    out_dir = ROOT / "build"
    out_dir.mkdir(exist_ok=True)
    for name, content in files.items():
        path = out_dir / name
        path.write_text(content)
        if name in ("wan-failover.sh",):
            path.chmod(0o755)

    print(f"{len(files)} arquivos renderizados em build/")
    for name in sorted(files):
        print(f"  {name:22s} -> {TARGETS[name]}")

    if "--diff" not in sys.argv:
        return 0

    print("\nDiff semantico contra o estado vivo:")
    live = ROOT / "legacy" / "live"
    total = 0
    for name in sorted(files):
        # o failover virou script novo; nao ha baseline equivalente linha a linha
        if name == "wan-failover.sh":
            continue
        baseline = live / name
        diffs, report = compare(name, files[name], baseline)
        total += diffs
        print("\n".join(report))

    print(
        f"\n{'SEM DIFERENCAS — o modelo reproduz o firewall atual' if not total else f'{total} diferencas para revisar'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
