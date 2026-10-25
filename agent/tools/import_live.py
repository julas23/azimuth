#!/usr/bin/env python3
"""Linha de comando do importador; o codigo mora em fwadmin/importer.py.

    python3 tools/import_live.py legacy/live legacy/portal-index.html
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fwadmin.importer import *  # noqa: E402,F403
from fwadmin.importer import CHANGES, FINDINGS, build, main  # noqa: E402,F401

if __name__ == "__main__":
    raise SystemExit(main())
