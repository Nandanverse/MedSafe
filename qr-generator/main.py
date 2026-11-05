#!/usr/bin/env python3
"""TrueMed QR generator — entry point.

A shim, deliberately. All the logic lives in ``truemed_qr/cli.py`` so that the
CLI is importable and its tests can call ``main(["verify", "--wire", ...])``
directly instead of spawning a subprocess per case — faster, and a failing
assertion points at a line of Python rather than at a captured stdout blob.

Usage::

    python main.py keygen --out keys/
    python main.py demo --count 5 --out out/
    python main.py verify --image out/PARACETAMOL500MG_PARACIP500_2026_000001.png
    python main.py selftest

Run ``python main.py --help`` for the rest.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Running `python main.py` from inside qr-generator/ puts this directory on
# sys.path already, so the import below resolves. Running it from elsewhere
# (`python qr-generator/main.py`) does not, hence the explicit insert. Position 0
# rather than append so a stale `truemed_qr` installed in site-packages cannot
# shadow the working tree — a genuinely confusing failure to debug, because the
# code you are reading is not the code that runs.
sys.path.insert(0, str(Path(__file__).resolve().parent))

if sys.version_info < (3, 10):
    # `str | None` annotations are evaluated lazily thanks to
    # `from __future__ import annotations`, but `match` statements and several
    # stdlib behaviours are not. Fail with a sentence instead of a SyntaxError
    # traceback from a module three imports deep.
    sys.stderr.write(
        f"TrueMed needs Python 3.10 or newer; this is "
        f"{sys.version_info.major}.{sys.version_info.minor}.\n"
    )
    raise SystemExit(1)

from truemed_qr.cli import main  # noqa: E402  (must follow the sys.path insert)

if __name__ == "__main__":
    raise SystemExit(main())
