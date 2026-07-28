#!/usr/bin/env python3
"""Deprecated checkout-local shim for the installed shodan-skill command."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if sys.path and Path(sys.path[0]).resolve() == Path(__file__).resolve().parent:
    sys.path.pop(0)
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shodan_skill.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
