#!/usr/bin/env python3
"""Backward-compatible entry point for the CorsOne package."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _run() -> int:
    from corsone.cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_run())
