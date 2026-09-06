#!/usr/bin/env python3
"""Require HEAD to match index and working tree, excluding ignored gate artifacts."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    result = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.stdout:
        print("working tree is not clean:\n" + result.stdout, file=sys.stderr)
        return 1
    print("working tree is clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
