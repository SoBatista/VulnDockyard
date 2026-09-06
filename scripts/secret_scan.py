#!/usr/bin/env python3
"""Scan exactly the tracked release tree with the pinned Gitleaks binary."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_repository import tracked_files  # noqa: E402
from scripts.install_gitleaks import install  # noqa: E402


def scan() -> None:
    binary = install()
    with tempfile.TemporaryDirectory(prefix="vdy-secret-scan-") as temporary:
        staged = Path(temporary)
        for source in tracked_files():
            relative = source.relative_to(ROOT)
            target = staged / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        subprocess.run(  # noqa: S603 - checksum-pinned scanner and fixed arguments
            (
                str(binary),
                "dir",
                "--no-banner",
                "--no-color",
                "--redact=100",
                "--config",
                str(ROOT / ".gitleaks.toml"),
                "--timeout=45",
                str(staged),
            ),
            cwd=ROOT,
            check=True,
            timeout=60,
        )


def main() -> int:
    os.chdir(ROOT)
    try:
        scan()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"secret scan failed: {exc}", file=sys.stderr)
        return 1
    print("tracked release tree secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
