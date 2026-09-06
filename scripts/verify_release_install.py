#!/usr/bin/env python3
"""Install the release wheel into a fresh venv and verify clean CLI invocation."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version import authoritative_version  # noqa: E402


def main() -> int:
    wheel = next((ROOT / "artifacts" / "release").glob("*.whl"), None)
    if wheel is None:
        print("release wheel is missing", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="vdy-clean-install-") as temporary:
        venv = Path(temporary) / "venv"
        subprocess.run(  # noqa: S603 - current interpreter and private temporary path
            (sys.executable, "-m", "venv", str(venv)), check=True, timeout=60
        )
        python = venv / "bin" / "python"
        subprocess.run(  # noqa: S603 - clean-venv interpreter and reviewed wheel path
            (
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--require-hashes",
                "-r",
                str(ROOT / "requirements-runtime.lock"),
            ),
            check=True,
            timeout=180,
        )
        subprocess.run(  # noqa: S603 - clean-venv interpreter and reviewed wheel path
            (str(python), "-m", "pip", "install", "--no-deps", str(wheel)),
            check=True,
            timeout=60,
        )
        subprocess.run(  # noqa: S603 - clean-venv interpreter
            (str(python), "-m", "pip", "check"),
            check=True,
            timeout=30,
        )
        version_result = subprocess.run(  # noqa: S603 - clean-venv interpreter
            (str(python), "-m", "vulndockyard", "version", "--json"),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if json.loads(version_result.stdout)["data"]["version"] != authoritative_version():
            print("clean-installed CLI version does not match", file=sys.stderr)
            return 1
        subprocess.run(  # noqa: S603 - clean-venv interpreter
            (str(python), "-m", "vulndockyard", "help"),
            check=True,
            stdout=subprocess.DEVNULL,
            timeout=30,
        )
        subprocess.run(  # noqa: S603 - clean-venv entry point
            (str(venv / "bin" / "vdy"), "version"),
            check=True,
            stdout=subprocess.DEVNULL,
            timeout=30,
        )
    print("clean release installation and both entry points passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
