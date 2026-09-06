#!/usr/bin/env python3
"""Exercise the documented development install from an isolated local clone."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version import authoritative_version  # noqa: E402


def _run(argv: tuple[str, ...], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - resolved executables and private temporary paths
        argv,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def main() -> int:
    git = shutil.which("git")
    if git is None:
        print("required executable is unavailable: git", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="vdy-fresh-clone-") as temporary:
        root = Path(temporary)
        checkout = root / "vulndockyard"
        venv = root / "venv"
        try:
            _run(
                (
                    git,
                    "clone",
                    "--quiet",
                    "--no-hardlinks",
                    "--no-tags",
                    "--single-branch",
                    str(ROOT),
                    str(checkout),
                ),
                cwd=root,
                timeout=60,
            )
            _run((sys.executable, "-m", "venv", str(venv)), cwd=root, timeout=60)
            python = venv / "bin" / "python"
            _run(
                (
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--require-hashes",
                    "-r",
                    str(checkout / "requirements-dev.lock"),
                ),
                cwd=checkout,
                timeout=180,
            )
            _run(
                (
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-deps",
                    "--no-build-isolation",
                    "-e",
                    ".",
                ),
                cwd=checkout,
                timeout=90,
            )
            version = _run(
                (str(venv / "bin" / "vulndockyard"), "version", "--json"),
                cwd=checkout,
                timeout=30,
            )
            if json.loads(version.stdout)["data"]["version"] != authoritative_version():
                raise RuntimeError("fresh-clone CLI version does not match")
            _run((str(venv / "bin" / "vdy"), "help"), cwd=checkout, timeout=30)
            _run(
                (str(venv / "bin" / "vulndockyard"), "list", "--json"),
                cwd=checkout,
                timeout=30,
            )
        except (
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            KeyError,
            json.JSONDecodeError,
        ) as exc:
            print(f"fresh-clone development install failed: {exc}", file=sys.stderr)
            if isinstance(exc, subprocess.CalledProcessError):
                diagnostic = "\n".join(part for part in (exc.stdout, exc.stderr) if part)
                if diagnostic:
                    print(diagnostic[-8_000:], file=sys.stderr)
            return 1
    print("fresh-clone development installation and both entry points passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
