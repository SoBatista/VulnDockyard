#!/usr/bin/env python3
"""Check the authoritative version and all reviewed projections."""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def authoritative_version() -> str:
    path = ROOT / "src" / "vulndockyard" / "_version.py"
    matches = re.findall(
        r'^__version__ = "([^"]+)"$', path.read_text(encoding="utf-8"), flags=re.MULTILINE
    )
    if len(matches) != 1 or SEMVER.fullmatch(matches[0]) is None:
        raise RuntimeError("_version.py must contain one stable SemVer assignment")
    return matches[0]


def check() -> str:
    version = authoritative_version()
    failures: list[str] = []
    if (ROOT / "VERSION").read_text(encoding="utf-8") != f"{version}\n":
        failures.append("VERSION does not match the authoritative source")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if project.get("tool", {}).get("hatch", {}).get("version", {}).get("path") != (
        "src/vulndockyard/_version.py"
    ):
        failures.append("package metadata does not project the authoritative source")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for expected in (f"version-{version}-blue", f"Version: `{version}`"):
        if expected not in readme:
            failures.append(f"README version projection is missing: {expected}")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if changelog.count(f"## [{version}]") != 1:
        failures.append("changelog must contain exactly one current version section")
    spec = importlib.util.spec_from_file_location(
        "vulndockyard_version", ROOT / "src" / "vulndockyard" / "_version.py"
    )
    if spec is None or spec.loader is None:
        failures.append("CLI version module could not be loaded")
    else:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if getattr(module, "__version__", None) != version:
            failures.append("CLI version does not match")
    if failures:
        raise RuntimeError("; ".join(failures))
    return version


def main() -> int:
    try:
        version = check()
    except (OSError, RuntimeError, tomllib.TOMLDecodeError) as exc:
        print(f"version check failed: {exc}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
