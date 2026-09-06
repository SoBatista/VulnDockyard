#!/usr/bin/env python3
"""Validate one live release-impact label and the matching exact SemVer increment."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version import authoritative_version  # noqa: E402

LABELS = {"release:major", "release:minor", "release:patch"}
ASSIGNMENT = re.compile(rb'^__version__ = "([^"]+)"$', re.MULTILINE)


def _version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise RuntimeError(f"not stable SemVer: {value}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def _base_version(base_sha: str) -> str | None:
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise RuntimeError("base commit must be a full lowercase SHA")
    result = subprocess.run(  # noqa: S603 - validated SHA, fixed git subcommand
        ("git", "show", f"{base_sha}:src/vulndockyard/_version.py"),
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    matches = ASSIGNMENT.findall(result.stdout)
    if len(matches) != 1:
        raise RuntimeError("base branch has malformed authoritative version")
    return matches[0].decode()


def _live_labels() -> set[str]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    number = os.environ.get("VDY_PR_NUMBER", "")
    if repository != "SoBatista/VulnDockyard" or not number.isdigit():
        raise RuntimeError("trusted repository and pull-request context are required")
    result = subprocess.run(  # noqa: S603 - fixed gh command, numeric PR and exact repository
        (
            "gh",
            "api",
            "--paginate",
            f"repos/{repository}/issues/{number}/labels",
            "--jq",
            ".[].name",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def check() -> None:
    current = authoritative_version()
    base = _base_version(os.environ.get("VDY_BASE_SHA", ""))
    if base is None:
        if current != "1.0.0":
            raise RuntimeError("the bootstrap tree must be exactly version 1.0.0")
        return
    selected = _live_labels() & LABELS
    if len(selected) != 1:
        raise RuntimeError(
            "exactly one release:major, release:minor, or release:patch label is required"
        )
    old = _version(base)
    label = selected.pop()
    expected = {
        "release:major": (old[0] + 1, 0, 0),
        "release:minor": (old[0], old[1] + 1, 0),
        "release:patch": (old[0], old[1], old[2] + 1),
    }[label]
    if _version(current) != expected:
        expected_text = ".".join(str(part) for part in expected)
        raise RuntimeError(f"{label} requires exact version {expected_text}, found {current}")


def main() -> int:
    try:
        check()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"release metadata check failed: {exc}", file=sys.stderr)
        return 1
    print("release metadata is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
