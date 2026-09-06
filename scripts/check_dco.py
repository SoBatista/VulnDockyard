#!/usr/bin/env python3
"""Require every pull-request commit to carry its author's DCO sign-off."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SIGNOFF = re.compile(
    r"^Signed-off-by:\s*(?P<name>[^<>\r\n]+?)\s*<(?P<email>[^<>\s]+)>\s*$",
    flags=re.IGNORECASE | re.MULTILINE,
)


def _git() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("required executable is unavailable: git")
    return executable


def _commits(base_sha: str) -> tuple[str, ...]:
    if FULL_SHA.fullmatch(base_sha) is None:
        raise RuntimeError("pull-request base must be a full lowercase commit SHA")
    result = subprocess.run(  # noqa: S603 - validated revision and fixed git arguments
        (_git(), "rev-list", "--reverse", f"{base_sha}..HEAD"),
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
        timeout=15,
    )
    commits = tuple(line for line in result.stdout.splitlines() if line)
    if not commits:
        raise RuntimeError("pull request contains no commits relative to its base")
    if len(commits) > 500 or any(FULL_SHA.fullmatch(commit) is None for commit in commits):
        raise RuntimeError("pull-request commit inventory is malformed or exceeds 500 commits")
    return commits


def _commit_identity(commit: str) -> tuple[str, str, str]:
    if FULL_SHA.fullmatch(commit) is None:
        raise RuntimeError("commit identity requires a full lowercase SHA")
    result = subprocess.run(  # noqa: S603 - validated revision and fixed git arguments
        (_git(), "show", "-s", "--format=%an%x00%ae%x00%B", commit),
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    fields = result.stdout.split("\0", 2)
    if len(fields) != 3 or not fields[0].strip() or not fields[1].strip():
        raise RuntimeError(f"commit {commit} has malformed author metadata")
    return fields[0].strip(), fields[1].strip(), fields[2]


def _has_author_signoff(name: str, email: str, message: str) -> bool:
    expected_name = " ".join(name.split())
    expected_email = email.casefold()
    return any(
        " ".join(match.group("name").split()) == expected_name
        and match.group("email").casefold() == expected_email
        for match in SIGNOFF.finditer(message)
    )


def check() -> None:
    base_sha = os.environ.get("VDY_BASE_SHA", "")
    failures: list[str] = []
    for commit in _commits(base_sha):
        name, email, message = _commit_identity(commit)
        if not _has_author_signoff(name, email, message):
            failures.append(commit)
    if failures:
        raise RuntimeError(
            "commits lack a matching author DCO sign-off: "
            + ", ".join(commit[:12] for commit in failures)
        )


def main() -> int:
    try:
        check()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"DCO check failed: {exc}", file=sys.stderr)
        return 1
    print("pull-request commit DCO checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
