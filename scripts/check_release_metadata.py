#!/usr/bin/env python3
"""Validate one live release-impact label and the matching exact SemVer increment."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version import check as check_version_projections  # noqa: E402

LABELS = {"release:major", "release:minor", "release:patch"}
ASSIGNMENT = re.compile(rb'^__version__ = "([^"]+)"$', re.MULTILINE)


def _executable(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise RuntimeError(f"required executable is unavailable: {name}")
    return value


def _version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise RuntimeError(f"not stable SemVer: {value}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def _base_version(base_sha: str) -> str | None:
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise RuntimeError("base commit must be a full lowercase SHA")
    result = subprocess.run(  # noqa: S603 - validated SHA, fixed git subcommand
        (_executable("git"), "show", f"{base_sha}:src/vulndockyard/_version.py"),
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    matches: list[bytes] = ASSIGNMENT.findall(result.stdout)
    if len(matches) != 1:
        raise RuntimeError("base branch has malformed authoritative version")
    return matches[0].decode()


def _bootstrap_release_is_ancestor(base_sha: str) -> bool:
    tag = subprocess.run(  # noqa: S603 - resolved Git executable and fixed arguments
        (_executable("git"), "rev-parse", "--verify", "refs/tags/v1.0.0^{commit}"),
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if tag.returncode != 0:
        return False
    relation = subprocess.run(  # noqa: S603 - validated SHA and fixed tag
        (
            _executable("git"),
            "merge-base",
            "--is-ancestor",
            tag.stdout.strip(),
            base_sha,
        ),
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=10,
    )
    return relation.returncode == 0


def _base_changelog_has_bootstrap_release(base_sha: str) -> bool:
    result = subprocess.run(  # noqa: S603 - validated SHA, fixed git subcommand
        (_executable("git"), "show", f"{base_sha}:CHANGELOG.md"),
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("could not inspect the base changelog release state")
    return (
        re.search(rb"^## \[1\.0\.0\] - \d{4}-\d{2}-\d{2}$", result.stdout, re.MULTILINE) is not None
    )


def _validate_reviewed_changelog(base: str, current: str, version: str) -> None:
    heading = re.compile(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", re.MULTILINE)
    if base == current:
        raise RuntimeError("release pull request must change CHANGELOG.md")
    if heading.search(base) is not None:
        raise RuntimeError(f"release {version} section already exists on the base branch")
    matches = list(heading.finditer(current))
    if len(matches) != 1:
        raise RuntimeError(f"release pull request must add one dated [{version}] section")
    start = matches[0].end()
    next_heading = re.search(r"^## ", current[start:], flags=re.MULTILINE)
    end = start + next_heading.start() if next_heading is not None else len(current)
    body = current[start:end].strip()
    if (
        re.search(r"^### \S", body, flags=re.MULTILINE) is None
        or re.search(r"^- \S", body, flags=re.MULTILINE) is None
    ):
        raise RuntimeError(f"release {version} section must contain reviewed categorized notes")
    release_link = f"[{version}]: https://github.com/SoBatista/VulnDockyard/releases/tag/v{version}"
    if release_link in base or current.count(release_link) != 1:
        raise RuntimeError(f"release {version} must add its exact immutable release link")


def _reviewed_changelog_increment(base_sha: str, version: str) -> None:
    result = subprocess.run(  # noqa: S603 - validated SHA, fixed git subcommand
        (_executable("git"), "show", f"{base_sha}:CHANGELOG.md"),
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("could not inspect base CHANGELOG.md")
    _validate_reviewed_changelog(
        result.stdout,
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
        version,
    )


def _live_labels() -> set[str]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    number = os.environ.get("VDY_PR_NUMBER", "")
    if repository != "SoBatista/VulnDockyard" or not number.isdigit():
        raise RuntimeError("trusted repository and pull-request context are required")
    result = subprocess.run(  # noqa: S603 - fixed gh command, numeric PR and exact repository
        (
            _executable("gh"),
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
    current = check_version_projections()
    base_sha = os.environ.get("VDY_BASE_SHA", "")
    base = _base_version(base_sha)
    if base is None:
        if current != "1.0.0":
            raise RuntimeError("the bootstrap tree must be exactly version 1.0.0")
        return
    if not _bootstrap_release_is_ancestor(base_sha):
        if current != "1.0.0" or base != "1.0.0":
            raise RuntimeError("pre-release bootstrap changes must remain exactly version 1.0.0")
        if _base_changelog_has_bootstrap_release(base_sha):
            raise RuntimeError(
                "released v1.0.0 tag is missing or is not an ancestor of the pull-request base"
            )
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
    _reviewed_changelog_increment(base_sha, current)


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
