#!/usr/bin/env python3
"""Fail-closed repository, secret, image-lock, and documentation checks."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
BANNED_TOP_LEVEL = {
    "juice-shop",
    "webgoat",
    "crapi",
    "dvwa",
    "bwapp",
    "mutillidae",
    "vampi",
    "dvga",
    "wrongsecrets",
    "nodegoat",
    "railsgoat",
    "security-shepherd",
    "vulhub",
}
SECRET_PATTERNS = {
    "private key": re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"(?:ghp|github_pat)_[A-Za-z0-9_]{20,}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "machine home path": re.compile(
        r"(?:/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|"
        r"[A-Z]:\\\\Users\\\\[A-Za-z0-9._-]+\\\\)"
    ),
}


def tracked_files() -> tuple[Path, ...]:
    result = subprocess.run(
        ("git", "ls-files", "-z"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=10,
    )
    return tuple(ROOT / value.decode() for value in result.stdout.split(b"\0") if value)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path.relative_to(ROOT)} is not a JSON object")
    return value


def check() -> None:
    failures: list[str] = []
    files = tracked_files()
    if not files:
        failures.append("repository has no tracked files")
    for path in files:
        relative = path.relative_to(ROOT)
        if relative.parts and relative.parts[0].casefold() in BANNED_TOP_LEVEL:
            failures.append(f"vulnerable upstream source-tree path is tracked: {relative}")
        if path.is_symlink():
            failures.append(f"symlink is not reviewed for the release archive: {relative}")
            continue
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            failures.append(f"tracked file is absent: {relative}")
            continue
        if size > 1_048_576:
            failures.append(f"tracked file exceeds 1 MiB: {relative}")
        if path.suffix.casefold() not in TEXT_SUFFIXES or size > 1_048_576:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"tracked release file is not UTF-8 text: {relative}")
            continue
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                failures.append(f"possible {name} in {relative}")
    docs = (ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
    from vulndockyard.cli import build_parser

    commands = set(build_parser()._vdy_choices)
    missing_docs = sorted(
        name for name in commands if re.search(rf"`{re.escape(name)}(?:`|\s)", docs) is None
    )
    if missing_docs:
        failures.append(f"commands missing from docs/commands.md: {', '.join(missing_docs)}")
    manifest_root = ROOT / "src" / "vulndockyard" / "data" / "manifests"
    lock_root = ROOT / "src" / "vulndockyard" / "data" / "locks"
    for manifest_path in sorted(manifest_root.glob("*.json")):
        manifest = _load(manifest_path)
        lock = _load(lock_root / f"{manifest['id']}.lock.json")
        if manifest["adapter_status"] == "runnable":
            for image in lock["images"]:
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"]):
                    failures.append(f"runnable image is not digest-pinned: {manifest['id']}")
            if manifest["trust"]["level"] == "vulndockyard-built":
                license_review = str(manifest["license"]["redistribution"]).casefold()
                if not lock["source_sha256"] or not lock["build_recipe_revision"]:
                    failures.append(
                        f"project-built image lacks source/build lock: {manifest['id']}"
                    )
                if not any(word in license_review for word in ("permit", "allow", "apache", "mit")):
                    failures.append(
                        f"project-built image lacks redistribution authority: {manifest['id']}"
                    )
    if failures:
        raise RuntimeError("\n".join(failures))


def main() -> int:
    os.chdir(ROOT)
    try:
        check()
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"repository check failed:\n{exc}", file=sys.stderr)
        return 1
    print("repository policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
