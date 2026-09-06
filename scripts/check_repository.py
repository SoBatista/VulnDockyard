#!/usr/bin/env python3
"""Fail-closed repository, secret, image-lock, and documentation checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

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
LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
EXACT_REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)
DIRECT_REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?"
    r"==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)
EXPECTED_MARKERS = {
    "colorama": "os_name == 'nt' or sys_platform == 'win32'",
    "librt": "platform_python_implementation != 'PyPy'",
    "tomli": "python_full_version <= '3.11'",
}
TRUSTED_PRECOMMIT = {
    "https://github.com/astral-sh/ruff-pre-commit": "1f1e8bf348ff38fc88619a38d3ca4d9c56abea49",
    "https://github.com/pre-commit/pre-commit-hooks": "3e8a8703264a2f4a69428a0aa4dcb512790b2c8c",
}


def tracked_files() -> tuple[Path, ...]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("required executable is unavailable: git")
    result = subprocess.run(  # noqa: S603 - resolved Git executable and fixed arguments
        (git, "ls-files", "-z"),
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


def _requirement_records(path: Path) -> tuple[str, ...]:
    records: list[str] = []
    current = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].strip() if continued else stripped
        current = f"{current} {fragment}".strip()
        if not continued:
            records.append(current)
            current = ""
    if current:
        raise RuntimeError(f"unterminated requirement continuation in {path.name}")
    return tuple(records)


def _dependency_lock_failures() -> list[str]:
    failures: list[str] = []
    path = ROOT / "requirements-dev.lock"
    if not path.is_file() or path.is_symlink():
        return ["requirements-dev.lock must be a regular file"]
    requirements: dict[str, tuple[str, set[str]]] = {}
    for record in _requirement_records(path):
        requirement_hashes = set(LOCK_HASH.findall(record))
        without_hashes = LOCK_HASH.sub("", record).strip()
        requirement, separator, marker = without_hashes.partition(";")
        requirement = requirement.strip()
        match = EXACT_REQUIREMENT.fullmatch(requirement)
        if match is None or not requirement_hashes:
            failures.append(f"unhashed or non-exact dependency lock entry: {record}")
            continue
        name = re.sub(r"[-_.]+", "-", match.group("name")).casefold()
        expected_marker = EXPECTED_MARKERS.get(name, "")
        if marker.strip() != expected_marker or bool(separator) != bool(expected_marker):
            failures.append(f"requirements-dev.lock has an unexpected marker for {name}")
        if name in requirements:
            failures.append(f"duplicate dependency lock entry: {name}")
            continue
        requirements[name] = (match.group("version"), requirement_hashes)

    uv_data = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    expected: dict[str, tuple[str, set[str]]] = {}
    for package in uv_data.get("package", []):
        if not isinstance(package, dict) or "version" not in package:
            continue
        source = package.get("source")
        if not isinstance(source, dict) or "registry" not in source:
            continue
        name = re.sub(r"[-_.]+", "-", str(package["name"])).casefold()
        artifact_hashes: set[str] = set()
        artifacts = [package.get("sdist"), *package.get("wheels", [])]
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            digest = artifact.get("hash")
            if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                artifact_hashes.add(digest.removeprefix("sha256:"))
        if not artifact_hashes:
            failures.append(f"uv.lock registry package has no SHA-256 artifacts: {name}")
        expected[name] = (str(package["version"]), artifact_hashes)

    if set(requirements) != set(expected):
        missing = sorted(set(expected) - set(requirements))
        extra = sorted(set(requirements) - set(expected))
        failures.append(f"requirements-dev.lock package mismatch: missing={missing}, extra={extra}")
    for name in sorted(set(requirements) & set(expected)):
        if requirements[name] != expected[name]:
            failures.append(f"requirements-dev.lock differs from uv.lock for {name}")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    direct_values = [
        *project.get("build-system", {}).get("requires", []),
        *project.get("project", {}).get("dependencies", []),
        *project.get("project", {}).get("optional-dependencies", {}).get("dev", []),
    ]
    for value in direct_values:
        match = DIRECT_REQUIREMENT.fullmatch(str(value))
        if match is None:
            failures.append(f"project dependency is not exactly pinned: {value}")
            continue
        name = re.sub(r"[-_.]+", "-", match.group("name")).casefold()
        locked = requirements.get(name)
        if locked is None or locked[0] != match.group("version"):
            failures.append(f"project dependency differs from requirements-dev.lock: {value}")
    return failures


def check() -> None:
    failures: list[str] = []
    failures.extend(_dependency_lock_failures())
    files = tracked_files()
    if not files:
        failures.append("repository has no tracked files")
    relative_files = {str(path.relative_to(ROOT)) for path in files}
    if "requirements-dev.lock" not in relative_files:
        failures.append("requirements-dev.lock is not tracked")
    for path in files:
        relative = path.relative_to(ROOT)
        if any(part.casefold() in BANNED_TOP_LEVEL for part in relative.parts[:-1]):
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
    precommit = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    repositories = precommit.get("repos", []) if isinstance(precommit, dict) else []
    configured = {
        str(item.get("repo")): str(item.get("rev"))
        for item in repositories
        if isinstance(item, dict)
    }
    if configured != TRUSTED_PRECOMMIT:
        failures.append("pre-commit repositories must match the reviewed full-SHA allowlist")
    docs = (ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
    from vulndockyard.cli import build_parser
    from vulndockyard.privilege import HELPER_SHA256

    helper = ROOT / "src" / "vulndockyard" / "data" / "helpers" / "vulndockyard-hosts"
    if hashlib.sha256(helper.read_bytes()).hexdigest() != HELPER_SHA256:
        failures.append("packaged privileged helper does not match its release checksum")
    for path in files:
        if path.suffix.casefold() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"sudo\s+(?:--\s+)?(?:\.venv/|python|[^\s]*/python)", text):
            relative = path.relative_to(ROOT)
            failures.append(f"unsafe elevation of user-writable Python is documented: {relative}")

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
