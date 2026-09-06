#!/usr/bin/env python3
"""Check the authoritative version and all reviewed projections."""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
LINK_DEFINITION = re.compile(r"^\[[^\]\n]+\]:\s+\S", re.MULTILINE)


def authoritative_version() -> str:
    path = ROOT / "src" / "vulndockyard" / "_version.py"
    matches = re.findall(
        r'^__version__ = "([^"]+)"$', path.read_text(encoding="utf-8"), flags=re.MULTILINE
    )
    if len(matches) != 1 or SEMVER.fullmatch(matches[0]) is None:
        raise RuntimeError("_version.py must contain one stable SemVer assignment")
    return str(matches[0])


def _changelog_section(changelog: str, heading: re.Pattern[str]) -> str:
    matches = list(heading.finditer(changelog))
    if len(matches) != 1:
        raise RuntimeError("changelog must contain exactly one matching section")
    start = matches[0].end()
    tail = changelog[start:]
    boundaries = [
        match.start()
        for pattern in (re.compile(r"^## ", re.MULTILINE), LINK_DEFINITION)
        if (match := pattern.search(tail)) is not None
    ]
    body = tail[: min(boundaries)] if boundaries else tail
    normalized = body.strip()
    return normalized + "\n" if normalized else ""


def target_changelog_notes(version: str, changelog: str) -> str:
    body = _changelog_section(
        changelog,
        re.compile(r"^## \[Unreleased\]\s*$", re.MULTILINE),
    )
    declaration = f"Target release: {version} (not yet released)."
    if not body.startswith(declaration):
        raise RuntimeError("unreleased changelog section lacks the exact target declaration")
    notes = body[len(declaration) :].strip()
    if not notes:
        raise RuntimeError(f"changelog has no target notes for {version}")
    return notes + "\n"


def release_changelog_notes(version: str, changelog: str) -> str:
    notes = _changelog_section(
        changelog,
        re.compile(
            rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}\s*$",
            re.MULTILINE,
        ),
    )
    if not notes:
        raise RuntimeError(f"changelog has no release notes for {version}")
    return notes


def validate_bootstrap_notes_moved(base: str, current: str, version: str) -> None:
    expected = target_changelog_notes(version, base)
    actual = release_changelog_notes(version, current)
    if actual != expected:
        raise RuntimeError(
            f"bootstrap release {version} must move the complete Unreleased notes intact"
        )
    unreleased = _changelog_section(
        current,
        re.compile(r"^## \[Unreleased\]\s*$", re.MULTILINE),
    )
    if unreleased:
        raise RuntimeError("bootstrap release must leave the Unreleased section empty")


def _validate_bootstrap_notes_from_history(version: str, current: str) -> None:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("required executable is unavailable: git")
    history = subprocess.run(  # noqa: S603 - fixed local history inspection
        (git, "log", "--first-parent", "--format=%H", "HEAD^", "--", "CHANGELOG.md"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.splitlines()
    if len(history) > 500:
        raise RuntimeError("bootstrap changelog history exceeds the 500-commit review bound")
    declaration = f"Target release: {version} (not yet released)."
    for commit in history:
        if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise RuntimeError("bootstrap changelog history returned a malformed commit")
        candidate = subprocess.run(  # noqa: S603 - validated commit, fixed Git arguments
            (git, "show", f"{commit}:CHANGELOG.md"),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        if declaration in candidate:
            validate_bootstrap_notes_moved(candidate, current, version)
            return
    raise RuntimeError("could not find the reviewed bootstrap target notes in Git history")


def _categorized(notes: str) -> bool:
    return (
        re.search(r"^### \S", notes, flags=re.MULTILINE) is not None
        and re.search(r"^- \S", notes, flags=re.MULTILINE) is not None
    )


def _projection_state(version: str, readme: str, changelog: str) -> str:
    target_badge = f"target--version-{version}-orange"
    target_declaration = f"Target version: `{version}` (unreleased; release gates incomplete)."
    released_badge = f"version-{version}-blue"
    released_declaration = f"Version: `{version}`"
    target_changelog_declaration = f"Target release: {version} (not yet released)."
    unreleased_target_link = "[Unreleased]: https://github.com/SoBatista/VulnDockyard/commits/main"
    release_headings = list(
        re.finditer(
            rf"^## \[{re.escape(version)}\] - (?P<date>\d{{4}}-\d{{2}}-\d{{2}})$",
            changelog,
            flags=re.MULTILINE,
        )
    )
    release_heading = release_headings[0] if len(release_headings) == 1 else None
    try:
        target_notes = target_changelog_notes(version, changelog)
    except RuntimeError:
        target_notes = ""
    try:
        release_body = release_changelog_notes(version, changelog)
    except RuntimeError:
        release_body = ""
    released_notes = _categorized(release_body)
    released_links = all(
        changelog.count(expected) == 1
        for expected in (
            f"[Unreleased]: https://github.com/SoBatista/VulnDockyard/compare/v{version}...HEAD",
            f"[{version}]: https://github.com/SoBatista/VulnDockyard/releases/tag/v{version}",
        )
    )
    target_state = (
        readme.count(target_badge) == 1
        and readme.count(target_declaration) == 1
        and released_badge not in readme
        and released_declaration not in readme
        and changelog.count(target_changelog_declaration) == 1
        and _categorized(target_notes)
        and release_heading is None
        and changelog.count(unreleased_target_link) == 1
        and f"[{version}]:" not in changelog
    )
    released_state = (
        readme.count(released_badge) == 1
        and readme.count(released_declaration) == 1
        and target_badge not in readme
        and target_declaration not in readme
        and target_changelog_declaration not in changelog
        and unreleased_target_link not in changelog
        and release_heading is not None
        and released_notes
        and released_links
    )
    if target_state:
        return "target"
    if released_state:
        assert release_heading is not None
        try:
            date.fromisoformat(release_heading.group("date"))
        except ValueError as exc:
            raise RuntimeError("changelog release date is not a calendar date") from exc
        return "released"
    raise RuntimeError(
        "README and changelog must consistently describe either an unreleased target or a "
        "dated release"
    )


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
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_documentation = (ROOT / "docs" / "release.md").read_text(encoding="utf-8")
    if f"vulndockyard-{version}-py3-none-any.whl" not in release_documentation:
        failures.append("release documentation does not project the authoritative version")
    if changelog.count("## [Unreleased]") != 1:
        failures.append("changelog must contain exactly one Unreleased section")
    projection_state = ""
    try:
        projection_state = _projection_state(version, readme, changelog)
    except RuntimeError as exc:
        failures.append(str(exc))
    classifiers = project.get("project", {}).get("classifiers", [])
    expected_classifier = (
        "Development Status :: 3 - Alpha"
        if projection_state == "target"
        else "Development Status :: 5 - Production/Stable"
    )
    if projection_state and expected_classifier not in classifiers:
        failures.append(
            f"{projection_state} package metadata must use the {expected_classifier!r} classifier"
        )
    contradictory_classifier = (
        "Development Status :: 5 - Production/Stable"
        if projection_state == "target"
        else "Development Status :: 3 - Alpha"
    )
    if projection_state and contradictory_classifier in classifiers:
        failures.append(
            f"{projection_state} package metadata must not use the "
            f"{contradictory_classifier!r} classifier"
        )
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


def check_release_ready() -> str:
    version = check()
    state = _projection_state(
        version,
        (ROOT / "README.md").read_text(encoding="utf-8"),
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
    )
    if state != "released":
        raise RuntimeError(f"version {version} is an unreleased target, not publication-ready")
    if version == "1.0.0":
        _validate_bootstrap_notes_from_history(
            version,
            (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
        )
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
