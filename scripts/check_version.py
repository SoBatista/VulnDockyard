#!/usr/bin/env python3
"""Check the authoritative version and all reviewed projections."""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from datetime import date
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
    return str(matches[0])


def _projection_state(version: str, readme: str, changelog: str) -> str:
    target_badge = f"target--version-{version}-orange"
    target_declaration = f"Target version: `{version}` (unreleased; release gates incomplete)."
    released_badge = f"version-{version}-blue"
    released_declaration = f"Version: `{version}`"
    target_changelog_declaration = f"Target release: {version} (not yet released)."
    unreleased_target_link = "[Unreleased]: https://github.com/SoBatista/VulnDockyard/commits/main"
    release_heading = re.search(
        rf"^## \[{re.escape(version)}\] - (?P<date>\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        flags=re.MULTILINE,
    )
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
