#!/usr/bin/env python3
"""Validate the installed Python dependency graph without requiring pip."""

from __future__ import annotations

import sys
from importlib import metadata

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


def failures() -> list[str]:
    installed: dict[str, str] = {}
    requirements: dict[str, tuple[str, ...]] = {}
    problems: list[str] = []
    for distribution in metadata.distributions():
        try:
            name = distribution.metadata["Name"].strip()
        except KeyError:
            problems.append("installed distribution has no package name")
            continue
        normalized = canonicalize_name(name)
        if normalized in installed and installed[normalized] != distribution.version:
            problems.append(f"multiple installed versions of {normalized}")
            continue
        installed[normalized] = distribution.version
        requirements[normalized] = tuple(distribution.requires or ())

    environment: dict[str, str] = {}
    for key, value in default_environment().items():
        if not isinstance(value, str):
            problems.append(f"dependency marker environment {key} is not textual")
            continue
        environment[key] = value
    environment["extra"] = ""
    for package in sorted(requirements):
        for raw in requirements[package]:
            try:
                requirement = Requirement(raw)
            except InvalidRequirement:
                problems.append(f"{package} declares an invalid requirement: {raw}")
                continue
            if requirement.marker is not None and not requirement.marker.evaluate(environment):
                continue
            dependency = canonicalize_name(requirement.name)
            installed_version = installed.get(dependency)
            if installed_version is None:
                problems.append(f"{package} requires missing dependency {dependency}")
                continue
            try:
                version = Version(installed_version)
            except InvalidVersion:
                problems.append(f"{dependency} has invalid installed version {installed_version}")
                continue
            if requirement.specifier and not requirement.specifier.contains(
                version, prereleases=True
            ):
                problems.append(
                    f"{package} requires {requirement}, but {dependency} {installed_version} "
                    "is installed"
                )
    return problems


def main() -> int:
    problems = failures()
    if problems:
        print("installed dependency check failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print("installed dependency graph is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
