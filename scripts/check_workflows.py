#!/usr/bin/env python3
"""Statically validate GitHub workflow pinning, permissions, and cost boundaries."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[0-9a-f]{40}$")
USES_LINE = re.compile(r"uses:\s*([^\s#]+)(?:\s+#\s*(v[^\s]+))?")
STANDARD_RUNNERS = {"ubuntu-24.04", "ubuntu-latest"}


class WorkflowLoader(yaml.SafeLoader):
    """YAML 1.2-like loader that does not coerce the key `on` to true."""


for first, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
    WorkflowLoader.yaml_implicit_resolvers[first] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]


def _walk(value: object) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        for item in value.values():
            found.extend(_walk(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk(item))
    return found


def check() -> None:
    failures: list[str] = []
    workflow_root = ROOT / ".github" / "workflows"
    paths = sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")))
    if not paths:
        failures.append("no GitHub workflows exist")
    for path in paths:
        try:
            document = yaml.load(
                path.read_text(encoding="utf-8"),
                Loader=WorkflowLoader,  # noqa: S506 - loader derives from SafeLoader
            )
        except yaml.YAMLError as exc:
            failures.append(f"{path.name}: invalid YAML: {exc}")
            continue
        if not isinstance(document, dict):
            failures.append(f"{path.name}: workflow root is not an object")
            continue
        events = document.get("on")
        event_names = {events} if isinstance(events, str) else set(events or {})
        if "pull_request_target" in event_names:
            failures.append(f"{path.name}: pull_request_target is forbidden")
        permissions = document.get("permissions")
        if (
            not isinstance(permissions, dict)
            or permissions.get("contents") != "read"
            or any(value != "read" for value in permissions.values())
        ):
            failures.append(f"{path.name}: default permissions must be explicit and read-only")
        jobs = document.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            failures.append(f"{path.name}: jobs must be a non-empty object")
            continue
        for job_name, raw_job in jobs.items():
            if not isinstance(raw_job, dict):
                failures.append(f"{path.name}:{job_name}: job is malformed")
                continue
            if raw_job.get("runs-on") not in STANDARD_RUNNERS:
                failures.append(f"{path.name}:{job_name}: only standard Ubuntu runners are allowed")
            timeout = raw_job.get("timeout-minutes")
            if not isinstance(timeout, int) or not 1 <= timeout <= 30:
                failures.append(f"{path.name}:{job_name}: bounded timeout-minutes is required")
            job_permissions = raw_job.get("permissions")
            if job_permissions is not None:
                allowed = {
                    ("security.yml", "codeql"): {
                        "contents": "read",
                        "security-events": "write",
                    },
                    ("release.yml", "publish"): {
                        "contents": "write",
                        "id-token": "write",
                        "attestations": "write",
                    },
                }.get((path.name, str(job_name)))
                if job_permissions != allowed:
                    failures.append(f"{path.name}:{job_name}: job permissions exceed policy")
        for mapping in _walk(document):
            uses = mapping.get("uses")
            if not isinstance(uses, str) or uses.startswith("./"):
                continue
            if "@" not in uses or not SHA.fullmatch(uses.rsplit("@", 1)[1]):
                failures.append(f"{path.name}: action is not full-SHA pinned: {uses}")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_LINE.search(line)
            if match and not match.group(1).startswith("./") and match.group(2) is None:
                failures.append(f"{path.name}:{line_number}: pinned action lacks version comment")
        if path.name == "release.yml":
            if event_names != {"workflow_dispatch"}:
                failures.append("release.yml: release must be manual-only")
            publish = jobs.get("publish", {})
            if not isinstance(publish, dict) or publish.get("environment") != "release":
                failures.append("release.yml: protected release environment is required")
            if "push" in event_names or "pull_request" in event_names:
                failures.append("release.yml: development events must never publish")
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"retention-days:\s*(\d+)", text):
            if int(match.group(1)) > 7:
                failures.append(f"{path.name}: artifact retention exceeds seven days")
    if failures:
        raise RuntimeError("\n".join(failures))


def main() -> int:
    try:
        check()
    except (OSError, RuntimeError) as exc:
        print(f"workflow policy check failed:\n{exc}", file=sys.stderr)
        return 1
    print("workflow policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
