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
ALLOWED_PIP_INSTALLS = {
    "python -m pip install --disable-pip-version-check --require-hashes -r requirements-dev.lock",
    "python -m pip install --disable-pip-version-check --no-deps --no-build-isolation -e .",
    "python -m pip install --disable-pip-version-check --no-deps --no-build-isolation .",
}
TRUSTED_ACTIONS = {
    "actions/attest-build-provenance": "4d101475d8b20a2381f78447822ac1eab6504dd8",
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/dependency-review-action": "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "github/codeql-action/analyze": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
    "github/codeql-action/init": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
}


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
                        "actions": "read",
                        "contents": "write",
                        "id-token": "write",
                        "attestations": "write",
                    },
                }.get((path.name, str(job_name)))
                if job_permissions != allowed:
                    failures.append(f"{path.name}:{job_name}: job permissions exceed policy")
            steps = raw_job.get("steps")
            if not isinstance(steps, list) or not steps:
                failures.append(f"{path.name}:{job_name}: steps must be a non-empty list")
                continue
            for step in steps:
                if not isinstance(step, dict):
                    failures.append(f"{path.name}:{job_name}: malformed workflow step")
                    continue
                run = step.get("run")
                if isinstance(run, str):
                    for line in run.splitlines():
                        command = line.strip()
                        if "pip install" in command and command not in ALLOWED_PIP_INSTALLS:
                            failures.append(
                                f"{path.name}:{job_name}: unsafe dependency installation: {command}"
                            )
                uses = step.get("uses")
                settings = step.get("with", {})
                if (
                    isinstance(uses, str)
                    and uses.startswith("actions/checkout@")
                    and isinstance(settings, dict)
                    and settings.get("persist-credentials") is True
                    and (path.name, str(job_name)) != ("release.yml", "publish")
                ):
                    failures.append(
                        f"{path.name}:{job_name}: persisted checkout credentials are forbidden"
                    )
        for mapping in _walk(document):
            uses = mapping.get("uses")
            if not isinstance(uses, str) or uses.startswith("./"):
                continue
            if "@" not in uses or not SHA.fullmatch(uses.rsplit("@", 1)[1]):
                failures.append(f"{path.name}: action is not full-SHA pinned: {uses}")
                continue
            action, digest = uses.rsplit("@", 1)
            if TRUSTED_ACTIONS.get(action) != digest:
                failures.append(f"{path.name}: action pin is not in the reviewed allowlist: {uses}")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_LINE.search(line)
            if match and not match.group(1).startswith("./") and match.group(2) is None:
                failures.append(f"{path.name}:{line_number}: pinned action lacks version comment")
        if path.name == "release.yml":
            if event_names != {"workflow_dispatch"}:
                failures.append("release.yml: release must be manual-only")
            build = jobs.get("build", {})
            publish = jobs.get("publish", {})
            if not isinstance(build, dict):
                failures.append("release.yml: isolated build job is required")
                build = {}
            if not isinstance(publish, dict) or publish.get("environment") != "release":
                failures.append("release.yml: protected release environment is required")
                publish = {}
            if build.get("permissions") is not None or build.get("environment") is not None:
                failures.append("release.yml: build job must be unprivileged and ungated")
            if publish.get("needs") != "build":
                failures.append("release.yml: publish job must consume the isolated build job")
            build_text = str(build)
            publish_text = str(publish)
            if "scripts/release.py prepare" not in build_text:
                failures.append("release.yml: build job must prepare the release payload")
            if "actions/upload-artifact@" not in build_text:
                failures.append("release.yml: build job must transfer a bounded artifact")
            if "actions/download-artifact@" not in publish_text:
                failures.append("release.yml: publish job must download the isolated artifact")
            if "actions/attest-build-provenance@" not in publish_text:
                failures.append("release.yml: publish job must attest the release payload")
            if "actions/setup-python@" in publish_text or re.search(
                r"(?:pip install|uv sync|python(?:3)? -m build|release\.py prepare)", publish_text
            ):
                failures.append(
                    "release.yml: privileged publish job installs or builds dependencies"
                )
            publish_runs = [
                step.get("run")
                for step in publish.get("steps", [])
                if isinstance(step, dict) and isinstance(step.get("run"), str)
            ]
            if publish_runs != ["python3 scripts/release.py publish"]:
                failures.append("release.yml: publish job may run only the stdlib publisher")
            if "push" in event_names or "pull_request" in event_names:
                failures.append("release.yml: development events must never publish")
        text = path.read_text(encoding="utf-8")
        if path.name == "ci.yml":
            smoke = jobs.get("docker-smoke", {})
            smoke_text = str(smoke)
            for required in (
                "github.event.before",
                "git cat-file -e",
                "0000000000000000000000000000000000000000",
                "run_smoke=true",
            ):
                if required not in smoke_text:
                    failures.append(
                        f"ci.yml: Docker smoke classifier lacks fail-closed marker: {required}"
                    )
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
