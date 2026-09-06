#!/usr/bin/env python3
"""Run every locally applicable 1.0.0 gate with bounded watchdogs and JSON evidence."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version import authoritative_version  # noqa: E402

ACTIVE_PROCESS: subprocess.Popen[str] | None = None
ACTIVE_PHASE = "initialization"
ACTIVE_REPORT: dict[str, Any] | None = None


def _terminate_active() -> None:
    if ACTIVE_PROCESS is None or ACTIVE_PROCESS.poll() is not None:
        return
    os.killpg(ACTIVE_PROCESS.pid, signal.SIGTERM)
    try:
        ACTIVE_PROCESS.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(ACTIVE_PROCESS.pid, signal.SIGKILL)
        ACTIVE_PROCESS.wait(timeout=10)


def _overall_timeout(signum: int, frame: object) -> None:
    del signum, frame
    _terminate_active()
    if ACTIVE_REPORT is not None:
        ACTIVE_REPORT["result"] = "fail"
        ACTIVE_REPORT["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        ACTIVE_REPORT["gates"].append(
            {
                "name": "overall-watchdog",
                "result": "fail",
                "reason": f"overall watchdog interrupted phase {ACTIVE_PHASE}",
            }
        )
        _checkpoint(ACTIVE_REPORT)
    print(f"overall watchdog interrupted phase {ACTIVE_PHASE}", file=sys.stderr)
    raise SystemExit(124)


@dataclasses.dataclass(frozen=True)
class Phase:
    name: str
    command: tuple[str, ...]
    timeout: int
    environment: dict[str, str] = dataclasses.field(default_factory=dict)


def _git(*arguments: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("required executable is unavailable: git")
    return subprocess.run(  # noqa: S603 - fixed local Git inspection arguments
        (git, *arguments),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.strip()


def _inventory() -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    from vulndockyard.catalogue import Catalogue

    labs: list[dict[str, object]] = []
    images: list[dict[str, str]] = []
    for lab in Catalogue().all():
        labs.append(
            {
                "id": lab.manifest.id,
                "status": lab.manifest.adapter_status.value,
                "reason": lab.manifest.status_reason,
            }
        )
        for image in lab.lock.images:
            images.append(
                {
                    "lab_id": lab.manifest.id,
                    "role": image.role,
                    "reference": image.reference,
                    "trust": lab.manifest.trust.value,
                }
            )
    return labs, images


def _residual() -> dict[str, list[str]]:
    from vulndockyard.docker import Docker

    values = Docker().managed_resources()
    return {f"{kind}s": sorted(identifiers) for kind, identifiers in values.items()}


def _checkpoint(report: dict[str, Any]) -> None:
    artifact_root = ROOT / "artifacts"
    artifact_root.mkdir(mode=0o700, exist_ok=True)
    temporary = artifact_root / ".checkpoint.json.tmp"
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, artifact_root / "checkpoint.json")


def _run_phase(phase: Phase) -> dict[str, object]:
    global ACTIVE_PHASE, ACTIVE_PROCESS

    ACTIVE_PHASE = phase.name
    started = time.monotonic()
    environment = os.environ.copy()
    environment.update(phase.environment)
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed reviewed phase argv
            phase.command,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        duration = round(time.monotonic() - started, 3)
        reason = f"could not start gate command: {type(exc).__name__}: {exc}"
        print(f"[FAIL] {phase.name} ({duration:.3f}s)\n{reason}")
        return {
            "name": phase.name,
            "command": list(phase.command),
            "timeout_seconds": phase.timeout,
            "duration_seconds": duration,
            "result": "fail",
            "reason": reason,
            "exit_code": None,
            "diagnostic_tail": reason,
        }
    ACTIVE_PROCESS = process
    timed_out = False
    try:
        output, _ = process.communicate(timeout=phase.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            output, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate(timeout=10)
    except BaseException:
        _terminate_active()
        raise
    finally:
        ACTIVE_PROCESS = None
    duration = round(time.monotonic() - started, 3)
    passed = process.returncode == 0 and not timed_out
    reason = ""
    if timed_out:
        reason = f"phase exceeded its {phase.timeout}s watchdog"
    elif process.returncode:
        reason = f"command exited {process.returncode}"
    print(f"[{('PASS' if passed else 'FAIL')}] {phase.name} ({duration:.3f}s)")
    if output and (not passed or os.environ.get("VDY_SELF_TEST_VERBOSE") == "1"):
        print(output[-12_000:])
    return {
        "name": phase.name,
        "command": list(phase.command),
        "timeout_seconds": phase.timeout,
        "duration_seconds": duration,
        "result": "pass" if passed else "fail",
        "reason": reason,
        "exit_code": process.returncode,
        "diagnostic_tail": output[-12_000:] if not passed else "",
    }


def _phases() -> tuple[Phase, ...]:
    python = sys.executable
    return (
        Phase("version-consistency", (python, "scripts/check_version.py"), 30),
        Phase(
            "formatting", (python, "-m", "ruff", "format", "--check", "src", "tests", "scripts"), 30
        ),
        Phase("lint", (python, "-m", "ruff", "check", "src", "tests", "scripts"), 60),
        Phase("static-typing", (python, "-m", "mypy", "src", "tests", "scripts"), 180),
        Phase(
            "unit-policy-contract-tests",
            (python, "-m", "pytest", "-m", "not docker and not smoke"),
            240,
        ),
        Phase("repository-secret-doc-lock-policy", (python, "scripts/check_repository.py"), 60),
        Phase("workflow-policy", (python, "scripts/check_workflows.py"), 30),
        Phase("actionlint-bootstrap", (python, "scripts/install_actionlint.py"), 60),
        Phase("actionlint", (str(ROOT / ".tools" / "actionlint"), "-no-color"), 30),
        Phase("reproducible-release-build-and-sbom", (python, "scripts/release_artifacts.py"), 420),
        Phase("clean-release-install", (python, "scripts/verify_release_install.py"), 240),
        Phase("docker-preflight", (python, "scripts/docker_gate.py", "preflight"), 30),
        Phase(
            "runnable-adapter-smoke-and-reference-equivalence",
            (python, "-m", "pytest", "-m", "docker and smoke", "--no-cov"),
            900,
            {"VDY_RUN_DOCKER_TESTS": "1"},
        ),
        Phase("residual-docker-resource-audit", ("scripts/docker-audit.sh",), 60),
        Phase("git-diff-check", ("git", "diff", "--check", "HEAD"), 30),
        Phase("clean-working-tree", (python, "scripts/verify_clean_tree.py"), 30),
    )


def main() -> int:
    global ACTIVE_REPORT

    os.chdir(ROOT)
    signal.signal(signal.SIGTERM, _overall_timeout)
    started_at = datetime.now(UTC)
    try:
        version = authoritative_version()
        commit = _git("rev-parse", "HEAD")
        tree = _git("rev-parse", "HEAD^{tree}")
        labs, images = _inventory()
    except Exception as exc:
        print(f"self-test initialization failed: {exc}", file=sys.stderr)
        return 1
    report: dict[str, Any] = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "tree": tree,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": None,
        "result": "running",
        "gates": [],
        "labs": labs,
        "images": images,
        "residual_docker_resources": None,
        "remote_bootstrap_gates": [
            {
                "gate": "hosted CI and security workflows",
                "result": "skip",
                "required_before_release": True,
                "reason": "cannot validate this candidate commit until it is pushed",
            },
            {
                "gate": "repository ruleset and private vulnerability reporting",
                "result": "skip",
                "required_before_release": True,
                "reason": "GitHub repository settings cannot be proven by a local gate",
            },
            {
                "gate": "GitHub artifact attestation and published artifact verification",
                "result": "skip",
                "required_before_release": True,
                "reason": "requires an explicitly approved stable release",
            },
            {
                "gate": "GHCR keyless signing",
                "result": "skip",
                "required_before_release": False,
                "reason": "no redistribution-authorized project-built image exists in 1.0.0",
            },
        ],
    }
    ACTIVE_REPORT = report
    _checkpoint(report)
    failed = False
    for phase in _phases():
        result = _run_phase(phase)
        report["gates"].append(result)
        _checkpoint(report)
        if result["result"] != "pass":
            failed = True
            break
    try:
        report["residual_docker_resources"] = _residual()
    except Exception as exc:
        report["residual_docker_resources"] = {"audit_error": [str(exc)]}
        failed = True
    report["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    report["duration_seconds"] = round((datetime.now(UTC) - started_at).total_seconds(), 3)
    report["result"] = "fail" if failed else "pass"
    _checkpoint(report)
    print(f"Checkpoint: {ROOT / 'artifacts' / 'checkpoint.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
