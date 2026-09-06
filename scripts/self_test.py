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
ACTIVE_PHASE_STARTED: float | None = None
ACTIVE_PHASES: tuple[Phase, ...] = ()
ACTIVE_REPORT: dict[str, Any] | None = None
SELF_TEST_STARTED: float | None = None


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
    reason = f"overall watchdog interrupted phase {ACTIVE_PHASE}"
    if ACTIVE_REPORT is not None:
        existing = {str(gate.get("name")) for gate in ACTIVE_REPORT["gates"]}
        active = next((phase for phase in ACTIVE_PHASES if phase.name == ACTIVE_PHASE), None)
        if active is not None and active.name not in existing:
            duration = 0.0
            if ACTIVE_PHASE_STARTED is not None:
                duration = round(time.monotonic() - ACTIVE_PHASE_STARTED, 3)
            ACTIVE_REPORT["gates"].append(
                {
                    "name": active.name,
                    "command": list(active.command),
                    "timeout_seconds": active.timeout,
                    "duration_seconds": duration,
                    "result": "fail",
                    "reason": reason,
                    "exit_code": 124,
                    "diagnostic_tail": reason,
                }
            )
        _append_unrun_phases(ACTIVE_REPORT, ACTIVE_PHASES, reason)
        ACTIVE_REPORT["result"] = "fail"
        ACTIVE_REPORT["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        if SELF_TEST_STARTED is not None:
            ACTIVE_REPORT["duration_seconds"] = round(time.monotonic() - SELF_TEST_STARTED, 3)
        ACTIVE_REPORT["watchdog"] = {
            "result": "fail",
            "phase": ACTIVE_PHASE,
            "reason": reason,
        }
        if ACTIVE_REPORT["residual_docker_resources"] is None:
            ACTIVE_REPORT["residual_docker_resources"] = {
                "audit_error": ["not run because the overall watchdog expired"]
            }
        _checkpoint(ACTIVE_REPORT)
    print(reason, file=sys.stderr)
    raise SystemExit(124)


@dataclasses.dataclass(frozen=True)
class Phase:
    name: str
    command: tuple[str, ...]
    timeout: int
    environment: dict[str, str] = dataclasses.field(default_factory=dict)


def _skipped_phase(phase: Phase, reason: str) -> dict[str, object]:
    return {
        "name": phase.name,
        "command": list(phase.command),
        "timeout_seconds": phase.timeout,
        "duration_seconds": 0.0,
        "result": "skip",
        "reason": reason,
        "exit_code": None,
        "diagnostic_tail": "",
    }


def _append_unrun_phases(report: dict[str, Any], phases: tuple[Phase, ...], reason: str) -> None:
    recorded = {str(gate.get("name")) for gate in report["gates"]}
    for phase in phases:
        if phase.name not in recorded:
            report["gates"].append(_skipped_phase(phase, reason))


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


def _record_final_residual_audit(report: dict[str, Any]) -> bool:
    """Record a final inventory and return whether no owned Docker resource remains."""
    try:
        inventory = _residual()
    except Exception as exc:
        report["residual_docker_resources"] = {"audit_error": [str(exc)]}
        return False
    report["residual_docker_resources"] = inventory
    return all(not identifiers for identifiers in inventory.values())


def _refresh_checkpoint_status(report: dict[str, Any]) -> None:
    """Keep local-gate and full-release readiness explicit in every checkpoint."""
    local_result = str(report.get("result", "running"))
    blockers: list[dict[str, str]] = []
    for gate in report.get("gates", []):
        if not isinstance(gate, dict) or gate.get("result") == "pass":
            continue
        blockers.append(
            {
                "scope": "local",
                "gate": str(gate.get("name", "unknown")),
                "result": str(gate.get("result", "unknown")),
                "reason": str(gate.get("reason", "required local gate did not pass")),
            }
        )
    residual = report.get("residual_docker_resources")
    if isinstance(residual, dict) and any(residual.values()):
        blockers.append(
            {
                "scope": "local",
                "gate": "final-residual-docker-resource-audit",
                "result": "fail",
                "reason": json.dumps(residual, sort_keys=True, separators=(",", ":")),
            }
        )
    for gate in report.get("remote_bootstrap_gates", []):
        if (
            not isinstance(gate, dict)
            or gate.get("required_before_release") is not True
            or gate.get("result") == "pass"
        ):
            continue
        blockers.append(
            {
                "scope": "remote",
                "gate": str(gate.get("gate", "unknown")),
                "result": str(gate.get("result", "unknown")),
                "reason": str(gate.get("reason", "required remote gate did not pass")),
            }
        )
    report["result_scope"] = "locally-applicable-gates"
    report["local_result"] = local_result
    report["blockers"] = blockers
    report["release_ready"] = local_result == "pass" and not blockers


def _checkpoint(report: dict[str, Any]) -> None:
    _refresh_checkpoint_status(report)
    artifact_root = ROOT / "artifacts"
    artifact_root.mkdir(mode=0o700, exist_ok=True)
    temporary = artifact_root / ".checkpoint.json.tmp"
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, artifact_root / "checkpoint.json")


def _load_smoke_report() -> dict[str, Any]:
    path = ROOT / "artifacts" / "smoke-report.json"
    if path.is_symlink():
        raise RuntimeError("smoke report is an unsafe symlink")
    raw = path.read_bytes()
    if len(raw) > 1_000_000 or b"\0" in raw:
        raise RuntimeError("smoke report is oversized or malformed")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("result") not in {"pass", "fail"}
        or not isinstance(value.get("expected_runnable_labs"), list)
        or not isinstance(value.get("labs"), list)
        or not isinstance(value.get("failures"), list)
    ):
        raise RuntimeError("smoke report has an invalid terminal contract")
    return value


def _run_phase(phase: Phase) -> dict[str, object]:
    global ACTIVE_PHASE, ACTIVE_PHASE_STARTED, ACTIVE_PROCESS

    ACTIVE_PHASE = phase.name
    started = time.monotonic()
    ACTIVE_PHASE_STARTED = started
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
        ACTIVE_PHASE_STARTED = None
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
        ACTIVE_PHASE_STARTED = None
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
            "installed-environment-dependency-check",
            (python, "scripts/check_environment.py"),
            30,
        ),
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
        Phase("repository-doc-lock-policy", (python, "scripts/check_repository.py"), 60),
        Phase("gitleaks-bootstrap", (python, "scripts/install_gitleaks.py"), 60),
        Phase("tracked-tree-and-history-secret-scan", (python, "scripts/secret_scan.py"), 120),
        Phase("workflow-policy", (python, "scripts/check_workflows.py"), 30),
        Phase("actionlint-bootstrap", (python, "scripts/install_actionlint.py"), 60),
        Phase("actionlint", (str(ROOT / ".tools" / "actionlint"), "-no-color"), 30),
        Phase("reproducible-release-build-and-sbom", (python, "scripts/release_artifacts.py"), 420),
        Phase("clean-release-install", (python, "scripts/verify_release_install.py"), 240),
        Phase(
            "fresh-clone-development-install",
            (python, "scripts/verify_fresh_clone.py"),
            300,
        ),
        Phase("docker-preflight", (python, "scripts/docker_gate.py", "preflight"), 30),
        Phase(
            "runnable-adapter-smoke-and-reference-equivalence",
            (python, "scripts/run_smoke_gate.py"),
            900,
            {"VDY_RUN_DOCKER_TESTS": "1"},
        ),
        Phase("residual-docker-resource-audit", ("scripts/docker-audit.sh",), 60),
        Phase("git-diff-check", ("git", "diff", "--check", "HEAD"), 30),
        Phase("clean-working-tree", (python, "scripts/verify_clean_tree.py"), 30),
    )


def _remote_bootstrap_gates() -> list[dict[str, object]]:
    return [
        {
            "gate": "hosted CI and security workflows",
            "result": "skip",
            "required_before_release": True,
            "reason": "not verified by this local command; inspect hosted CI for the exact commit",
        },
        {
            "gate": "repository ruleset and private vulnerability reporting",
            "result": "skip",
            "required_before_release": True,
            "reason": "GitHub repository settings cannot be proven by a local gate",
        },
        {
            "gate": "GitHub release publication and artifact attestation",
            "result": "skip",
            "required_before_release": False,
            "reason": "runs only during an explicitly approved stable release",
        },
        {
            "gate": "manual published artifact and attestation verification",
            "result": "skip",
            "required_before_release": False,
            "reason": "post-release verification requires genuinely published artifacts",
        },
        {
            "gate": "GHCR keyless signing",
            "result": "skip",
            "required_before_release": False,
            "reason": "no redistribution-authorized project-built image exists in 1.0.0",
        },
    ]


def _initialization_failure_report(
    *,
    started_at: datetime,
    phases: tuple[Phase, ...],
    reason: str,
    version: str,
    commit: str,
    tree: str,
) -> dict[str, Any]:
    skip_reason = f"not run because self-test initialization failed: {reason}"
    finished_at = datetime.now(UTC)
    report: dict[str, Any] = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "tree": tree,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": finished_at.isoformat().replace("+00:00", "Z"),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "result": "fail",
        "initialization": {"result": "fail", "reason": reason},
        "gates": [_skipped_phase(phase, skip_reason) for phase in phases],
        "labs": [],
        "images": [],
        "smoke": None,
        "residual_docker_resources": {"audit_error": [skip_reason]},
        "remote_bootstrap_gates": _remote_bootstrap_gates(),
    }
    _refresh_checkpoint_status(report)
    return report


def main() -> int:
    global ACTIVE_PHASES, ACTIVE_REPORT, SELF_TEST_STARTED

    os.chdir(ROOT)
    signal.signal(signal.SIGTERM, _overall_timeout)
    started_at = datetime.now(UTC)
    SELF_TEST_STARTED = time.monotonic()
    phases = _phases()
    ACTIVE_PHASES = phases
    version = "unavailable"
    commit = "unavailable"
    tree = "unavailable"
    try:
        version = authoritative_version()
        commit = _git("rev-parse", "HEAD")
        tree = _git("rev-parse", "HEAD^{tree}")
        labs, images = _inventory()
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        failure_report = _initialization_failure_report(
            started_at=started_at,
            phases=phases,
            reason=reason,
            version=version,
            commit=commit,
            tree=tree,
        )
        ACTIVE_REPORT = failure_report
        _checkpoint(failure_report)
        print(f"self-test initialization failed: {reason}", file=sys.stderr)
        print(f"Checkpoint: {ROOT / 'artifacts' / 'checkpoint.json'}")
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
        "smoke": None,
        "residual_docker_resources": None,
        "remote_bootstrap_gates": _remote_bootstrap_gates(),
    }
    _refresh_checkpoint_status(report)
    ACTIVE_REPORT = report
    _checkpoint(report)
    failed = False
    for index, phase in enumerate(phases):
        result = _run_phase(phase)
        if phase.name == "runnable-adapter-smoke-and-reference-equivalence":
            try:
                smoke = _load_smoke_report()
                report["smoke"] = smoke
                if result["result"] == "pass" and smoke["result"] != "pass":
                    result["result"] = "fail"
                    result["reason"] = "smoke accounting report did not pass"
                    result["exit_code"] = 1
            except (OSError, ValueError, RuntimeError) as exc:
                report["smoke"] = {"result": "fail", "reason": str(exc)}
                result["result"] = "fail"
                result["reason"] = f"smoke accounting unavailable: {exc}"
                result["exit_code"] = 1
        report["gates"].append(result)
        if result["result"] != "pass":
            failed = True
            _append_unrun_phases(
                report,
                phases[index + 1 :],
                f"not run because required gate {phase.name} failed",
            )
            _checkpoint(report)
            break
        _checkpoint(report)
    if not _record_final_residual_audit(report):
        failed = True
    report["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    report["duration_seconds"] = round((datetime.now(UTC) - started_at).total_seconds(), 3)
    report["result"] = "fail" if failed else "pass"
    _checkpoint(report)
    print(f"Checkpoint: {ROOT / 'artifacts' / 'checkpoint.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
