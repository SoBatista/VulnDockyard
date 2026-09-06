from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import self_test

ROOT = Path(__file__).resolve().parents[1]


def test_append_unrun_phases_records_every_field_and_preserves_results() -> None:
    phases = (
        self_test.Phase("passed", ("tool", "one"), 10),
        self_test.Phase("failed", ("tool", "two"), 20),
        self_test.Phase("unrun", ("tool", "three"), 30),
    )
    report = {
        "gates": [
            {
                "name": "passed",
                "result": "pass",
            },
            {
                "name": "failed",
                "result": "fail",
            },
        ]
    }

    self_test._append_unrun_phases(report, phases, "not run after failure")

    assert report["gates"][-1] == {
        "name": "unrun",
        "command": ["tool", "three"],
        "timeout_seconds": 30,
        "duration_seconds": 0.0,
        "result": "skip",
        "reason": "not run after failure",
        "exit_code": None,
        "diagnostic_tail": "",
    }
    assert [gate["name"] for gate in report["gates"]] == ["passed", "failed", "unrun"]


def test_self_test_launcher_rejects_unbounded_overall_watchdog() -> None:
    bash = shutil.which("bash")
    assert bash is not None
    environment = os.environ.copy()
    environment["VDY_SELF_TEST_TIMEOUT_SECONDS"] = "3601"

    result = subprocess.run(
        (bash, "scripts/self-test.sh"),
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "VDY_SELF_TEST_TIMEOUT_SECONDS must not exceed 3600 seconds.\n"


def test_full_gate_checks_the_installed_dependency_environment_once() -> None:
    phases = self_test._phases()

    matches = [phase for phase in phases if phase.name == "installed-environment-dependency-check"]
    assert len(matches) == 1
    assert matches[0].command[-1] == "scripts/check_environment.py"


def test_initialization_failure_checkpoint_cannot_retain_stale_passes() -> None:
    phases = (
        self_test.Phase("first", ("tool", "one"), 10),
        self_test.Phase("second", ("tool", "two"), 20),
    )
    report = self_test._initialization_failure_report(
        started_at=datetime.now(UTC),
        phases=phases,
        reason="RuntimeError: catalogue unavailable",
        version="1.0.0",
        commit="unavailable",
        tree="unavailable",
    )

    assert report["result"] == "fail"
    assert report["initialization"] == {
        "result": "fail",
        "reason": "RuntimeError: catalogue unavailable",
    }
    assert [gate["result"] for gate in report["gates"]] == ["skip", "skip"]
    assert all("initialization failed" in gate["reason"] for gate in report["gates"])
    assert report["residual_docker_resources"] == {
        "audit_error": [
            "not run because self-test initialization failed: RuntimeError: catalogue unavailable"
        ]
    }
    assert report["result_scope"] == "locally-applicable-gates"
    assert report["local_result"] == "fail"
    assert report["release_ready"] is False
    assert {blocker["scope"] for blocker in report["blockers"]} == {"local", "remote"}


def test_remote_bootstrap_gates_do_not_make_publication_circular() -> None:
    gates = self_test._remote_bootstrap_gates()
    required = {gate["gate"] for gate in gates if gate["required_before_release"]}
    post_release = {gate["gate"] for gate in gates if not gate["required_before_release"]}

    assert required == {
        "hosted CI and security workflows",
        "repository ruleset and private vulnerability reporting",
    }
    assert "GitHub release publication and artifact attestation" in post_release
    assert "manual published artifact and attestation verification" in post_release


def test_checkpoint_distinguishes_local_pass_from_release_readiness() -> None:
    report: dict[str, Any] = {
        "result": "pass",
        "gates": [{"name": "local", "result": "pass", "reason": ""}],
        "residual_docker_resources": {"containers": [], "networks": [], "volumes": []},
        "remote_bootstrap_gates": self_test._remote_bootstrap_gates(),
    }

    self_test._refresh_checkpoint_status(report)

    assert report["result"] == "pass"
    assert report["result_scope"] == "locally-applicable-gates"
    assert report["local_result"] == "pass"
    assert report["release_ready"] is False
    assert [blocker["gate"] for blocker in report["blockers"]] == [
        "hosted CI and security workflows",
        "repository ruleset and private vulnerability reporting",
    ]
    assert all(blocker["scope"] == "remote" for blocker in report["blockers"])


def test_smoke_checkpoint_loader_requires_a_terminal_machine_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(self_test, "ROOT", tmp_path)
    artifact = tmp_path / "artifacts"
    artifact.mkdir()
    report = {
        "schema_version": 1,
        "result": "pass",
        "pytest_exit_code": 0,
        "expected_runnable_labs": ["juice-shop"],
        "labs": [{"id": "juice-shop", "result": "pass"}],
        "failures": [],
    }
    (artifact / "smoke-report.json").write_text(json.dumps(report) + "\n", encoding="utf-8")

    assert self_test._load_smoke_report() == report

    report["result"] = "running"
    (artifact / "smoke-report.json").write_text(json.dumps(report) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="terminal contract"):
        self_test._load_smoke_report()


def test_final_residual_inventory_makes_the_checkpoint_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report: dict[str, object] = {"residual_docker_resources": None}
    monkeypatch.setattr(
        self_test,
        "_residual",
        lambda: {"containers": ["owned-container"], "networks": [], "volumes": []},
    )

    assert not self_test._record_final_residual_audit(report)
    assert report["residual_docker_resources"] == {
        "containers": ["owned-container"],
        "networks": [],
        "volumes": [],
    }
