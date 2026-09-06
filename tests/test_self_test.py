from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

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
