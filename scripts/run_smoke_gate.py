#!/usr/bin/env python3
"""Run and account for every runnable adapter's required Docker smoke tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from vulndockyard.catalogue import Catalogue  # noqa: E402
from vulndockyard.models import AdapterStatus  # noqa: E402

REPORT = ROOT / "artifacts" / "smoke-report.json"


class SmokeAccounting:
    def __init__(self, expected: tuple[str, ...]) -> None:
        self.expected = expected
        self.collected: dict[str, list[str]] = {}
        self.outcomes: dict[str, str] = {}
        self.collection_errors: list[str] = []

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        for item in items:
            if (
                item.get_closest_marker("docker") is None
                or item.get_closest_marker("smoke") is None
            ):
                continue
            marker = item.get_closest_marker("lab_id")
            if (
                marker is None
                or len(marker.args) != 1
                or marker.kwargs
                or not isinstance(marker.args[0], str)
                or not marker.args[0]
            ):
                self.collection_errors.append(
                    f"{item.nodeid}: required lab_id marker must contain one non-empty string"
                )
                continue
            lab_id = marker.args[0]
            self.collected.setdefault(lab_id, []).append(item.nodeid)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when == "call":
            self.outcomes[report.nodeid] = report.outcome
        elif report.when == "setup" and report.skipped:
            self.outcomes[report.nodeid] = "skipped"


def _accounting_report(
    expected: tuple[str, ...],
    collected: dict[str, list[str]],
    outcomes: dict[str, str],
    collection_errors: list[str],
    pytest_exit_code: int,
) -> dict[str, Any]:
    labs: list[dict[str, object]] = []
    failures = list(collection_errors)
    unknown = sorted(set(collected) - set(expected))
    if unknown:
        failures.append("smoke tests declare non-runnable lab IDs: " + ", ".join(unknown))
    for lab_id in expected:
        nodes = sorted(collected.get(lab_id, []))
        values = [outcomes.get(node, "not-run") for node in nodes]
        counts = {name: values.count(name) for name in ("passed", "failed", "skipped", "not-run")}
        result = (
            "pass"
            if nodes
            and counts
            == {
                "passed": len(nodes),
                "failed": 0,
                "skipped": 0,
                "not-run": 0,
            }
            else "fail"
        )
        if result == "fail":
            failures.append(f"runnable lab {lab_id} lacks an all-passing smoke result")
        labs.append(
            {
                "id": lab_id,
                "collected_tests": len(nodes),
                "passed_tests": counts["passed"],
                "failed_tests": counts["failed"],
                "skipped_tests": counts["skipped"],
                "not_run_tests": counts["not-run"],
                "result": result,
            }
        )
    if pytest_exit_code != 0:
        failures.append(f"pytest exited {pytest_exit_code}")
    return {
        "schema_version": 1,
        "result": "fail" if failures else "pass",
        "pytest_exit_code": pytest_exit_code,
        "expected_runnable_labs": list(expected),
        "labs": labs,
        "failures": failures,
    }


def _write_report(value: dict[str, Any]) -> None:
    REPORT.parent.mkdir(mode=0o700, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, REPORT)


def main() -> int:
    expected = tuple(
        lab.manifest.id
        for lab in Catalogue().all()
        if lab.manifest.adapter_status is AdapterStatus.RUNNABLE
    )
    _write_report(
        {
            "schema_version": 1,
            "result": "running",
            "pytest_exit_code": None,
            "expected_runnable_labs": list(expected),
            "labs": [],
            "failures": [],
        }
    )
    accounting = SmokeAccounting(expected)
    exit_code = int(
        pytest.main(
            ["-m", "docker and smoke", "--no-cov"],
            plugins=(accounting,),
        )
    )
    report = _accounting_report(
        expected,
        accounting.collected,
        accounting.outcomes,
        accounting.collection_errors,
        exit_code,
    )
    _write_report(report)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
