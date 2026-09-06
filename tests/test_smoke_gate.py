from __future__ import annotations

from scripts.run_smoke_gate import _accounting_report


def test_smoke_accounting_requires_every_runnable_lab_to_pass() -> None:
    report = _accounting_report(
        ("juice-shop",),
        {"juice-shop": ["test_smoke.py::test_one", "test_smoke.py::test_two"]},
        {
            "test_smoke.py::test_one": "passed",
            "test_smoke.py::test_two": "passed",
        },
        [],
        0,
    )

    assert report["result"] == "pass"
    assert report["expected_runnable_labs"] == ["juice-shop"]
    assert report["labs"] == [
        {
            "id": "juice-shop",
            "collected_tests": 2,
            "passed_tests": 2,
            "failed_tests": 0,
            "skipped_tests": 0,
            "not_run_tests": 0,
            "result": "pass",
        }
    ]


def test_smoke_accounting_never_represents_skip_or_missing_test_as_pass() -> None:
    skipped = _accounting_report(
        ("juice-shop",),
        {"juice-shop": ["test_smoke.py::test_one"]},
        {"test_smoke.py::test_one": "skipped"},
        [],
        0,
    )
    missing = _accounting_report(("juice-shop",), {}, {}, [], 0)

    assert skipped["result"] == "fail"
    assert skipped["labs"][0]["skipped_tests"] == 1
    assert missing["result"] == "fail"
    assert missing["labs"][0]["collected_tests"] == 0


def test_smoke_accounting_rejects_unknown_lab_and_pytest_failure() -> None:
    report = _accounting_report(
        ("juice-shop",),
        {"juice-shop": ["known"], "quarantined": ["unknown"]},
        {"known": "passed", "unknown": "passed"},
        [],
        2,
    )

    assert report["result"] == "fail"
    assert "non-runnable lab IDs" in report["failures"][0]
    assert "pytest exited 2" in report["failures"]
