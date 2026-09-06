from __future__ import annotations

import os
from pathlib import Path

import pytest

import vulndockyard.hosts_helper as helper
from vulndockyard.hosts import HostsManager


class FixtureManager(HostsManager):
    path_value: Path

    def __init__(self) -> None:
        super().__init__(self.path_value)


def test_helper_usage_and_privilege_boundary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert helper.main([]) == 2
    assert "Usage" in capsys.readouterr().err
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert helper.main(["add", "juice-shop.test"]) == 1
    assert "must run as root" in capsys.readouterr().err


def test_helper_applies_only_valid_test_hostname(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    path.chmod(0o644)
    FixtureManager.path_value = path
    monkeypatch.setattr(helper, "HostsManager", FixtureManager)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert helper.main(["add", "juice-shop.test"]) == 0
    assert b"juice-shop.test" in path.read_bytes()
    assert helper.main(["remove", "juice-shop.test"]) == 0
    assert b"juice-shop.test" not in path.read_bytes()
