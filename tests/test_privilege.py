from __future__ import annotations

import hashlib
import os
import runpy
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import vulndockyard.privilege as privilege
from vulndockyard.errors import PreflightError
from vulndockyard.process import Result, Runner


class RecordingRunner(Runner):
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> Result:
        self.commands.append(tuple(argv))
        return Result(tuple(argv), 0, "", "")


def test_packaged_helper_matches_release_checksum_and_is_isolated() -> None:
    helper = privilege.packaged_helper()
    content = helper.read_bytes()
    assert hashlib.sha256(content).hexdigest() == privilege.HELPER_SHA256
    assert content.startswith(b"#!/usr/bin/python3 -I\n")
    assert b"vulndockyard" not in b"\n".join(content.splitlines()[1:20])
    result = subprocess.run(
        ("/usr/bin/python3", "-I", str(helper)),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "usage:" in result.stderr


def test_packaged_helper_preserves_a_missing_final_newline_round_trip() -> None:
    namespace = runpy.run_path(str(privilege.packaged_helper()), run_name="vdy_hosts_helper_test")
    transform = namespace["transform"]
    original = b"127.0.0.1 localhost\n# final line"
    added = transform(original, [b"juice-shop.test"])
    assert transform(added, []) == original


@pytest.mark.parametrize(
    "content",
    (
        b"prefix # BEGIN VULNDOCKYARD MANAGED BLOCK\n# END VULNDOCKYARD MANAGED BLOCK\n",
        b"# END VULNDOCKYARD MANAGED BLOCK\n# BEGIN VULNDOCKYARD MANAGED BLOCK\n",
    ),
)
def test_packaged_helper_rejects_inexact_or_misordered_markers(content: bytes) -> None:
    namespace = runpy.run_path(str(privilege.packaged_helper()), run_name="vdy_hosts_helper_test")
    with pytest.raises(SystemExit):
        namespace["bounds"](content)


def test_root_metadata_contract() -> None:
    safe = cast(os.stat_result, SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755))
    writable = cast(os.stat_result, SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o775))
    user_owned = cast(os.stat_result, SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o755))
    assert privilege._safe_root_metadata(safe, executable=True)
    assert not privilege._safe_root_metadata(writable, executable=True)
    assert not privilege._safe_root_metadata(user_owned, executable=True)


def test_root_executable_rejects_user_writable_candidate(tmp_path: Path) -> None:
    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o755)
    with pytest.raises(PreflightError, match="unsafe ownership"):
        privilege._root_executable((helper,))


def test_invoke_uses_only_validated_helper_and_system_sudo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = iter((Path("/approved/helper"), Path("/usr/bin/sudo")))
    monkeypatch.setattr(privilege, "_root_executable", lambda *args, **kwargs: next(selected))
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    runner = RecordingRunner()
    privilege.invoke_hosts_helper("add", "juice-shop.test", runner)
    assert runner.commands == [
        ("/usr/bin/sudo", "--", "/approved/helper", "add", "juice-shop.test")
    ]


def test_invoke_rejects_unknown_action() -> None:
    with pytest.raises(ValueError, match="action"):
        privilege.invoke_hosts_helper("replace", "juice-shop.test")
