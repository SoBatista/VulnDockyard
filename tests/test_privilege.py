from __future__ import annotations

import hashlib
import os
import runpy
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import vulndockyard.privilege as privilege
from vulndockyard.errors import PreflightError
from vulndockyard.process import CommandError, CommandTimeout, Result, Runner


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


def test_packaged_helper_replaces_the_confirmed_set_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = runpy.run_path(str(privilege.packaged_helper()), run_name="vdy_hosts_helper_test")
    hosts = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    hosts.write_bytes(original)
    hosts.chmod(0o600)
    helper_globals = namespace["main"].__globals__
    helper_globals["HOSTS"] = str(hosts)
    helper_globals["snapshot"] = lambda: (hosts.lstat(), hosts.read_bytes())
    checksum = hashlib.sha256(original).hexdigest()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sys,
        "argv",
        ["vulndockyard-hosts", "replace", checksum, "juice-shop.test", "webgoat.test"],
    )

    assert namespace["main"]() == 0
    assert namespace["parse"](hosts.read_bytes()) == (
        b"juice-shop.test",
        b"webgoat.test",
    )


def test_packaged_helper_rejects_a_stale_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = runpy.run_path(str(privilege.packaged_helper()), run_name="vdy_hosts_helper_test")
    hosts = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    hosts.write_bytes(original)
    hosts.chmod(0o600)
    helper_globals = namespace["main"].__globals__
    helper_globals["HOSTS"] = str(hosts)
    helper_globals["snapshot"] = lambda: (hosts.lstat(), hosts.read_bytes())
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sys,
        "argv",
        ["vulndockyard-hosts", "replace", "0" * 64, "juice-shop.test"],
    )

    with pytest.raises(SystemExit):
        namespace["main"]()
    assert hosts.read_bytes() == original


def test_packaged_helper_refuses_a_change_before_atomic_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = runpy.run_path(str(privilege.packaged_helper()), run_name="vdy_hosts_helper_test")
    hosts = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    foreign = original + b"# concurrent foreign edit\n"
    hosts.write_bytes(original)
    hosts.chmod(0o600)
    helper_globals = namespace["main"].__globals__
    helper_globals["HOSTS"] = str(hosts)
    snapshots = 0

    def changing_snapshot() -> tuple[os.stat_result, bytes]:
        nonlocal snapshots
        snapshots += 1
        if snapshots == 2:
            hosts.write_bytes(foreign)
            hosts.chmod(0o600)
        return hosts.lstat(), hosts.read_bytes()

    helper_globals["snapshot"] = changing_snapshot
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulndockyard-hosts",
            "replace",
            hashlib.sha256(original).hexdigest(),
            "juice-shop.test",
        ],
    )

    with pytest.raises(SystemExit):
        namespace["main"]()
    assert hosts.read_bytes() == foreign


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
    elevated: list[tuple[tuple[str, ...], float]] = []

    def fake_elevated(argv: Sequence[str], *, timeout: float) -> Result:
        elevated.append((tuple(argv), timeout))
        return Result(tuple(argv), 0, "", "")

    monkeypatch.setattr(privilege, "_run_elevated", fake_elevated)
    runner = RecordingRunner()
    checksum = "a" * 64
    privilege.invoke_hosts_helper(checksum, ("juice-shop.test", "webgoat.test"), runner)
    # The detached Runner can never satisfy a sudo password prompt, so sudo must
    # run through the session-preserving path and never through the Runner.
    assert runner.commands == []
    assert elevated == [
        (
            (
                "/usr/bin/sudo",
                "--",
                "/approved/helper",
                "replace",
                checksum,
                "juice-shop.test",
                "webgoat.test",
            ),
            privilege.SUDO_TIMEOUT,
        )
    ]


def test_invoke_as_root_calls_the_helper_directly_through_the_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(privilege, "_root_executable", lambda *args, **kwargs: Path("/h"))
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def unexpected(argv: Sequence[str], *, timeout: float) -> Result:
        raise AssertionError("root must not go through sudo")

    monkeypatch.setattr(privilege, "_run_elevated", unexpected)
    runner = RecordingRunner()
    checksum = "b" * 64
    privilege.invoke_hosts_helper(checksum, ("juice-shop.test",), runner)
    assert runner.commands == [("/h", "replace", checksum, "juice-shop.test")]


def _python(snippet: str) -> tuple[str, ...]:
    return (sys.executable, "-I", "-c", snippet)


def test_run_elevated_keeps_the_session_and_captures_output() -> None:
    result = privilege._run_elevated(
        _python(
            "import os, sys; sys.stdout.write(str(os.getsid(0) == os.getsid(os.getppid())));"
            " sys.stderr.write('quiet'); sys.exit(0)"
        ),
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout == "True"
    assert result.stderr == "quiet"


def test_run_elevated_explains_a_missing_terminal() -> None:
    with pytest.raises(PreflightError, match="no controlling terminal"):
        privilege._run_elevated(
            _python(
                "import sys; sys.stderr.write('sudo: a terminal is required to read the "
                "password; either use the -S option to read from standard input or configure "
                "an askpass helper\\nsudo: a password is required\\n'); sys.exit(1)"
            ),
            timeout=30,
        )


def test_run_elevated_reports_other_failures_as_command_errors() -> None:
    with pytest.raises(CommandError, match="hosts file contains multiple"):
        privilege._run_elevated(
            _python(
                "import sys; sys.stderr.write('Error: hosts file contains multiple'); sys.exit(1)"
            ),
            timeout=30,
        )


def test_run_elevated_terminates_on_timeout() -> None:
    with pytest.raises(CommandTimeout, match="timed out"):
        privilege._run_elevated(_python("import time; time.sleep(30)"), timeout=0.2)


def test_run_elevated_rejects_missing_executable_and_bad_argv() -> None:
    with pytest.raises(PreflightError, match="required executable is unavailable"):
        privilege._run_elevated(("/nonexistent/vulndockyard-sudo", "--"), timeout=1)
    with pytest.raises(ValueError, match="argument vector"):
        privilege._run_elevated((), timeout=1)
    with pytest.raises(ValueError, match="argument vector"):
        privilege._run_elevated(("a", "b\x00c"), timeout=1)


@pytest.mark.parametrize(
    ("checksum", "hostnames"),
    (("bad", ()), ("a" * 64, ("UPPER.test",)), ("a" * 64, ("webgoat.test", "a.test"))),
)
def test_invoke_rejects_malformed_replacement(checksum: str, hostnames: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="hosts-helper"):
        privilege.invoke_hosts_helper(checksum, hostnames)
