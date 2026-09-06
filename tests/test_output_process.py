from __future__ import annotations

import io
import os
import signal
import sys

import pytest

from vulndockyard.errors import PreflightError
from vulndockyard.output import Output, terminal_safe
from vulndockyard.process import CommandError, CommandTimeout, Result, Runner


def test_output_human_and_json_contract() -> None:
    stream = io.StringIO()
    errors = io.StringIO()
    output = Output(False, stream, errors)
    output.emit("list", {"x": 1}, "human")
    output.error("list", "bad", 4)
    assert stream.getvalue() == "human\n"
    assert errors.getvalue() == "Error: bad\n"
    stream = io.StringIO()
    errors = io.StringIO()
    output = Output(True, stream, errors)
    output.emit("list", {"b": 2, "a": 1})
    output.error("list", "bad", 4)
    assert stream.getvalue() == '{"command":"list","data":{"a":1,"b":2},"schema_version":1}\n'
    assert '"code":4' in errors.getvalue()


def test_human_output_escapes_terminal_controls_but_json_is_structured() -> None:
    stream = io.StringIO()
    errors = io.StringIO()
    output = Output(False, stream, errors)
    output.emit("logs", {}, "safe\n\x1b[31mdanger\r")
    output.error("logs", "bad\x07value", 6)
    assert stream.getvalue() == "safe\n\\x1b[31mdanger\\x0d\n"
    assert errors.getvalue() == "Error: bad\\x07value\n"
    assert terminal_safe("ordinary\ttext") == "ordinary\ttext"


def test_runner_uses_argv_and_preserves_output() -> None:
    result = Runner().run(
        (sys.executable, "-c", "import sys; print(sys.argv[1])", "$(not-a-shell)"),
        timeout=5,
    )
    assert result.stdout == "$(not-a-shell)\n"
    assert result.returncode == 0


def test_runner_failure_missing_binary_timeout_and_invalid_argv() -> None:
    with pytest.raises(CommandError) as failure:
        Runner().run((sys.executable, "-c", "raise SystemExit(7)"), timeout=5)
    assert failure.value.result.returncode == 7
    with pytest.raises(PreflightError, match="unavailable"):
        Runner().run(("/definitely/missing/vdy",), timeout=1)
    with pytest.raises(PreflightError, match="timed out"):
        Runner().run((sys.executable, "-c", "import time; time.sleep(1)"), timeout=0.01)
    with pytest.raises(ValueError):
        Runner().run((), timeout=1)
    with pytest.raises(ValueError):
        Runner().run(("bad\x00argument",), timeout=1)
    with pytest.raises(ValueError, match="output limit"):
        Runner(max_output_bytes=0)
    with pytest.raises(ValueError, match="termination grace"):
        Runner(terminate_grace=0)


def test_runner_timeout_retains_bounded_captured_output() -> None:
    with pytest.raises(CommandTimeout) as timeout:
        Runner(terminate_grace=0.1).run(
            (
                sys.executable,
                "-c",
                "import sys,time; print('followed', flush=True); time.sleep(10)",
            ),
            timeout=0.5,
        )
    assert timeout.value.result.returncode == 124
    assert timeout.value.result.stdout == "followed\n"


def test_runner_bounds_combined_subprocess_output() -> None:
    with pytest.raises(PreflightError, match="output exceeded 1024 bytes"):
        Runner(max_output_bytes=1024).run(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"),
            timeout=5,
        )


def test_command_error_detail_is_bounded() -> None:
    error = CommandError(Result(("tool",), 1, "", "x" * 20_000))
    assert len(str(error)) < 8_300
    assert str(error).endswith("…[truncated]")


def test_timeout_signals_only_the_runner_created_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, signal.Signals]] = []
    original = os.killpg

    def recording_killpg(process_group: int, value: signal.Signals) -> None:
        calls.append((process_group, value))
        original(process_group, value)

    monkeypatch.setattr("vulndockyard.process.os.killpg", recording_killpg)
    with pytest.raises(PreflightError, match="timed out"):
        Runner(terminate_grace=0.1).run(
            (sys.executable, "-c", "import time; time.sleep(10)"), timeout=0.05
        )
    assert calls
    assert all(process_group != os.getpgrp() for process_group, _ in calls)
    assert calls[0][1] == signal.SIGTERM
