from __future__ import annotations

import io
import sys

import pytest

from vulndockyard.errors import PreflightError
from vulndockyard.output import Output
from vulndockyard.process import CommandError, Runner


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
