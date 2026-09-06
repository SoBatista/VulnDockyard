"""Bounded subprocess execution with no shell interpolation."""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .errors import PreflightError, VulnDockyardError


@dataclass(frozen=True)
class Result:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandError(VulnDockyardError):
    def __init__(self, result: Result) -> None:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        if len(detail) > 8_192:
            detail = detail[:8_192] + "…[truncated]"
        super().__init__(f"command failed: {result.argv[0]}: {detail}")
        self.result = result


class Runner:
    def __init__(
        self, *, max_output_bytes: int = 4 * 1024 * 1024, terminate_grace: float = 2
    ) -> None:
        if not 1 <= max_output_bytes <= 64 * 1024 * 1024:
            raise ValueError("subprocess output limit must be between 1 byte and 64 MiB")
        if not 0 < terminate_grace <= 30:
            raise ValueError("subprocess termination grace must be between 0 and 30 seconds")
        self.max_output_bytes = max_output_bytes
        self.terminate_grace = terminate_grace

    @staticmethod
    def _signal_group(process_group: int, value: signal.Signals) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process_group, value)

    @staticmethod
    def _group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        return True

    def _terminate(self, process: subprocess.Popen[bytes], process_group: int) -> None:
        # The group identifier is the PID of the process for which this Runner
        # created a fresh session. It can never refer to the caller's process group.
        self._signal_group(process_group, signal.SIGTERM)
        deadline = time.monotonic() + self.terminate_grace
        while time.monotonic() < deadline:
            process.poll()
            if not self._group_exists(process_group):
                break
            time.sleep(0.02)
        if self._group_exists(process_group):
            self._signal_group(process_group, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=self.terminate_grace)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> Result:
        if not argv or any("\x00" in value for value in argv):
            raise ValueError("invalid command argument vector")
        if timeout <= 0:
            raise ValueError("command timeout must be positive")
        try:
            process = subprocess.Popen(  # noqa: S603 - argv only, no shell
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise PreflightError(f"required executable is unavailable: {argv[0]}") from exc

        process_group = process.pid
        streams = (process.stdout, process.stderr)
        if any(stream is None for stream in streams):  # pragma: no cover - Popen contract
            self._terminate(process, process_group)
            raise PreflightError("could not capture command output")
        stdout = bytearray()
        stderr = bytearray()
        captured = (stdout, stderr)
        selector = selectors.DefaultSelector()
        for index, stream in enumerate(streams):
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PreflightError(f"command timed out after {timeout:g}s: {argv[0]}")
                events = selector.select(min(remaining, 0.1))
                if not events and process.poll() is not None:
                    events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
                for key, _ in events:
                    chunk = os.read(key.fd, min(65_536, self.max_output_bytes + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured[key.data].extend(chunk)
                    if len(stdout) + len(stderr) > self.max_output_bytes:
                        raise PreflightError(
                            f"command output exceeded {self.max_output_bytes} bytes: {argv[0]}"
                        )
            remaining = deadline - time.monotonic()
            if remaining <= 0 and process.poll() is None:
                raise PreflightError(f"command timed out after {timeout:g}s: {argv[0]}")
            returncode = process.wait(timeout=max(remaining, 0.001))
        except subprocess.TimeoutExpired as exc:
            self._terminate(process, process_group)
            raise PreflightError(f"command timed out after {timeout:g}s: {argv[0]}") from exc
        except BaseException:
            self._terminate(process, process_group)
            raise
        finally:
            selector.close()
            for stream in streams:
                if stream is not None:
                    stream.close()

        result = Result(
            tuple(argv),
            returncode,
            stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"),
        )
        if check and result.returncode != 0:
            raise CommandError(result)
        return result
