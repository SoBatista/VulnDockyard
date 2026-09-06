"""Bounded subprocess execution with no shell interpolation."""

from __future__ import annotations

import subprocess
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
        super().__init__(f"command failed: {result.argv[0]}: {detail}")
        self.result = result


class Runner:
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
        try:
            completed = subprocess.run(  # noqa: S603 - argv only, no shell
                list(argv),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env=env,
            )
        except FileNotFoundError as exc:
            raise PreflightError(f"required executable is unavailable: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise PreflightError(f"command timed out after {timeout:g}s: {argv[0]}") from exc
        result = Result(tuple(argv), completed.returncode, completed.stdout, completed.stderr)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result
