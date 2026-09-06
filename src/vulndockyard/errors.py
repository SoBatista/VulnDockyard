"""Domain errors and stable process exit codes."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    NOT_FOUND = 3
    POLICY = 4
    PREFLIGHT = 5
    RUNTIME = 6
    INTEGRITY = 7
    CANCELLED = 8


class VulnDockyardError(Exception):
    """An expected failure that can be rendered safely."""

    exit_code = ExitCode.RUNTIME


class UsageError(VulnDockyardError):
    exit_code = ExitCode.USAGE


class NotFoundError(VulnDockyardError):
    exit_code = ExitCode.NOT_FOUND


class PolicyError(VulnDockyardError):
    exit_code = ExitCode.POLICY


class PreflightError(VulnDockyardError):
    exit_code = ExitCode.PREFLIGHT


class IntegrityError(VulnDockyardError):
    exit_code = ExitCode.INTEGRITY


class CancelledError(VulnDockyardError):
    exit_code = ExitCode.CANCELLED
