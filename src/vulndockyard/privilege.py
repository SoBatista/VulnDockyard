"""Minimal elevation boundary using only a root-owned checksum-matched helper."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Sequence
from importlib import resources
from pathlib import Path

from .errors import PreflightError
from .process import CommandError, CommandTimeout, Result, Runner

HELPER_SHA256 = "61fc6c54f51d7f17897e43c60dde0633fb3ec5e13ded661fc7e91709b3404586"
HELPER_PATHS = (
    Path("/usr/local/libexec/vulndockyard-hosts"),
    Path("/usr/libexec/vulndockyard-hosts"),
)
SUDO_PATHS = (Path("/usr/bin/sudo"), Path("/bin/sudo"))
SUDO_TIMEOUT = 300.0
SUDO_NO_TERMINAL_MARKERS = ("a terminal is required", "a password is required")
SUDO_NO_TERMINAL_GUIDANCE = (
    "sudo could not ask for a password because this process has no controlling terminal; "
    "rerun the command from an interactive terminal, or authenticate in that terminal "
    "first with `sudo -v`."
)


def packaged_helper() -> Path:
    value = resources.files("vulndockyard").joinpath("data", "helpers", "vulndockyard-hosts")
    return Path(str(value))


def _safe_root_metadata(info: os.stat_result, *, executable: bool) -> bool:
    return (
        info.st_uid == 0
        and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and (not executable or bool(info.st_mode & stat.S_IXUSR))
    )


def _root_executable(candidates: tuple[Path, ...], *, checksum: str | None = None) -> Path:
    for path in candidates:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        parents: list[Path] = []
        parent = path.parent
        while True:
            parents.append(parent)
            if parent == parent.parent:
                break
            parent = parent.parent
        unsafe_parent = False
        for parent in parents:
            parent_info = parent.lstat()
            if (
                parent.is_symlink()
                or not stat.S_ISDIR(parent_info.st_mode)
                or not _safe_root_metadata(parent_info, executable=False)
            ):
                unsafe_parent = True
                break
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or not _safe_root_metadata(info, executable=True)
            or unsafe_parent
        ):
            raise PreflightError(f"privileged executable has unsafe ownership or mode: {path}")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            content = b""
            if checksum is not None:
                if opened.st_size > 65_536:
                    raise PreflightError("privileged helper exceeds the reviewed size bound")
                while chunk := os.read(descriptor, 65_536):
                    content += chunk
        finally:
            os.close(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise PreflightError(f"privileged executable changed during validation: {path}")
        if checksum is not None and hashlib.sha256(content).hexdigest() != checksum:
            raise PreflightError(f"privileged helper checksum does not match this release: {path}")
        return path
    raise PreflightError("the root-owned VulnDockyard hosts helper is not installed")


def invoke_hosts_helper(
    expected_before_sha256: str,
    hostnames: tuple[str, ...],
    runner: Runner | None = None,
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_before_sha256) is None:
        raise ValueError("invalid hosts-helper checksum")
    if (
        len(hostnames) > 256
        or tuple(sorted(set(hostnames))) != hostnames
        or any(re.fullmatch(r"[a-z][a-z0-9-]{0,61}\.test", value) is None for value in hostnames)
    ):
        raise ValueError("invalid hosts-helper hostname set")
    helper = _root_executable(HELPER_PATHS, checksum=HELPER_SHA256)
    command = [str(helper), "replace", expected_before_sha256, *hostnames]
    if os.geteuid() == 0:
        (runner or Runner()).run(command, timeout=60)
        return
    sudo = _root_executable(SUDO_PATHS)
    _run_elevated([str(sudo), "--", *command], timeout=SUDO_TIMEOUT)


def _run_elevated(argv: Sequence[str], *, timeout: float) -> Result:
    """Run sudo inside the caller's session so it can use the controlling terminal.

    The generic Runner starts a new session, which detaches the child from the
    terminal: sudo can then neither prompt for a password nor consult its
    per-terminal credential cache, so a documented `hosts add` fails for every
    user without a NOPASSWD rule. Output stays captured and stdin stays closed;
    sudo prompts on /dev/tty, never on stdin. A timeout sends SIGTERM first so
    sudo can restore terminal settings and relay the signal to the helper.
    """
    if not argv or any("\x00" in value for value in argv):
        raise ValueError("invalid command argument vector")
    try:
        process = subprocess.Popen(  # noqa: S603 - argv only, no shell
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise PreflightError(f"required executable is unavailable: {argv[0]}") from exc
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
    result = Result(
        tuple(argv),
        124 if timed_out else process.returncode,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )
    if timed_out:
        raise CommandTimeout(result, timeout)
    if result.returncode != 0:
        lowered = result.stderr.casefold()
        if any(marker in lowered for marker in SUDO_NO_TERMINAL_MARKERS):
            raise PreflightError(SUDO_NO_TERMINAL_GUIDANCE)
        raise CommandError(result)
    return result
