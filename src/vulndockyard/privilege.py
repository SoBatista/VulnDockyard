"""Minimal elevation boundary using only a root-owned checksum-matched helper."""

from __future__ import annotations

import hashlib
import os
import stat
from importlib import resources
from pathlib import Path

from .errors import PreflightError
from .process import Runner

HELPER_SHA256 = "4eafd8cdddaa41b454c1a49f6ba56fa0ecad9309dfa0a75757767f866cfffc67"
HELPER_PATHS = (
    Path("/usr/local/libexec/vulndockyard-hosts"),
    Path("/usr/libexec/vulndockyard-hosts"),
)
SUDO_PATHS = (Path("/usr/bin/sudo"), Path("/bin/sudo"))


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


def invoke_hosts_helper(action: str, hostname: str, runner: Runner | None = None) -> None:
    if action not in {"add", "remove"}:
        raise ValueError("invalid hosts-helper action")
    helper = _root_executable(HELPER_PATHS, checksum=HELPER_SHA256)
    command = [str(helper), action, hostname]
    if os.geteuid() != 0:
        sudo = _root_executable(SUDO_PATHS)
        command = [str(sudo), "--", *command]
    (runner or Runner()).run(command, timeout=60)
