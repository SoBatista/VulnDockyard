"""Minimal elevation boundary using only a root-owned checksum-matched helper."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from importlib import resources
from pathlib import Path

from .errors import PreflightError
from .process import Runner

HELPER_SHA256 = "61fc6c54f51d7f17897e43c60dde0633fb3ec5e13ded661fc7e91709b3404586"
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
    if os.geteuid() != 0:
        sudo = _root_executable(SUDO_PATHS)
        command = [str(sudo), "--", *command]
    (runner or Runner()).run(command, timeout=60)
