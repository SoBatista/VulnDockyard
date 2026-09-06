"""Lossless marker-delimited hosts-file transformations."""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import IntegrityError, PolicyError

BEGIN = "# BEGIN VULNDOCKYARD MANAGED BLOCK\n"
END = "# END VULNDOCKYARD MANAGED BLOCK\n"


def _managed_block(hostnames: tuple[str, ...]) -> bytes:
    names = tuple(sorted(set(hostnames)))
    lines = [BEGIN, *(f"127.0.0.1\t{name}\n" for name in names), END]
    return "".join(lines).encode("ascii")


def _bounds(content: bytes) -> tuple[int, int] | None:
    begin = BEGIN.encode()
    end = END.encode()
    if content.count(begin) != content.count(end):
        raise IntegrityError("hosts file contains an incomplete VulnDockyard block")
    if content.count(begin) > 1:
        raise IntegrityError("hosts file contains multiple VulnDockyard blocks")
    if begin not in content:
        return None
    start = content.index(begin)
    finish = content.index(end, start) + len(end)
    return start, finish


def parse_managed_hosts(content: bytes) -> tuple[str, ...]:
    bounds = _bounds(content)
    if bounds is None:
        return ()
    block = content[bounds[0] : bounds[1]].decode("ascii")
    lines = block.splitlines()[1:-1]
    result = []
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] != "127.0.0.1" or not fields[1].endswith(".test"):
            raise IntegrityError("hosts file contains a malformed VulnDockyard entry")
        result.append(fields[1])
    if len(result) != len(set(result)):
        raise IntegrityError("hosts file contains duplicate managed hostnames")
    return tuple(result)


def transform_hosts(content: bytes, hostnames: tuple[str, ...]) -> bytes:
    if b"\x00" in content:
        raise IntegrityError("hosts file contains a NUL byte")
    bounds = _bounds(content)
    if bounds is not None:
        parse_managed_hosts(content)
    new_block = _managed_block(hostnames) if hostnames else b""
    if bounds is None:
        if not new_block:
            return content
        separator = b"" if not content or content.endswith(b"\n") else b"\n"
        return content + separator + new_block
    before, after = content[: bounds[0]], content[bounds[1] :]
    return before + new_block + after


@dataclass(frozen=True)
class HostsPreview:
    before: tuple[str, ...]
    after: tuple[str, ...]
    changed: bool


class HostsManager:
    def __init__(self, path: Path = Path("/etc/hosts")) -> None:
        self.path = path

    def _validate(self) -> os.stat_result:
        if self.path.is_symlink():
            raise PolicyError(f"refusing symlinked hosts file: {self.path}")
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("hosts path is not a regular file")
        if info.st_uid != 0 and self.path == Path("/etc/hosts"):
            raise PolicyError("/etc/hosts is not owned by root")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError("hosts file is group- or world-writable")
        return info

    def preview(self, hostname: str, *, add: bool) -> HostsPreview:
        self._validate()
        content = self.path.read_bytes()
        before = parse_managed_hosts(content)
        values = set(before)
        values.add(hostname) if add else values.discard(hostname)
        after = tuple(sorted(values))
        return HostsPreview(before, after, before != after)

    def apply(self, hostname: str, *, add: bool) -> HostsPreview:
        info = self._validate()
        content = self.path.read_bytes()
        before = parse_managed_hosts(content)
        values = set(before)
        values.add(hostname) if add else values.discard(hostname)
        after = tuple(sorted(values))
        updated = transform_hosts(content, after)
        if updated == content:
            return HostsPreview(before, after, False)
        directory = self.path.parent
        descriptor, temporary = tempfile.mkstemp(prefix=".vulndockyard-hosts-", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(updated)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, stat.S_IMODE(info.st_mode))
            try:
                os.chown(temporary, info.st_uid, info.st_gid)
            except PermissionError:
                if (info.st_uid, info.st_gid) != (os.getuid(), os.getgid()):
                    raise
            if parse_managed_hosts(Path(temporary).read_bytes()) != after:
                raise IntegrityError("temporary hosts replacement failed validation")
            os.replace(temporary, self.path)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
        return HostsPreview(before, after, True)
