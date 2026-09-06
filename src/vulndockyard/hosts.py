"""Lossless marker-delimited hosts-file transformations."""

from __future__ import annotations

import contextlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import IntegrityError, PolicyError

BEGIN = "# BEGIN VULNDOCKYARD MANAGED BLOCK\n"
END = "# END VULNDOCKYARD MANAGED BLOCK\n"
INSERTED_SEPARATOR = "# VULNDOCKYARD INSERTED NEWLINE\n"
HOSTNAME = re.compile(r"^[a-z][a-z0-9-]{0,61}\.test$")


def _managed_block(hostnames: tuple[str, ...], *, inserted_separator: bool = False) -> bytes:
    names = tuple(sorted(set(hostnames)))
    if any(HOSTNAME.fullmatch(name) is None for name in names):
        raise IntegrityError("managed hostname is not a lowercase .test name")
    lines = [
        BEGIN,
        *((INSERTED_SEPARATOR,) if inserted_separator else ()),
        *(f"127.0.0.1\t{name}\n" for name in names),
        END,
    ]
    return "".join(lines).encode("ascii")


def _bounds(content: bytes) -> tuple[int, int] | None:
    begin = BEGIN.encode()
    end = END.encode()

    def exact_marker(marker: bytes) -> int | None:
        token = marker.rstrip(b"\n")
        count = content.count(token)
        if count > 1:
            raise IntegrityError("hosts file contains multiple VulnDockyard blocks")
        if count == 0:
            return None
        position = content.index(token)
        if (position != 0 and content[position - 1 : position] != b"\n") or content[
            position : position + len(marker)
        ] != marker:
            raise IntegrityError("hosts file contains an inexact VulnDockyard marker")
        return position

    start = exact_marker(begin)
    end_start = exact_marker(end)
    if (start is None) != (end_start is None):
        raise IntegrityError("hosts file contains an incomplete VulnDockyard block")
    if start is None or end_start is None:
        return None
    if end_start <= start:
        raise IntegrityError("hosts file contains misordered VulnDockyard markers")
    return start, end_start + len(end)


def parse_managed_hosts(content: bytes) -> tuple[str, ...]:
    bounds = _bounds(content)
    if bounds is None:
        return ()
    block = content[bounds[0] : bounds[1]].decode("ascii")
    lines = block.splitlines()[1:-1]
    if lines and lines[0] == INSERTED_SEPARATOR.rstrip("\n"):
        lines = lines[1:]
    result = []
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] != "127.0.0.1" or HOSTNAME.fullmatch(fields[1]) is None:
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
    inserted_separator = False
    if bounds is not None:
        block = content[bounds[0] : bounds[1]]
        inserted_separator = INSERTED_SEPARATOR.encode() in block
    elif content and not content.endswith(b"\n"):
        inserted_separator = True
    new_block = (
        _managed_block(hostnames, inserted_separator=inserted_separator) if hostnames else b""
    )
    if bounds is None:
        if not new_block:
            return content
        separator = b"" if not content or content.endswith(b"\n") else b"\n"
        return content + separator + new_block
    before, after = content[: bounds[0]], content[bounds[1] :]
    if not new_block and inserted_separator:
        if not before.endswith(b"\n"):
            raise IntegrityError("managed hosts separator metadata is inconsistent")
        before = before[:-1]
    return before + new_block + after


@dataclass(frozen=True)
class HostsPreview:
    before: tuple[str, ...]
    after: tuple[str, ...]
    changed: bool
    before_block: str
    after_block: str


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _block_text(content: bytes) -> str:
    bounds = _bounds(content)
    if bounds is None:
        return ""
    parse_managed_hosts(content)
    return content[bounds[0] : bounds[1]].decode("ascii")


class HostsManager:
    def __init__(self, path: Path = Path("/etc/hosts")) -> None:
        self.path = path

    def _validate(self, info: os.stat_result) -> None:
        if stat.S_ISLNK(info.st_mode):
            raise PolicyError(f"refusing symlinked hosts file: {self.path}")
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("hosts path is not a regular file")
        if info.st_uid != 0 and self.path == Path("/etc/hosts"):
            raise PolicyError("/etc/hosts is not owned by root")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError("hosts file is group- or world-writable")
        if info.st_size > 2_000_000:
            raise PolicyError("hosts file exceeds the 2 MB safety bound")

    def _snapshot(self) -> tuple[os.stat_result, bytes]:
        info = self.path.lstat()
        self._validate(info)
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            if _fingerprint(opened) != _fingerprint(info):
                raise PolicyError("hosts file changed during validation")
            self._validate(opened)
            chunks: list[bytes] = []
            remaining = 2_000_001
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            finished = os.fstat(descriptor)
            if _fingerprint(finished) != _fingerprint(opened):
                raise PolicyError("hosts file changed while it was being read")
        finally:
            os.close(descriptor)
        if len(content) > 2_000_000 or b"\x00" in content:
            raise IntegrityError("hosts file is too large or contains a NUL byte")
        return finished, content

    def _require_unchanged(self, expected: os.stat_result, expected_content: bytes) -> None:
        current, content = self._snapshot()
        if _fingerprint(current) != _fingerprint(expected) or content != expected_content:
            raise PolicyError("hosts file changed before atomic replacement")

    def preview(self, hostname: str, *, add: bool) -> HostsPreview:
        return self.preview_many((hostname,), add=add)

    def preview_many(self, hostnames: tuple[str, ...], *, add: bool) -> HostsPreview:
        _, content = self._snapshot()
        before = parse_managed_hosts(content)
        values = set(before)
        if any(HOSTNAME.fullmatch(hostname) is None for hostname in hostnames):
            raise IntegrityError("managed hostname is not a lowercase .test name")
        values.update(hostnames) if add else values.difference_update(hostnames)
        after = tuple(sorted(values))
        updated = transform_hosts(content, after)
        return HostsPreview(
            before,
            after,
            before != after,
            _block_text(content),
            _block_text(updated),
        )

    def managed_hosts(self) -> tuple[str, ...]:
        _, content = self._snapshot()
        return parse_managed_hosts(content)

    def apply(self, hostname: str, *, add: bool) -> HostsPreview:
        return self.apply_many((hostname,), add=add)

    def apply_many(self, hostnames: tuple[str, ...], *, add: bool) -> HostsPreview:
        info, content = self._snapshot()
        before = parse_managed_hosts(content)
        values = set(before)
        if any(HOSTNAME.fullmatch(hostname) is None for hostname in hostnames):
            raise IntegrityError("managed hostname is not a lowercase .test name")
        values.update(hostnames) if add else values.difference_update(hostnames)
        after = tuple(sorted(values))
        updated = transform_hosts(content, after)
        if updated == content:
            return HostsPreview(
                before,
                after,
                False,
                _block_text(content),
                _block_text(updated),
            )
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
            self._require_unchanged(info, content)
            os.replace(temporary, self.path)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
        return HostsPreview(
            before,
            after,
            True,
            _block_text(content),
            _block_text(updated),
        )
