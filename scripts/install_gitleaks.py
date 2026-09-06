#!/usr/bin/env python3
"""Install the pinned official Gitleaks binary after checksum verification."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import stat
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.30.1"
ARCHIVE_CHECKSUMS = {
    "x86_64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "aarch64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
}
BINARY_CHECKSUMS = {
    "x86_64": "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
    "aarch64": "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b",
}
MAX_ARCHIVE_BYTES = 12_000_000


def install() -> Path:
    target = ROOT / ".tools" / "gitleaks"
    machine = platform.machine().casefold()
    architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if architecture not in ARCHIVE_CHECKSUMS:
        raise RuntimeError(f"Gitleaks bootstrap does not support architecture {machine}")
    if target.is_file():
        actual_binary = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_binary != BINARY_CHECKSUMS[architecture]:
            raise RuntimeError("existing Gitleaks binary failed its pinned checksum")
        return target
    release_arch = "x64" if architecture == "x86_64" else "arm64"
    url = (
        f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/"
        f"gitleaks_{VERSION}_linux_{release_arch}.tar.gz"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "VulnDockyard/1"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed URL
        archive = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise RuntimeError("Gitleaks archive exceeded 12 MB")
    actual = hashlib.sha256(archive).hexdigest()
    if actual != ARCHIVE_CHECKSUMS[architecture]:
        raise RuntimeError(f"Gitleaks archive checksum mismatch: {actual}")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = [member for member in bundle.getmembers() if member.name == "gitleaks"]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 30_000_000:
            raise RuntimeError("Gitleaks archive has an unexpected shape")
        source = bundle.extractfile(members[0])
        if source is None:
            raise RuntimeError("Gitleaks binary could not be read")
        content = source.read(30_000_001)
    if len(content) > 30_000_000:
        raise RuntimeError("Gitleaks binary exceeded 30 MB")
    if hashlib.sha256(content).hexdigest() != BINARY_CHECKSUMS[architecture]:
        raise RuntimeError("extracted Gitleaks binary failed its pinned checksum")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(content)
    os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    os.replace(temporary, target)
    return target


def main() -> int:
    try:
        print(install())
    except (OSError, RuntimeError, tarfile.TarError) as exc:
        print(f"Gitleaks bootstrap failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
