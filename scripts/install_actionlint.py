#!/usr/bin/env python3
"""Install the pinned official Actionlint binary after checksum verification."""

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
VERSION = "1.7.7"
CHECKSUMS = {
    "x86_64": "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757",
    "aarch64": "401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0",
}
BINARY_CHECKSUMS = {
    "x86_64": "9f7dedb4e23f89f2922073d1a6720405b7b520d4f5832ebb96f0d55a2958886c",
    "aarch64": "446687e63fac45472b0a66bae28975c28678af062670af119c11a7087baf35cc",
}


def install() -> Path:
    target = ROOT / ".tools" / "actionlint"
    machine = platform.machine().casefold()
    architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if architecture not in CHECKSUMS:
        raise RuntimeError(f"Actionlint bootstrap does not support architecture {machine}")
    if target.is_file():
        actual_binary = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_binary != BINARY_CHECKSUMS[architecture]:
            raise RuntimeError("existing Actionlint binary failed its pinned checksum")
        return target
    release_arch = "amd64" if architecture == "x86_64" else "arm64"
    url = (
        f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/"
        f"actionlint_{VERSION}_linux_{release_arch}.tar.gz"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "VulnDockyard/1"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed URL
        archive = response.read(10_000_001)
    if len(archive) > 10_000_000:
        raise RuntimeError("Actionlint archive exceeded 10 MB")
    actual = hashlib.sha256(archive).hexdigest()
    if actual != CHECKSUMS[architecture]:
        raise RuntimeError(f"Actionlint checksum mismatch: {actual}")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = [member for member in bundle.getmembers() if member.name == "actionlint"]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 10_000_000:
            raise RuntimeError("Actionlint archive has an unexpected shape")
        source = bundle.extractfile(members[0])
        if source is None:
            raise RuntimeError("Actionlint binary could not be read")
        content = source.read(10_000_001)
    if hashlib.sha256(content).hexdigest() != BINARY_CHECKSUMS[architecture]:
        raise RuntimeError("extracted Actionlint binary failed its pinned checksum")
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
        print(f"Actionlint bootstrap failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
