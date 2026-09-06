#!/usr/bin/env python3
"""Build and compare release artifacts from a tracked-files-only Git archive."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version import authoritative_version  # noqa: E402
from scripts.generate_sbom import generate as generate_sbom  # noqa: E402


def _git() -> str:
    value = shutil.which("git")
    if value is None:
        raise RuntimeError("required executable is unavailable: git")
    return value


def _archive(prefix: str = "") -> bytes:
    command = [_git(), "archive", "--format=tar"]
    if prefix:
        command.append(f"--prefix={prefix}")
    command.append("HEAD")
    return subprocess.run(  # noqa: S603 - fixed git archive command and reviewed prefix
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=60,
    ).stdout


def _extract(content: bytes, destination: Path) -> Path:
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or not (member.isdir() or member.isfile())
            ):
                raise RuntimeError(f"unsafe release archive member: {member.name}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"could not extract release member: {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
    return destination


def _epoch() -> int:
    value = subprocess.run(  # noqa: S603 - resolved Git executable and fixed arguments
        (_git(), "show", "-s", "--format=%ct", "HEAD"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    return int(value)


def _build_once(archive: bytes, destination: Path, epoch: int) -> dict[str, str]:
    source = destination / "source"
    output = destination / "dist"
    source.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    _extract(archive, source)
    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": "0", "SOURCE_DATE_EPOCH": str(epoch)})
    subprocess.run(  # noqa: S603 - current interpreter and controlled release paths
        (sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)),
        cwd=source,
        env=environment,
        check=True,
        timeout=180,
    )
    files = sorted(path for path in output.iterdir() if path.is_file())
    if len(files) != 2 or not any(path.suffix == ".whl" for path in files):
        raise RuntimeError("release build did not produce exactly one wheel and one sdist")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def changelog_notes(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    import re

    match = re.search(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}\n(?P<body>.*?)(?=^## |\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None or not match.group("body").strip():
        raise RuntimeError(f"changelog has no release notes for {version}")
    return match.group("body").strip() + "\n"


def build(output: Path) -> dict[str, str]:
    if output.resolve() != (ROOT / "artifacts" / "release").resolve():
        raise RuntimeError("release artifacts must use artifacts/release")
    version = authoritative_version()
    archive = _archive()
    epoch = _epoch()
    with (
        tempfile.TemporaryDirectory(prefix="vdy-release-a-") as first_name,
        tempfile.TemporaryDirectory(prefix="vdy-release-b-") as second_name,
    ):
        first = Path(first_name)
        second = Path(second_name)
        hashes_a = _build_once(archive, first, epoch)
        hashes_b = _build_once(archive, second, epoch)
        if hashes_a != hashes_b:
            raise RuntimeError(f"release builds are not reproducible: {hashes_a} != {hashes_b}")
        if output.exists():
            shutil.rmtree(output)
        output.mkdir(mode=0o700, parents=True)
        for name in sorted(hashes_a):
            shutil.copy2(first / "dist" / name, output / name)
    source_tar = _archive(prefix=f"VulnDockyard-{version}/")
    source_path = output / f"VulnDockyard-{version}.tar.gz"
    with (
        source_path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed,
    ):
        compressed.write(source_tar)
    wheel = next(output.glob("*.whl"))
    generate_sbom(wheel, output / f"vulndockyard-{version}.spdx.json")
    (output / "RELEASE_NOTES.md").write_text(changelog_notes(version), encoding="utf-8")
    checksummed = sorted(path for path in output.iterdir() if path.name != "SHA256SUMS")
    sums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in checksummed
    )
    (output / "SHA256SUMS").write_text(sums, encoding="ascii")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output.iterdir()}


def main() -> int:
    try:
        hashes = build(ROOT / "artifacts" / "release")
    except (OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"release artifact build failed: {exc}", file=sys.stderr)
        return 1
    for name in sorted(hashes):
        print(f"{hashes[name]}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
