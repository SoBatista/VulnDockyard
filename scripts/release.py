#!/usr/bin/env python3
"""Guarded, manual, idempotent release publication and verification."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import check_version as version_tools  # noqa: E402

ORIGIN = "https://github.com/SoBatista/VulnDockyard.git"
HOSTED_CHECKOUT_ORIGIN = "https://github.com/SoBatista/VulnDockyard"
REPOSITORY = "SoBatista/VulnDockyard"
SHA256_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)$")


def _run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - release constructs argv after strict context checks
        arguments,
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _release_context() -> tuple[str, str]:
    version = version_tools.check_release_ready()
    if os.environ.get("VDY_RELEASE_VERSION") != version:
        raise RuntimeError("workflow input does not match the authoritative stable version")
    if os.environ.get("VDY_CONFIRM") != f"publish-v{version}":
        raise RuntimeError("explicit publish confirmation is missing")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != (
        "refs/heads/main"
    ):
        raise RuntimeError("publication is allowed only from a manual main workflow run")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise RuntimeError("publication repository identity does not match")
    if _run("git", "remote", "get-url", "origin").stdout.strip() not in {
        ORIGIN,
        HOSTED_CHECKOUT_ORIGIN,
    }:
        raise RuntimeError("origin URL does not match the authorized repository")
    head = _run("git", "rev-parse", "HEAD").stdout.strip()
    if _run("git", "status", "--porcelain").stdout:
        raise RuntimeError("release checkout is not clean")
    return version, head


def _verify_main_ci(head: str) -> None:
    run_id = os.environ.get("VDY_CI_RUN_ID", "")
    if not run_id.isdigit():
        raise RuntimeError("a successful main CI run ID is required")
    result = _run("gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}")
    value = json.loads(result.stdout)
    expected = {
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "head_branch": "main",
        "head_sha": head,
        "conclusion": "success",
    }
    if not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items()):
        raise RuntimeError("CI run is not a successful CI result for this exact main commit")
    if value.get("event") not in {"push", "workflow_dispatch"}:
        raise RuntimeError("CI authorization must come from a main push or manual main run")


def _reviewed_notes(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}\n"
        r"(?P<body>.*?)(?=^## |\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None or not match.group("body").strip():
        raise RuntimeError(f"changelog has no release notes for {version}")
    return match.group("body").strip() + "\n"


def prepare() -> None:
    from scripts.release_artifacts import build as build_artifacts

    _, head = _release_context()
    _verify_main_ci(head)
    build_artifacts(ROOT / "artifacts" / "release")


def _remote_tag_commit(tag: str) -> str | None:
    result = _run(
        "git",
        "ls-remote",
        "--tags",
        "origin",
        f"refs/tags/{tag}",
        f"refs/tags/{tag}^{{}}",
    )
    lines = [line.split() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    dereferenced = [value[0] for value in lines if value[1].endswith("^{}")]
    if len(dereferenced) != 1:
        raise RuntimeError("existing release tag is not an annotated tag")
    return dereferenced[0]


def _expected_artifacts(version: str) -> set[str]:
    return {
        "RELEASE_NOTES.md",
        "SHA256SUMS",
        f"VulnDockyard-{version}.tar.gz",
        f"vulndockyard-{version}-py3-none-any.whl",
        f"vulndockyard-{version}.spdx.json",
        f"vulndockyard-{version}.tar.gz",
    }


def _verify_sums(directory: Path, version: str) -> None:
    if directory.is_symlink():
        raise RuntimeError("release artifact root must not be a symlink")
    resolved = directory.resolve(strict=True)
    if not resolved.is_dir():
        raise RuntimeError("release artifact root must be a real directory")
    actual = {path.name for path in resolved.iterdir() if path.is_file() and not path.is_symlink()}
    expected = _expected_artifacts(version)
    if actual != expected:
        raise RuntimeError(
            f"release artifact set mismatch: expected {sorted(expected)}, found {sorted(actual)}"
        )
    sums_path = resolved / "SHA256SUMS"
    lines = sums_path.read_text(encoding="ascii").splitlines()
    entries: dict[str, str] = {}
    for line in lines:
        match = SHA256_LINE.fullmatch(line)
        if match is None:
            raise RuntimeError("SHA256SUMS contains a malformed entry")
        name = match.group("name")
        if name in entries:
            raise RuntimeError(f"SHA256SUMS contains a duplicate entry: {name}")
        entries[name] = match.group("digest")
    expected_sums = expected - {"SHA256SUMS"}
    if set(entries) != expected_sums:
        raise RuntimeError("SHA256SUMS does not cover the exact release artifact set")
    for name, digest in entries.items():
        path = resolved / name
        if path.resolve(strict=True).parent != resolved or path.is_symlink():
            raise RuntimeError(f"release artifact escaped its directory: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"published checksum mismatch: {name}")


def _release_metadata(
    value: object, *, tag: str, version: str, notes: str, expected_assets: set[str]
) -> set[str]:
    if not isinstance(value, dict):
        raise RuntimeError("existing release metadata is malformed")
    expected = {
        "tagName": tag,
        "name": f"VulnDockyard {version}",
        "body": notes,
        "isDraft": False,
        "isPrerelease": False,
    }
    mismatches = [
        key for key, expected_value in expected.items() if value.get(key) != expected_value
    ]
    if mismatches:
        raise RuntimeError(f"existing release metadata differs: {', '.join(mismatches)}")
    raw_assets = value.get("assets")
    if not isinstance(raw_assets, list) or any(not isinstance(item, dict) for item in raw_assets):
        raise RuntimeError("existing release assets are malformed")
    names = [item.get("name") for item in raw_assets]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
        raise RuntimeError("existing release contains malformed or duplicate asset names")
    remote_assets = {str(name) for name in names}
    unexpected = sorted(remote_assets - expected_assets)
    if unexpected:
        raise RuntimeError(f"existing release contains unexpected assets: {unexpected}")
    return remote_assets


def _release_view(tag: str) -> subprocess.CompletedProcess[str]:
    return _run(
        "gh",
        "release",
        "view",
        tag,
        "--json",
        "assets,body,isDraft,isPrerelease,name,tagName",
        check=False,
    )


def _source_archive(version: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("required executable is unavailable: git")
    source = subprocess.run(  # noqa: S603 - fixed git command and validated version
        (
            git,
            "archive",
            "--format=tar",
            f"--prefix=VulnDockyard-{version}/",
            "HEAD",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=60,
    ).stdout
    epoch = int(_run("git", "show", "-s", "--format=%ct", "HEAD").stdout.strip())
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed:
        compressed.write(source)
    return output.getvalue()


def publish() -> None:
    version, head = _release_context()
    _verify_main_ci(head)
    artifact_root = ROOT / "artifacts" / "release"
    _verify_sums(artifact_root, version)
    notes = (artifact_root / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    if notes != _reviewed_notes(version):
        raise RuntimeError("release payload notes differ from the reviewed changelog")
    tag = f"v{version}"
    remote_commit = _remote_tag_commit(tag)
    if remote_commit is not None and remote_commit != head:
        raise RuntimeError(f"refusing to rewrite or relocate existing tag {tag}")
    if remote_commit is None:
        _run("git", "config", "user.name", "github-actions[bot]")
        _run(
            "git",
            "config",
            "user.email",
            "41898282+github-actions[bot]@users.noreply.github.com",
        )
        _run("git", "tag", "--annotate", tag, "--message", f"VulnDockyard {version}", head)
        _run("git", "push", "origin", f"refs/tags/{tag}")
    assets = sorted(path for path in artifact_root.iterdir() if path.is_file())
    release = _release_view(tag)
    if release.returncode != 0:
        _run(
            "gh",
            "release",
            "create",
            tag,
            "--verify-tag",
            "--title",
            f"VulnDockyard {version}",
            "--notes-file",
            str(artifact_root / "RELEASE_NOTES.md"),
            *(str(path) for path in assets),
        )
        return
    remote_assets = _release_metadata(
        json.loads(release.stdout),
        tag=tag,
        version=version,
        notes=notes,
        expected_assets={path.name for path in assets},
    )
    with tempfile.TemporaryDirectory(prefix="vdy-existing-release-") as temporary:
        target = Path(temporary)
        for asset in assets:
            if asset.name not in remote_assets:
                _run("gh", "release", "upload", tag, str(asset))
                continue
            _run("gh", "release", "download", tag, "--pattern", asset.name, "--dir", str(target))
            if (
                hashlib.sha256((target / asset.name).read_bytes()).digest()
                != hashlib.sha256(asset.read_bytes()).digest()
            ):
                raise RuntimeError(
                    f"existing release asset differs; refusing overwrite: {asset.name}"
                )


def verify_published() -> None:
    version = os.environ.get("VDY_RELEASE_VERSION", "")
    if version != version_tools.authoritative_version():
        raise RuntimeError("requested published version does not match checked-out tag")
    tag = f"v{version}"
    if _run("git", "cat-file", "-t", tag).stdout.strip() != "tag":
        raise RuntimeError("published tag is not annotated")
    head = _run("git", "rev-parse", "HEAD").stdout.strip()
    if _remote_tag_commit(tag) != head:
        raise RuntimeError("published tag does not resolve to the checked-out commit")
    with tempfile.TemporaryDirectory(prefix="vdy-published-") as temporary:
        target = Path(temporary)
        _run("gh", "release", "download", tag, "--dir", str(target))
        _verify_sums(target, version)
        notes = (target / "RELEASE_NOTES.md").read_text(encoding="utf-8")
        if notes != _reviewed_notes(version):
            raise RuntimeError("published release notes differ from the reviewed changelog")
        release = _release_view(tag)
        if release.returncode != 0:
            raise RuntimeError("published release metadata is unavailable")
        _release_metadata(
            json.loads(release.stdout),
            tag=tag,
            version=version,
            notes=notes,
            expected_assets=_expected_artifacts(version),
        )
        source = target / f"VulnDockyard-{version}.tar.gz"
        if (
            hashlib.sha256(source.read_bytes()).digest()
            != hashlib.sha256(_source_archive(version)).digest()
        ):
            raise RuntimeError("published source archive does not match the checked-out tag")
        for artifact in sorted(target.iterdir()):
            _run("gh", "attestation", "verify", str(artifact), "--repo", REPOSITORY)
        wheel = next(target.glob("*.whl"))
        from scripts.generate_sbom import generate as generate_sbom

        generated_sbom = target / ".regenerated.spdx.json"
        generate_sbom(wheel, generated_sbom)
        published_sbom = target / f"vulndockyard-{version}.spdx.json"
        if generated_sbom.read_bytes() != published_sbom.read_bytes():
            raise RuntimeError("published SBOM does not describe the published wheel")
        venv = target / "venv"
        _run(sys.executable, "-m", "venv", str(venv))
        python = venv / "bin" / "python"
        _run(
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--require-hashes",
            "-r",
            str(ROOT / "requirements-dev.lock"),
        )
        _run(str(python), "-m", "pip", "install", "--no-deps", str(wheel))
        _run(str(python), "-m", "pip", "check")
        result = _run(str(python), "-m", "vulndockyard", "version", "--json")
        if json.loads(result.stdout)["data"]["version"] != version:
            raise RuntimeError("published wheel CLI version does not match")


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    operations = {"prepare": prepare, "publish": publish, "verify-published": verify_published}
    if len(values) != 1 or values[0] not in operations:
        print("Usage: release.py {prepare|publish|verify-published}", file=sys.stderr)
        return 2
    try:
        operations[values[0]]()
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"release operation failed: {exc}", file=sys.stderr)
        return 1
    print(f"release operation completed: {values[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
