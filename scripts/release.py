#!/usr/bin/env python3
"""Guarded, manual, idempotent release publication and verification."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import check_version as version_tools  # noqa: E402
from scripts.release_artifacts import build as build_artifacts  # noqa: E402

ORIGIN = "https://github.com/SoBatista/VulnDockyard.git"
REPOSITORY = "SoBatista/VulnDockyard"


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
    version = version_tools.check()
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
    if _run("git", "remote", "get-url", "origin").stdout.strip() != ORIGIN:
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
        "head_branch": "main",
        "head_sha": head,
        "conclusion": "success",
    }
    if not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items()):
        raise RuntimeError("CI run is not a successful CI result for this exact main commit")
    if value.get("event") not in {"push", "workflow_dispatch"}:
        raise RuntimeError("CI authorization must come from a main push or manual main run")


def prepare() -> None:
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


def _verify_sums(directory: Path) -> None:
    lines = (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    for line in lines:
        digest, separator, name = line.partition("  ")
        path = directory / name
        if (
            not separator
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise RuntimeError(f"published checksum mismatch: {name}")


def publish() -> None:
    version, head = _release_context()
    _verify_main_ci(head)
    artifact_root = ROOT / "artifacts" / "release"
    _verify_sums(artifact_root)
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
    assets = sorted(
        path
        for path in artifact_root.iterdir()
        if path.is_file() and path.name != "RELEASE_NOTES.md"
    )
    release = _run("gh", "release", "view", tag, "--json", "assets", check=False)
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
    remote_assets = {item["name"] for item in json.loads(release.stdout)["assets"]}
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
    with tempfile.TemporaryDirectory(prefix="vdy-published-") as temporary:
        target = Path(temporary)
        _run("gh", "release", "download", tag, "--dir", str(target))
        _verify_sums(target)
        wheel = next(target.glob("*.whl"))
        _run("gh", "attestation", "verify", str(wheel), "--repo", REPOSITORY)
        venv = target / "venv"
        _run(sys.executable, "-m", "venv", str(venv))
        python = venv / "bin" / "python"
        _run(str(python), "-m", "pip", "install", str(wheel))
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
