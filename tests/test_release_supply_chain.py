from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest
from scripts import release as release_module
from scripts import secret_scan
from scripts.check_repository import _dependency_lock_failures
from scripts.check_version import check as check_version
from scripts.check_version import check_release_ready
from scripts.check_workflows import check as check_workflows
from scripts.generate_sbom import generate
from scripts.release import _expected_artifacts, _release_metadata, _verify_sums
from scripts.release_artifacts import changelog_notes


def test_dependency_lock_matches_uv_lock() -> None:
    assert _dependency_lock_failures() == []


def test_every_canonical_version_projection_is_consistent() -> None:
    assert check_version() == "1.0.0"


def test_unreleased_target_cannot_enter_publication_workflow() -> None:
    with pytest.raises(RuntimeError, match="unreleased target, not publication-ready"):
        check_release_ready()


def test_release_shaped_local_build_uses_reviewed_target_notes() -> None:
    notes = changelog_notes("1.0.0")
    assert notes.startswith("### Added\n")
    assert "not yet released" not in notes


def test_workflow_supply_chain_policy() -> None:
    check_workflows()


def test_secret_scan_covers_tracked_tree_and_reachable_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("safe\n", encoding="utf-8")
    binary = tmp_path / "gitleaks"
    binary.write_text("fixture\n", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    def record(arguments: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(secret_scan, "ROOT", tmp_path)
    monkeypatch.setattr(secret_scan, "install", lambda: binary)
    monkeypatch.setattr(secret_scan, "tracked_files", lambda: (tracked,))
    monkeypatch.setattr(subprocess, "run", record)

    secret_scan.scan()

    assert [call[1] for call in calls] == ["dir", "git"]
    assert "--log-opts=--all" in calls[1]
    assert calls[1][-1] == str(tmp_path)


def test_sbom_contains_exact_runtime_dependency_relationship(tmp_path: Path) -> None:
    wheel = tmp_path / "example-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("example/__init__.py", "")
        archive.writestr(
            "example-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.3\n"
            "Name: example\n"
            "Version: 1.2.3\n"
            "Requires-Dist: PyYAML==6.0.3\n"
            "Requires-Dist: pytest==9.1.1; extra == 'dev'\n",
        )
    output = tmp_path / "example.spdx.json"

    generate(wheel, output)

    sbom = json.loads(output.read_text(encoding="utf-8"))
    dependency = next(package for package in sbom["packages"] if package["name"] == "PyYAML")
    assert dependency["versionInfo"] == "6.0.3"
    assert dependency["filesAnalyzed"] is False
    assert dependency["externalRefs"][0]["referenceLocator"] == "pkg:pypi/pyyaml@6.0.3"
    assert all(package["name"] != "pytest" for package in sbom["packages"])
    assert {
        "spdxElementId": "SPDXRef-Package",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": dependency["SPDXID"],
    } in sbom["relationships"]
    assert sbom["packages"][0]["packageVerificationCode"]["packageVerificationCodeValue"]


def _write_release_fixture(root: Path, version: str) -> None:
    names = _expected_artifacts(version) - {"SHA256SUMS"}
    for name in names:
        (root / name).write_bytes(f"content for {name}\n".encode())
    sums = "".join(
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
        for name in sorted(names)
    )
    (root / "SHA256SUMS").write_text(sums, encoding="ascii")


def test_release_payload_requires_exact_checksums(tmp_path: Path) -> None:
    _write_release_fixture(tmp_path, "1.2.3")
    _verify_sums(tmp_path, "1.2.3")

    (tmp_path / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="artifact set mismatch"):
        _verify_sums(tmp_path, "1.2.3")


def test_release_payload_rejects_malformed_checksum_name(tmp_path: Path) -> None:
    _write_release_fixture(tmp_path, "1.2.3")
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(sums.read_text(encoding="ascii") + f"{'0' * 64}  ../escape\n", encoding="ascii")

    with pytest.raises(RuntimeError, match="malformed entry"):
        _verify_sums(tmp_path, "1.2.3")


def test_existing_release_metadata_must_match_exactly() -> None:
    assets = _expected_artifacts("1.2.3")
    metadata = {
        "tagName": "v1.2.3",
        "name": "VulnDockyard 1.2.3",
        "body": "reviewed notes\n",
        "isDraft": False,
        "isPrerelease": False,
        "assets": [{"name": name} for name in sorted(assets)],
    }
    assert (
        _release_metadata(
            metadata,
            tag="v1.2.3",
            version="1.2.3",
            notes="reviewed notes\n",
            expected_assets=assets,
        )
        == assets
    )

    metadata["isPrerelease"] = True
    with pytest.raises(RuntimeError, match="isPrerelease"):
        _release_metadata(
            metadata,
            tag="v1.2.3",
            version="1.2.3",
            notes="reviewed notes\n",
            expected_assets=assets,
        )


def test_release_authorization_is_bound_to_exact_ci_workflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VDY_CI_RUN_ID", "12345")
    response = {
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "head_branch": "main",
        "head_sha": "a" * 40,
        "conclusion": "success",
        "event": "push",
    }
    monkeypatch.setattr(
        release_module,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(response), ""),
    )
    release_module._verify_main_ci("a" * 40)

    response["path"] = ".github/workflows/lookalike.yml"
    with pytest.raises(RuntimeError, match="successful CI result"):
        release_module._verify_main_ci("a" * 40)
