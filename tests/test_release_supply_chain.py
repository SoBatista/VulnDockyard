from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest
from scripts import release as release_module
from scripts import secret_scan
from scripts.check_repository import (
    _contributor_covenant_failures,
    _dependency_lock_failures,
    _requirement_records,
)
from scripts.check_version import (
    _projection_state,
    check_release_ready,
    release_changelog_notes,
    target_changelog_notes,
    validate_bootstrap_notes_moved,
)
from scripts.check_version import check as check_version
from scripts.check_workflows import check as check_workflows
from scripts.generate_sbom import generate, validate_spdx
from scripts.release import _expected_artifacts, _release_metadata, _verify_sums
from scripts.release_artifacts import changelog_notes


def test_dependency_lock_matches_uv_lock() -> None:
    assert _dependency_lock_failures() == []


def test_runtime_lock_contains_only_declared_runtime_dependencies() -> None:
    records = _requirement_records(Path("requirements-runtime.lock"))

    assert len(records) == 1
    assert records[0].startswith("pyyaml==6.0.3 ")
    assert "pytest" not in records[0]


def test_code_of_conduct_is_the_complete_reviewed_contributor_covenant(
    tmp_path: Path,
) -> None:
    assert _contributor_covenant_failures(Path("CODE_OF_CONDUCT.md")) == []

    abridged = tmp_path / "CODE_OF_CONDUCT.md"
    abridged.write_text("# Contributor Covenant Code of Conduct\n", encoding="utf-8")
    assert _contributor_covenant_failures(abridged) == [
        "CODE_OF_CONDUCT.md must match the reviewed complete Contributor Covenant 2.1 text "
        "with only the SECURITY.md enforcement-contact adaptation"
    ]


def test_every_canonical_version_projection_is_consistent() -> None:
    assert check_version() == "1.0.0"


def test_unreleased_target_cannot_enter_publication_workflow() -> None:
    with pytest.raises(RuntimeError, match="unreleased target, not publication-ready"):
        check_release_ready()


def test_released_projection_rejects_unreleased_target_markers() -> None:
    version = "1.2.3"
    readme = (
        "https://img.shields.io/badge/version-1.2.3-blue\n"
        "Version: `1.2.3`\n"
        "Target version: `1.2.3` (unreleased; release gates incomplete).\n"
    )
    changelog = (
        "## [Unreleased]\n\n"
        "Target release: 1.2.3 (not yet released).\n\n"
        "## [1.2.3] - 2026-09-06\n\n"
        "[Unreleased]: https://github.com/SoBatista/VulnDockyard/compare/v1.2.3...HEAD\n"
        "[1.2.3]: https://github.com/SoBatista/VulnDockyard/releases/tag/v1.2.3\n"
    )

    with pytest.raises(RuntimeError, match="consistently describe"):
        _projection_state(version, readme, changelog)


def test_target_projection_rejects_released_markers() -> None:
    version = "1.2.3"
    readme = (
        "https://img.shields.io/badge/target--version-1.2.3-orange\n"
        "Target version: `1.2.3` (unreleased; release gates incomplete).\n"
        "Version: `1.2.3`\n"
    )
    changelog = (
        "## [Unreleased]\n\n"
        "Target release: 1.2.3 (not yet released).\n\n"
        "[Unreleased]: https://github.com/SoBatista/VulnDockyard/commits/main\n"
    )

    with pytest.raises(RuntimeError, match="consistently describe"):
        _projection_state(version, readme, changelog)


def _released_projection() -> tuple[str, str]:
    readme = "https://img.shields.io/badge/version-1.2.3-blue\nVersion: `1.2.3`\n"
    changelog = (
        "## [Unreleased]\n\n"
        "## [1.2.3] - 2026-09-06\n\n"
        "### Fixed\n\n"
        "- Closed one reviewed defect.\n\n"
        "[Unreleased]: https://github.com/SoBatista/VulnDockyard/compare/v1.2.3...HEAD\n"
        "[1.2.3]: https://github.com/SoBatista/VulnDockyard/releases/tag/v1.2.3\n"
    )
    return readme, changelog


def test_released_projection_requires_exactly_one_categorized_section() -> None:
    readme, changelog = _released_projection()

    assert _projection_state("1.2.3", readme, changelog) == "released"

    duplicate = changelog.replace(
        "### Fixed", "## [1.2.3] - 2026-09-06\n\n### Added\n\n- Duplicate.\n\n### Fixed"
    )
    with pytest.raises(RuntimeError, match="consistently describe"):
        _projection_state("1.2.3", readme, duplicate)

    uncategorized = changelog.replace(
        "### Fixed\n\n- Closed one reviewed defect.\n\n",
        "Release text without categorized notes.\n\n",
    )
    with pytest.raises(RuntimeError, match="consistently describe"):
        _projection_state("1.2.3", readme, uncategorized)


def test_release_shaped_local_build_uses_reviewed_target_notes() -> None:
    notes = changelog_notes("1.0.0")
    assert notes.startswith("### Added\n")
    assert "not yet released" not in notes
    assert "[Unreleased]:" not in notes


def test_changelog_note_extraction_excludes_reference_links() -> None:
    target = (
        "## [Unreleased]\n\nTarget release: 1.0.0 (not yet released).\n\n"
        "### Added\n\n- Reviewed note.\n\n[Unreleased]: target-link\n"
    )
    released = (
        "## [Unreleased]\n\n## [1.0.0] - 2026-09-06\n\n"
        "### Added\n\n- Reviewed note.\n\n"
        "[Unreleased]: compare-link\n[1.0.0]: release-link\n"
    )

    assert target_changelog_notes("1.0.0", target) == "### Added\n\n- Reviewed note.\n"
    assert release_changelog_notes("1.0.0", released) == "### Added\n\n- Reviewed note.\n"
    validate_bootstrap_notes_moved(target, released, "1.0.0")


def test_workflow_supply_chain_policy() -> None:
    check_workflows()


def test_dependency_environment_check_is_consolidated() -> None:
    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    security = Path(".github/workflows/security.yml").read_text(encoding="utf-8")
    ci_check = Path("scripts/ci-check.sh").read_text(encoding="utf-8")

    assert "scripts/ci-check.sh" in ci
    assert "pip check" not in ci
    assert ci_check.count('"${VDY_PYTHON}" scripts/check_environment.py') == 1
    assert "dependency-lock:" not in security
    assert "requirements-dev.lock" not in security
    assert "pip check" not in security


def test_post_release_installs_pinned_verifier_before_validation() -> None:
    workflow = Path(".github/workflows/post-release.yml").read_text(encoding="utf-8")
    install = "pip install --disable-pip-version-check --require-hashes -r requirements-dev.lock"

    assert workflow.index(install) < workflow.index("python scripts/release.py verify-published")


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
    assert all(file["licenseConcluded"] == "NOASSERTION" for file in sbom["files"])
    assert all(file["licenseInfoInFiles"] == ["NOASSERTION"] for file in sbom["files"])
    assert all(file["copyrightText"] == "NOASSERTION" for file in sbom["files"])


def test_official_spdx_validation_rejects_an_incomplete_file_record(tmp_path: Path) -> None:
    wheel = tmp_path / "example-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("example/__init__.py", "")
        archive.writestr(
            "example-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.3\nName: example\nVersion: 1.2.3\n",
        )
    output = tmp_path / "example.spdx.json"
    generate(wheel, output)
    sbom = json.loads(output.read_text(encoding="utf-8"))
    del sbom["files"][0]["fileName"]
    output.write_text(json.dumps(sbom), encoding="utf-8")

    with pytest.raises(RuntimeError, match="official SPDX validation"):
        validate_spdx(output)


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
