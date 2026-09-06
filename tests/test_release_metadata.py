from __future__ import annotations

import pytest
from scripts import check_release_metadata


def _bootstrap_context(monkeypatch: pytest.MonkeyPatch, *, released: bool) -> None:
    monkeypatch.setenv("VDY_BASE_SHA", "a" * 40)
    monkeypatch.setattr(check_release_metadata, "check_version_projections", lambda: "1.0.0")
    monkeypatch.setattr(check_release_metadata, "_base_version", lambda value: "1.0.0")
    monkeypatch.setattr(
        check_release_metadata,
        "_bootstrap_release_is_ancestor",
        lambda value: False,
    )
    monkeypatch.setattr(
        check_release_metadata,
        "_base_changelog_has_bootstrap_release",
        lambda value: released,
    )


def test_unreleased_bootstrap_does_not_require_a_release_impact_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bootstrap_context(monkeypatch, released=False)
    check_release_metadata.check()


def test_released_bootstrap_cannot_bypass_policy_when_tag_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bootstrap_context(monkeypatch, released=True)
    with pytest.raises(RuntimeError, match="tag is missing"):
        check_release_metadata.check()


def test_post_bootstrap_release_requires_label_increment_and_new_changelog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_sha = "b" * 40
    calls: list[tuple[str, str]] = []
    monkeypatch.setenv("VDY_BASE_SHA", base_sha)
    monkeypatch.setattr(check_release_metadata, "check_version_projections", lambda: "1.2.4")
    monkeypatch.setattr(check_release_metadata, "_base_version", lambda value: "1.2.3")
    monkeypatch.setattr(
        check_release_metadata, "_bootstrap_release_is_ancestor", lambda value: True
    )
    monkeypatch.setattr(check_release_metadata, "_live_labels", lambda: {"release:patch"})
    monkeypatch.setattr(
        check_release_metadata,
        "_reviewed_changelog_increment",
        lambda base, version: calls.append((base, version)),
    )

    check_release_metadata.check()

    assert calls == [(base_sha, "1.2.4")]


def test_reviewed_changelog_rejects_section_without_notes() -> None:
    base = "## [Unreleased]\n\n[Unreleased]: example\n"
    current = (
        "## [Unreleased]\n\n"
        "## [1.2.4] - 2026-09-06\n\n"
        "[1.2.4]: https://github.com/SoBatista/VulnDockyard/releases/tag/v1.2.4\n"
    )

    with pytest.raises(RuntimeError, match="categorized notes"):
        check_release_metadata._validate_reviewed_changelog(base, current, "1.2.4")


def test_reviewed_changelog_accepts_exact_new_section_and_link() -> None:
    base = "## [Unreleased]\n\n[Unreleased]: example\n"
    current = (
        "## [Unreleased]\n\n"
        "## [1.2.4] - 2026-09-06\n\n"
        "### Fixed\n\n"
        "- Closed one reviewed defect.\n\n"
        "[Unreleased]: compare\n"
        "[1.2.4]: https://github.com/SoBatista/VulnDockyard/releases/tag/v1.2.4\n"
    )

    check_release_metadata._validate_reviewed_changelog(base, current, "1.2.4")
