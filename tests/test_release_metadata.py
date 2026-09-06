from __future__ import annotations

import pytest
from scripts import check_release_metadata


def _bootstrap_context(monkeypatch: pytest.MonkeyPatch, *, released: bool) -> None:
    monkeypatch.setenv("VDY_BASE_SHA", "a" * 40)
    monkeypatch.setattr(check_release_metadata, "authoritative_version", lambda: "1.0.0")
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
