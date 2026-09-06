from __future__ import annotations

import pytest
from scripts import check_dco


@pytest.mark.parametrize(
    ("message", "expected"),
    (
        ("fix: example\n\nSigned-off-by: Ada Lovelace <ada@example.test>\n", True),
        ("fix: example\n", False),
        ("Signed-off-by: Someone Else <ada@example.test>\n", False),
        ("Signed-off-by: Ada Lovelace <other@example.test>\n", False),
        (
            "fix: example\n\nSigned-off-by: Ada Lovelace <ada@example.test>\n\nMore body.\n",
            False,
        ),
        (
            "fix: example\n\nSigned-off-by: Ada Lovelace <ada@example.test>\n"
            "Co-authored-by: Grace Hopper <grace@example.test>\n",
            True,
        ),
    ),
)
def test_author_signoff_requires_matching_name_and_email(message: str, expected: bool) -> None:
    assert check_dco._has_author_signoff("Ada Lovelace", "ada@example.test", message) is expected


def test_check_reports_every_unsigned_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    first = "a" * 40
    second = "b" * 40
    monkeypatch.setenv("VDY_BASE_SHA", "c" * 40)
    monkeypatch.setattr(check_dco, "_commits", lambda base: (first, second))
    monkeypatch.setattr(
        check_dco,
        "_commit_identity",
        lambda commit: (
            "Ada Lovelace",
            "ada@example.test",
            (
                "Signed-off-by: Ada Lovelace <ada@example.test>\n"
                if commit == first
                else "unsigned\n"
            ),
        ),
    )

    with pytest.raises(RuntimeError, match=second[:12]):
        check_dco.check()
