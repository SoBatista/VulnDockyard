from __future__ import annotations

import io
from types import TracebackType

import pytest

from vulndockyard.catalogue import Catalogue
from vulndockyard.errors import IntegrityError, PolicyError
from vulndockyard.updates import apply_reviewed_update, check_latest, transactional_replace


class Response(io.BytesIO):
    def __enter__(self) -> Response:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def opener(tag: str):  # type: ignore[no-untyped-def]
    def open_response(request: object, *, timeout: float) -> Response:
        assert str(request).startswith("<urllib.request.Request")
        assert timeout == 10
        return Response(f'{{"tag_name":"{tag}"}}'.encode())

    return open_response


def test_update_check_is_read_only_and_semver_aware() -> None:
    lab = Catalogue().get("juice-shop")
    current = check_latest(lab, opener=opener("v20.2.0"))
    assert current.read_only and not current.update_available
    assert apply_reviewed_update(lab, current) == "already-current"
    newer = check_latest(lab, opener=opener("v20.3.0"))
    assert newer.update_available
    with pytest.raises(PolicyError, match="no reviewed immutable lock"):
        apply_reviewed_update(lab, newer)


def test_update_check_rejects_malformed_release() -> None:
    lab = Catalogue().get("juice-shop")
    with pytest.raises(IntegrityError, match="non-SemVer"):
        check_latest(lab, opener=opener("latest"))


class Transaction:
    def __init__(self, fail: bool) -> None:
        self.fail = fail
        self.events: list[str] = []

    def stage(self) -> None:
        self.events.append("stage")

    def smoke(self) -> None:
        self.events.append("smoke")
        if self.fail:
            raise RuntimeError("candidate failed identity")

    def activate(self) -> None:
        self.events.append("activate")

    def rollback(self) -> None:
        self.events.append("rollback")

    def discard_candidate(self) -> None:
        self.events.append("discard")


def test_transaction_activates_only_after_smoke() -> None:
    value = Transaction(False)
    transactional_replace(value)
    assert value.events == ["stage", "smoke", "activate"]


def test_failed_update_rolls_back_and_discards_candidate() -> None:
    value = Transaction(True)
    with pytest.raises(RuntimeError, match="identity"):
        transactional_replace(value)
    assert value.events == ["stage", "smoke", "rollback", "discard"]
