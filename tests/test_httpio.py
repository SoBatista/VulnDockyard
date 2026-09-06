from __future__ import annotations

import io
import threading
import time
import urllib.request
from types import TracebackType
from typing import Self

import pytest

from vulndockyard.httpio import fetch_bounded


class BlockingResponse:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def read1(self, amount: int) -> bytes:
        del amount
        self.closed.wait(timeout=5)
        return b""

    def close(self) -> None:
        self.closed.set()


def test_complete_http_operation_obeys_one_wall_clock_deadline() -> None:
    response = BlockingResponse()
    request = urllib.request.Request("https://example.test/metadata")
    started = time.monotonic()

    with pytest.raises(TimeoutError, match="wall-clock deadline"):
        fetch_bounded(
            request,
            opener=lambda requested, timeout: response,
            timeout=0.05,
            maximum=1024,
        )

    assert time.monotonic() - started < 0.5
    assert response.closed.wait(timeout=0.5)


def test_bounded_http_reader_returns_only_one_over_limit_byte() -> None:
    request = urllib.request.Request("https://example.test/metadata")

    assert (
        fetch_bounded(
            request,
            opener=lambda requested, timeout: io.BytesIO(b"12345"),
            timeout=1,
            maximum=4,
        )
        == b"12345"
    )
