"""Deadline- and size-bounded HTTP response retrieval."""

from __future__ import annotations

import math
import queue
import threading
import time
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from typing import Any, Protocol, cast


class ResponseOpener(Protocol):
    def __call__(self, request: urllib.request.Request, *, timeout: float) -> Any: ...


def _set_response_timeout(response: object, timeout: float) -> None:
    """Set the live urllib socket timeout when its implementation exposes one."""
    pending = [response]
    visited: set[int] = set()
    for _ in range(12):
        if not pending:
            return
        current = pending.pop(0)
        identity = id(current)
        if identity in visited:
            continue
        visited.add(identity)
        setter = getattr(current, "settimeout", None)
        if callable(setter):
            setter(max(0.001, timeout))
            return
        for attribute in ("fp", "raw", "_sock", "sock"):
            child = getattr(current, attribute, None)
            if child is not None:
                pending.append(child)


def _read_with_deadline(response: object, *, deadline: float, maximum: int) -> bytes:
    payload = bytearray()
    while len(payload) <= maximum:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP response exceeded its wall-clock deadline")
        _set_response_timeout(response, remaining)
        reader = getattr(response, "read1", None)
        if not callable(reader):
            reader = cast(Any, response).read
        chunk = reader(min(65_536, maximum + 1 - len(payload)))
        if not isinstance(chunk, bytes):
            raise OSError("HTTP response returned a non-bytes body")
        if not chunk:
            break
        payload.extend(chunk)
        if time.monotonic() > deadline:
            raise TimeoutError("HTTP response exceeded its wall-clock deadline")
    return bytes(payload)


def fetch_bounded(
    request: urllib.request.Request,
    *,
    opener: ResponseOpener,
    timeout: float,
    maximum: int,
    validate_response: Callable[[object], None] | None = None,
) -> bytes:
    """Open and read a response under one caller-visible wall-clock deadline.

    Name resolution and TLS setup are not reliably governed by urllib's socket timeout,
    so the complete operation runs in a short-lived daemon thread. On expiry the caller
    closes any acquired response and returns immediately; the worker cannot mutate state.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("HTTP timeout must be finite and positive")
    if maximum < 1:
        raise ValueError("HTTP maximum must be positive")
    deadline = time.monotonic() + timeout
    outcome: queue.Queue[tuple[bytes | None, Exception | None]] = queue.Queue(maxsize=1)
    response_lock = threading.Lock()
    response_holder: list[object] = []

    def retrieve() -> None:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP operation exceeded its wall-clock deadline")
            response = opener(request, timeout=remaining)
            with response_lock:
                response_holder.append(response)
            with response:
                if validate_response is not None:
                    validate_response(response)
                payload = _read_with_deadline(response, deadline=deadline, maximum=maximum)
            outcome.put_nowait((payload, None))
        except Exception as exc:
            with suppress(queue.Full):
                outcome.put_nowait((None, exc))
        finally:
            with response_lock:
                response_holder.clear()

    worker = threading.Thread(target=retrieve, name="vdy-bounded-http", daemon=True)
    worker.start()
    try:
        payload, error = outcome.get(timeout=timeout)
    except queue.Empty as exc:
        with response_lock:
            response = response_holder[0] if response_holder else None
        closer = getattr(response, "close", None)
        if callable(closer):
            with suppress(OSError):
                closer()
        raise TimeoutError("HTTP operation exceeded its wall-clock deadline") from exc
    if error is not None:
        raise error
    if payload is None:  # pragma: no cover - queue entries are created atomically above
        raise OSError("HTTP operation produced no response body")
    return payload
