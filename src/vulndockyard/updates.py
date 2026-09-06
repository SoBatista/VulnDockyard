"""Read-only discovery and transactional reviewed-update primitives."""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self
from urllib.parse import urlparse

from .catalogue import ReviewedLab
from .errors import IntegrityError, PolicyError, PreflightError
from .httpio import fetch_bounded
from .jsonio import StrictJSONError, strict_json_loads

if TYPE_CHECKING:
    from .runtime import RuntimeUpdate

SEMVER_TAG = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        return None


@dataclass(frozen=True)
class UpdateCheck:
    lab_id: str
    current: str
    available: str
    update_available: bool
    read_only: bool = True
    activation: str = "requires-reviewed-lock-and-smoke-test"


def _version(tag: str) -> tuple[int, int, int]:
    match = SEMVER_TAG.fullmatch(tag)
    if match is None:
        raise IntegrityError(f"upstream returned a non-SemVer release tag: {tag}")
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


class ReleaseOpener(Protocol):
    def __call__(self, request: urllib.request.Request, *, timeout: float) -> ReleaseResponse: ...


class ReleaseResponse(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def read(self, amount: int) -> bytes: ...


def _open_release(request: urllib.request.Request, *, timeout: float) -> ReleaseResponse:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)  # type: ignore[no-any-return]


def check_latest(
    lab: ReviewedLab,
    *,
    opener: ReleaseOpener = _open_release,
    timeout: float = 10,
) -> UpdateCheck:
    if not math.isfinite(timeout) or not 1 <= timeout <= 60:
        raise PolicyError("release discovery timeout must be between 1 and 60 seconds")
    repository = urlparse(str(lab.manifest.raw["upstream"]["repository"]))
    parts = repository.path.strip("/").removesuffix(".git").split("/")
    current = str(lab.manifest.raw["version"]["tag"])
    if repository.netloc.lower() != "github.com" or len(parts) != 2:
        raise PolicyError(
            "automated release discovery is available only for canonical GitHub repositories"
        )
    url = f"https://api.github.com/repos/{parts[0]}/{parts[1]}/releases/latest"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "VulnDockyard/1"},
    )
    try:
        payload = fetch_bounded(request, opener=opener, timeout=timeout, maximum=131_072)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PreflightError(f"upstream release discovery failed: {exc}") from exc
    if len(payload) > 131_072:
        raise IntegrityError("upstream release response exceeded 128 KiB")
    try:
        value = strict_json_loads(payload)
        latest = value["tag_name"]
    except (json.JSONDecodeError, StrictJSONError, KeyError, TypeError) as exc:
        raise IntegrityError("upstream release response is malformed") from exc
    if not isinstance(latest, str):
        raise IntegrityError("upstream release tag is malformed")
    return UpdateCheck(lab.manifest.id, current, latest, _version(latest) > _version(current))


class Transaction(Protocol):
    def stage(self) -> None: ...
    def smoke(self) -> None: ...
    def activate(self) -> None: ...
    def rollback(self) -> None: ...
    def discard_candidate(self) -> None: ...


def transactional_replace(transaction: Transaction) -> None:
    """Keep current deployment recoverable until a candidate verifies and activates."""
    transaction.stage()
    try:
        transaction.smoke()
        transaction.activate()
    except BaseException:
        transaction.rollback()
        transaction.discard_candidate()
        raise


class UpdateRuntime(Protocol):
    def activate_reviewed_update(self, lab: ReviewedLab) -> RuntimeUpdate: ...


class UpdateDiscovery(Protocol):
    def __call__(self, lab: ReviewedLab) -> UpdateCheck: ...


def apply_reviewed_update(
    lab: ReviewedLab,
    runtime: UpdateRuntime,
    *,
    discover: UpdateDiscovery = check_latest,
) -> RuntimeUpdate:
    candidate = runtime.activate_reviewed_update(lab)
    if candidate.outcome == "activated":
        return candidate
    update = discover(lab)
    if update.lab_id != lab.manifest.id:
        raise IntegrityError("update candidate does not match the selected lab")
    if not update.update_available:
        return candidate
    raise PolicyError(
        f"{update.available} is discoverable but has no reviewed immutable lock in this release; "
        "the current known-good deployment was preserved"
    )
