"""Atomic local runtime state records."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .errors import IntegrityError
from .paths import Paths


@dataclass(frozen=True)
class ResourceRecord:
    kind: str
    name: str
    object_id: str


@dataclass(frozen=True)
class RunState:
    schema_version: int
    lab_id: str
    run_id: str
    manifest_identity: str
    manifest_version: int
    created_at: str
    host_port: int
    trusted: bool
    requested_reference: str
    resolved_digest: str
    resources: tuple[ResourceRecord, ...]

    @classmethod
    def create(
        cls,
        *,
        lab_id: str,
        run_id: str,
        manifest_identity: str,
        host_port: int,
        trusted: bool,
        requested_reference: str,
        resolved_digest: str,
        resources: tuple[ResourceRecord, ...],
        created_at: str | None = None,
    ) -> RunState:
        return cls(
            1,
            lab_id,
            run_id,
            manifest_identity,
            1,
            created_at
            or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            host_port,
            trusted,
            requested_reference,
            resolved_digest,
            resources,
        )

    @classmethod
    def parse(cls, value: object) -> RunState:
        if not isinstance(value, dict):
            raise IntegrityError("run state must be an object")
        data = cast(dict[str, Any], value)
        keys = {
            "schema_version",
            "lab_id",
            "run_id",
            "manifest_identity",
            "manifest_version",
            "created_at",
            "host_port",
            "trusted",
            "requested_reference",
            "resolved_digest",
            "resources",
        }
        if data.keys() != keys:
            raise IntegrityError("run state contains missing or unknown fields")
        if data["schema_version"] != 1 or data["manifest_version"] != 1:
            raise IntegrityError("unsupported run state version")
        if not isinstance(data["host_port"], int) or not 1 <= data["host_port"] <= 65535:
            raise IntegrityError("run state host port is invalid")
        if not isinstance(data["trusted"], bool):
            raise IntegrityError("run state trusted marker is invalid")
        string_keys = (
            "lab_id",
            "run_id",
            "manifest_identity",
            "created_at",
            "requested_reference",
            "resolved_digest",
        )
        if any(not isinstance(data[key], str) or not data[key] for key in string_keys):
            raise IntegrityError("run state contains an invalid string")
        raw_resources = data["resources"]
        if not isinstance(raw_resources, list):
            raise IntegrityError("run state resources must be an array")
        resources: list[ResourceRecord] = []
        for value in raw_resources:
            if not isinstance(value, dict) or value.keys() != {"kind", "name", "object_id"}:
                raise IntegrityError("run state resource is malformed")
            if any(not isinstance(value[key], str) or not value[key] for key in value):
                raise IntegrityError("run state resource fields must be strings")
            resources.append(ResourceRecord(value["kind"], value["name"], value["object_id"]))
        return cls(
            1,
            data["lab_id"],
            data["run_id"],
            data["manifest_identity"],
            1,
            data["created_at"],
            data["host_port"],
            data["trusted"],
            data["requested_reference"],
            data["resolved_digest"],
            tuple(resources),
        )


class StateStore:
    def __init__(self, paths: Paths) -> None:
        self.paths = paths

    def path(self, lab_id: str) -> Path:
        return self.paths.state / "runs" / f"{lab_id}.json"

    def load(self, lab_id: str) -> RunState | None:
        path = self.path(lab_id)
        if path.is_symlink():
            raise IntegrityError(f"run state is a symlink: {path}")
        try:
            return RunState.parse(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"cannot read run state for {lab_id}: {exc}") from exc

    def save(self, state: RunState) -> None:
        directory = self.path(state.lab_id).parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(asdict(state), handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path(state.lab_id))
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def delete(self, lab_id: str) -> None:
        path = self.path(lab_id)
        if path.is_symlink():
            raise IntegrityError("refusing symlinked run state")
        with contextlib.suppress(FileNotFoundError):
            path.unlink()

    def all(self) -> tuple[RunState, ...]:
        directory = self.paths.state / "runs"
        if not directory.exists():
            return ()
        if directory.is_symlink():
            raise IntegrityError("run state directory is a symlink")
        states = []
        for path in sorted(directory.glob("*.json")):
            state = self.load(path.stem)
            if state is not None:
                states.append(state)
        return tuple(states)
