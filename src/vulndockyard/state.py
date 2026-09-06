"""Atomic local runtime state records."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .errors import IntegrityError, PreflightError
from .jsonio import StrictJSONError, strict_json_loads
from .models import DIGEST, HOSTNAME, LAB_ID, OCI_NAME, UTC_TIMESTAMP, EphemeralStorage, Service
from .paths import Paths


@dataclass(frozen=True)
class ResourceRecord:
    kind: str
    name: str
    object_id: str


@dataclass(frozen=True)
class RuntimePolicySnapshot:
    memory_mb: int
    cpus: float
    pids: int
    read_only_root: bool
    outbound_required: bool
    ephemeral_storage: EphemeralStorage
    friendly_hostname: str
    health_timeout_seconds: int
    services: tuple[Service, ...]
    persistence_required: bool = False

    @classmethod
    def parse(cls, value: object, *, legacy: bool = False) -> RuntimePolicySnapshot:
        if not isinstance(value, dict):
            raise IntegrityError("runtime policy snapshot must be an object")
        data = cast(dict[str, Any], value)
        keys = {
            "memory_mb",
            "cpus",
            "pids",
            "read_only_root",
            "outbound_required",
            "ephemeral_storage",
            "friendly_hostname",
            "health_timeout_seconds",
            "services",
        }
        if not legacy:
            keys.add("persistence_required")
        if data.keys() != keys:
            raise IntegrityError("runtime policy snapshot contains missing or unknown fields")
        memory = data["memory_mb"]
        cpus = data["cpus"]
        pids = data["pids"]
        if (
            not isinstance(memory, int)
            or isinstance(memory, bool)
            or not 128 <= memory <= 16_384
            or not isinstance(cpus, int | float)
            or isinstance(cpus, bool)
            or not 0.1 <= float(cpus) <= 8
            or not isinstance(pids, int)
            or isinstance(pids, bool)
            or not 16 <= pids <= 4096
        ):
            raise IntegrityError("runtime policy snapshot resource limits are invalid")
        if data["read_only_root"] is not True:
            raise IntegrityError("runtime policy snapshot must require a read-only root")
        if not isinstance(data["outbound_required"], bool):
            raise IntegrityError("runtime policy snapshot outbound marker is invalid")
        persistence_required = False if legacy else data["persistence_required"]
        if not isinstance(persistence_required, bool):
            raise IntegrityError("runtime policy snapshot persistence marker is invalid")
        hostname = data["friendly_hostname"]
        timeout = data["health_timeout_seconds"]
        raw_services = data["services"]
        if not isinstance(hostname, str) or HOSTNAME.fullmatch(hostname) is None:
            raise IntegrityError("runtime policy snapshot hostname is invalid")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 900:
            raise IntegrityError("runtime policy snapshot health timeout is invalid")
        if not isinstance(raw_services, list) or not raw_services:
            raise IntegrityError("runtime policy snapshot services must be a non-empty array")
        services = tuple(Service.parse(item) for item in raw_services)
        names = [service.name for service in services]
        if (
            len(names) != len(set(names))
            or len({service.internal_port for service in services}) != 1
            or any(
                service.image_role != "application"
                or service.protocol != "http"
                or len(service.identity_marker) > 160
                or not service.identity_marker.isprintable()
                for service in services
            )
        ):
            raise IntegrityError("runtime policy snapshot health services are invalid")
        return cls(
            memory,
            float(cpus),
            pids,
            True,
            data["outbound_required"],
            EphemeralStorage.parse(data["ephemeral_storage"]),
            hostname,
            timeout,
            services,
            persistence_required,
        )


def _persistent_volume_names(lab_id: str, run_id: str, policy: RuntimePolicySnapshot) -> set[str]:
    prefix = f"vdy-{lab_id}-{run_id[:12]}-volume-"
    mounts = policy.ephemeral_storage.seeded + policy.ephemeral_storage.empty
    return {f"{prefix}{mount.name}" for mount in mounts}


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
    gateway_reference: str | None
    upstream_port: int | None
    runtime_policy: RuntimePolicySnapshot | None
    phase: str = "steady"

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
        gateway_reference: str | None = None,
        upstream_port: int | None = None,
        runtime_policy: RuntimePolicySnapshot | None = None,
        created_at: str | None = None,
        phase: str = "steady",
    ) -> RunState:
        if (gateway_reference is None) != (upstream_port is None):
            raise ValueError("gateway reference and upstream port must be recorded together")
        if runtime_policy is not None and gateway_reference is None:
            raise ValueError("runtime policy requires a complete gateway snapshot")
        if phase not in {"steady", "rebuild"}:
            raise ValueError("run state phase must be steady or rebuild")
        if phase == "rebuild" and (
            runtime_policy is None or not runtime_policy.persistence_required
        ):
            raise ValueError("rebuild phase requires a complete persistent runtime snapshot")
        if phase == "rebuild" and runtime_policy is not None:
            expected_volumes = _persistent_volume_names(lab_id, run_id, runtime_policy)
            recorded_volumes = {
                resource.name for resource in resources if resource.kind == "volume"
            }
            if not expected_volumes or recorded_volumes != expected_volumes:
                raise ValueError("rebuild phase requires every deterministic persistent volume")
        return cls(
            4 if runtime_policy is not None else 2 if gateway_reference is not None else 1,
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
            gateway_reference,
            upstream_port,
            runtime_policy,
            phase,
        )

    @classmethod
    def parse(cls, value: object) -> RunState:
        if not isinstance(value, dict):
            raise IntegrityError("run state must be an object")
        data = cast(dict[str, Any], value)
        common_keys = {
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
        schema_version = data.get("schema_version")
        v2_keys = common_keys | {"gateway_reference", "upstream_port"}
        v3_keys = v2_keys | {"runtime_policy"}
        v4_keys = v3_keys | {"phase"}
        keys_valid = (
            data.keys() == v4_keys
            if schema_version == 4
            else data.keys() == v3_keys
            if schema_version == 3
            else data.keys() == v2_keys
            if schema_version == 2
            else data.keys() == common_keys or data.keys() == v2_keys
        )
        if not keys_valid:
            raise IntegrityError("run state contains missing or unknown fields")
        if schema_version not in {1, 2, 3, 4} or data["manifest_version"] != 1:
            raise IntegrityError("unsupported run state version")
        if (
            not isinstance(data["host_port"], int)
            or isinstance(data["host_port"], bool)
            or not 1 <= data["host_port"] <= 65535
        ):
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
        if not LAB_ID.fullmatch(data["lab_id"]):
            raise IntegrityError("run state lab ID is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", data["run_id"]):
            raise IntegrityError("run state run ID is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", data["manifest_identity"]):
            raise IntegrityError("run state manifest identity is invalid")
        if not DIGEST.fullmatch(data["resolved_digest"]):
            raise IntegrityError("run state resolved digest is invalid")
        reference_parts = data["requested_reference"].rsplit("@", 1)
        if (
            len(reference_parts) != 2
            or OCI_NAME.fullmatch(reference_parts[0]) is None
            or not DIGEST.fullmatch(reference_parts[1])
            or reference_parts[1] != data["resolved_digest"]
        ):
            raise IntegrityError("run state requested reference and resolved digest are invalid")
        gateway_reference: str | None = None
        upstream_port: int | None = None
        if (
            schema_version == 1
            and data.keys() == v2_keys
            and (data["gateway_reference"] is not None or data["upstream_port"] is not None)
        ):
            raise IntegrityError("legacy run state contains invalid rollback fields")
        if schema_version in {2, 3, 4}:
            gateway_reference = data["gateway_reference"]
            upstream_port = data["upstream_port"]
            if not isinstance(gateway_reference, str) or "@" not in gateway_reference:
                raise IntegrityError("run state gateway reference is invalid")
            gateway_name, gateway_digest = gateway_reference.rsplit("@", 1)
            if OCI_NAME.fullmatch(gateway_name) is None or DIGEST.fullmatch(gateway_digest) is None:
                raise IntegrityError("run state gateway reference is invalid")
            if (
                not isinstance(upstream_port, int)
                or isinstance(upstream_port, bool)
                or not 1 <= upstream_port <= 65535
            ):
                raise IntegrityError("run state upstream port is invalid")
        runtime_policy: RuntimePolicySnapshot | None = None
        phase = "steady"
        if schema_version in {3, 4}:
            runtime_policy = RuntimePolicySnapshot.parse(
                data["runtime_policy"], legacy=schema_version == 3
            )
            if upstream_port is None or any(
                service.internal_port != upstream_port for service in runtime_policy.services
            ):
                raise IntegrityError("run state health services differ from its gateway snapshot")
        if schema_version == 4:
            phase = data["phase"]
            if phase not in {"steady", "rebuild"}:
                raise IntegrityError("run state phase is invalid")
            if phase == "rebuild" and (
                runtime_policy is None or not runtime_policy.persistence_required
            ):
                raise IntegrityError(
                    "rebuild phase requires a complete persistent runtime snapshot"
                )
        if UTC_TIMESTAMP.fullmatch(data["created_at"]) is None:
            raise IntegrityError("run state creation timestamp is invalid")
        try:
            created = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise IntegrityError("run state creation timestamp is invalid") from exc
        if created.tzinfo != UTC:
            raise IntegrityError("run state creation timestamp is invalid")
        raw_resources = data["resources"]
        if not isinstance(raw_resources, list):
            raise IntegrityError("run state resources must be an array")
        resources: list[ResourceRecord] = []
        for value in raw_resources:
            if not isinstance(value, dict) or value.keys() != {"kind", "name", "object_id"}:
                raise IntegrityError("run state resource is malformed")
            if any(not isinstance(value[key], str) or not value[key] for key in value):
                raise IntegrityError("run state resource fields must be strings")
            if value["kind"] not in {"container", "network", "volume"}:
                raise IntegrityError("run state resource kind is invalid")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value["name"]):
                raise IntegrityError("run state resource name is invalid")
            object_id_valid = (
                value["object_id"] == value["name"]
                if value["kind"] == "volume"
                else bool(re.fullmatch(r"[0-9a-f]{64}", value["object_id"]))
            )
            if not object_id_valid:
                raise IntegrityError("run state resource ID is invalid")
            resources.append(ResourceRecord(value["kind"], value["name"], value["object_id"]))
        resource_keys = [(resource.kind, resource.object_id) for resource in resources]
        resource_names = [resource.name for resource in resources]
        if len(resource_keys) != len(set(resource_keys)) or len(resource_names) != len(
            set(resource_names)
        ):
            raise IntegrityError("run state contains duplicate resources")
        if phase == "rebuild" and runtime_policy is not None:
            expected_volumes = _persistent_volume_names(
                data["lab_id"], data["run_id"], runtime_policy
            )
            recorded_volumes = {
                resource.name for resource in resources if resource.kind == "volume"
            }
            if not expected_volumes or recorded_volumes != expected_volumes:
                raise IntegrityError("rebuild phase requires every deterministic persistent volume")
        return cls(
            schema_version,
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
            gateway_reference,
            upstream_port,
            runtime_policy,
            phase,
        )

    def serializable(self) -> dict[str, Any]:
        value = asdict(self)
        if self.schema_version == 1:
            value.pop("gateway_reference")
            value.pop("upstream_port")
            value.pop("runtime_policy")
            value.pop("phase")
        elif self.schema_version == 2:
            value.pop("runtime_policy")
            value.pop("phase")
        elif self.schema_version == 3:
            value.pop("phase")
            runtime_policy = value["runtime_policy"]
            if isinstance(runtime_policy, dict):
                runtime_policy.pop("persistence_required", None)
        return value


@dataclass(frozen=True)
class UpdateJournal:
    schema_version: int
    lab_id: str
    phase: str
    previous: RunState
    candidate: RunState
    running_roles: tuple[str, ...]
    temporary_port: int

    @classmethod
    def parse(cls, value: object) -> UpdateJournal:
        if not isinstance(value, dict):
            raise IntegrityError("update journal must be an object")
        data = cast(dict[str, Any], value)
        keys = {
            "schema_version",
            "lab_id",
            "phase",
            "previous",
            "candidate",
            "running_roles",
            "temporary_port",
        }
        if data.keys() != keys or data["schema_version"] != 1:
            raise IntegrityError("update journal contains missing, unknown, or unsupported data")
        previous = RunState.parse(data["previous"])
        candidate = RunState.parse(data["candidate"])
        lab_id = data["lab_id"]
        phase = data["phase"]
        roles = data["running_roles"]
        temporary_port = data["temporary_port"]
        if (
            not isinstance(lab_id, str)
            or LAB_ID.fullmatch(lab_id) is None
            or previous.lab_id != lab_id
            or candidate.lab_id != lab_id
            or previous.manifest_identity == candidate.manifest_identity
        ):
            raise IntegrityError("update journal lab or manifest identity is invalid")
        if (
            not previous.trusted
            or previous.gateway_reference is None
            or previous.upstream_port is None
            or previous.runtime_policy is None
            or not candidate.trusted
            or candidate.gateway_reference is None
            or candidate.upstream_port is None
            or candidate.runtime_policy is None
        ):
            raise IntegrityError("update journal lacks a trusted rollback snapshot")
        if previous.phase != "steady" or candidate.phase != "steady":
            raise IntegrityError("update journal requires steady run states")
        if phase not in {"staged", "cutover", "ready"}:
            raise IntegrityError("update journal phase is invalid")
        if (
            not isinstance(roles, list)
            or any(role not in {"application", "gateway"} for role in roles)
            or len(roles) != len(set(roles))
        ):
            raise IntegrityError("update journal running roles are invalid")
        if (
            not isinstance(temporary_port, int)
            or isinstance(temporary_port, bool)
            or not 1 <= temporary_port <= 65535
            or temporary_port == previous.host_port
        ):
            raise IntegrityError("update journal temporary port is invalid")
        if (phase == "staged" and candidate.host_port != temporary_port) or (
            phase == "ready" and candidate.host_port != previous.host_port
        ):
            raise IntegrityError("update journal phase and candidate port disagree")
        return cls(1, lab_id, phase, previous, candidate, tuple(roles), temporary_port)

    def serializable(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "lab_id": self.lab_id,
            "phase": self.phase,
            "previous": self.previous.serializable(),
            "candidate": self.candidate.serializable(),
            "running_roles": list(self.running_roles),
            "temporary_port": self.temporary_port,
        }


class StateStore:
    def __init__(self, paths: Paths) -> None:
        self.paths = paths

    def path(self, lab_id: str) -> Path:
        if not LAB_ID.fullmatch(lab_id):
            raise IntegrityError("invalid lab ID for run-state path")
        return self.paths.state / "runs" / f"{lab_id}.json"

    def update_path(self, lab_id: str) -> Path:
        if not LAB_ID.fullmatch(lab_id):
            raise IntegrityError("invalid lab ID for update-journal path")
        return self.paths.state / "updates" / f"{lab_id}.json"

    @contextmanager
    def lifecycle_lock(self, *, timeout: float = 30) -> Iterator[None]:
        if not 0 < timeout <= 120:
            raise ValueError("lifecycle lock timeout must be between 0 and 120 seconds")
        directory = self.paths.state / "runs"
        if directory.is_symlink():
            raise IntegrityError("run state directory is a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        path = directory / ".lifecycle.lock"
        if path.is_symlink():
            raise IntegrityError("lifecycle lock is a symlink")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise IntegrityError(f"cannot open lifecycle lock: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            ):
                raise IntegrityError("lifecycle lock has unsafe ownership or permissions")
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise PreflightError(
                            "another VulnDockyard lifecycle operation held the lock for "
                            f"{timeout:g}s"
                        ) from None
                    time.sleep(min(0.05, max(deadline - time.monotonic(), 0)))
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def load(self, lab_id: str) -> RunState | None:
        path = self.path(lab_id)
        if path.is_symlink():
            raise IntegrityError(f"run state is a symlink: {path}")
        try:
            info = path.stat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or info.st_size > 1_000_000
            ):
                raise IntegrityError("run state has unsafe type, ownership, mode, or size")
            state = RunState.parse(strict_json_loads(path.read_bytes()))
            if state.lab_id != lab_id:
                raise IntegrityError("run state lab ID does not match its filename")
            return state
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
            raise IntegrityError(f"cannot read run state for {lab_id}: {exc}") from exc

    def save(self, state: RunState) -> None:
        # Programmatically constructed state must pass the same closed parser used
        # when a later invocation loads it.
        value = state.serializable()
        RunState.parse(strict_json_loads(json.dumps(value)))
        self._save_json(self.path(state.lab_id), value)

    def _save_json(self, path: Path, value: object) -> None:
        directory = path.parent
        if directory.is_symlink():
            raise IntegrityError("run state directory is a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        if path.is_symlink():
            raise IntegrityError("refusing symlinked run state")
        descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def delete(self, lab_id: str) -> None:
        self._delete_json(self.path(lab_id), "run state")

    def load_update(self, lab_id: str) -> UpdateJournal | None:
        path = self.update_path(lab_id)
        if path.is_symlink():
            raise IntegrityError(f"update journal is a symlink: {path}")
        try:
            info = path.stat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or info.st_size > 1_000_000
            ):
                raise IntegrityError("update journal has unsafe type, ownership, mode, or size")
            journal = UpdateJournal.parse(strict_json_loads(path.read_bytes()))
            if journal.lab_id != lab_id:
                raise IntegrityError("update journal lab ID does not match its filename")
            return journal
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
            raise IntegrityError(f"cannot read update journal for {lab_id}: {exc}") from exc

    def save_update(self, journal: UpdateJournal) -> None:
        value = journal.serializable()
        UpdateJournal.parse(strict_json_loads(json.dumps(value)))
        self._save_json(self.update_path(journal.lab_id), value)

    def delete_update(self, lab_id: str) -> None:
        self._delete_json(self.update_path(lab_id), "update journal")

    @staticmethod
    def _delete_json(path: Path, description: str) -> None:
        directory = path.parent
        if directory.is_symlink():
            raise IntegrityError(f"{description} directory is a symlink")
        if path.is_symlink():
            raise IntegrityError(f"refusing symlinked {description}")
        try:
            path.unlink()
        except FileNotFoundError:
            return
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

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
