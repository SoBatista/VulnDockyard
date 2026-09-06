"""Contained Docker Engine and Compose v2 adapter."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from typing import Any, cast

from .errors import IntegrityError, PolicyError, PreflightError
from .process import Result, Runner
from .state import ResourceRecord, RunState

OWNER = "org.vulndockyard.managed"
LAB = "org.vulndockyard.lab-id"
MANIFEST = "org.vulndockyard.manifest-identity"
MANIFEST_VERSION = "org.vulndockyard.manifest-version"
RUN = "org.vulndockyard.run-id"
CREATED = "org.vulndockyard.created-at"
TRUSTED = "org.vulndockyard.trusted"
ROLE = "org.vulndockyard.role"
OBJECT_ID = re.compile(r"^[0-9a-f]{12,64}$")


@dataclass(frozen=True)
class Timeouts:
    pull: float = 600
    start: float = 30
    health: float = 120
    stop: float = 30
    cleanup: float = 60
    inspect: float = 15


@dataclass(frozen=True)
class Ownership:
    lab_id: str
    manifest_identity: str
    run_id: str
    created_at: str
    trusted: bool

    def labels(self, role: str) -> tuple[str, ...]:
        values = {
            OWNER: "true",
            LAB: self.lab_id,
            MANIFEST: self.manifest_identity,
            MANIFEST_VERSION: "1",
            RUN: self.run_id,
            CREATED: self.created_at,
            TRUSTED: str(self.trusted).lower(),
            ROLE: role,
        }
        result: list[str] = []
        for key, value in sorted(values.items()):
            result.extend(("--label", f"{key}={value}"))
        return tuple(result)

    @classmethod
    def from_state(cls, state: RunState) -> Ownership:
        return cls(
            state.lab_id, state.manifest_identity, state.run_id, state.created_at, state.trusted
        )


class Docker:
    def __init__(self, runner: Runner | None = None, timeouts: Timeouts | None = None) -> None:
        self.runner = runner or Runner()
        self.timeouts = timeouts or Timeouts()

    def _run(self, args: tuple[str, ...], *, timeout: float, check: bool = True) -> Result:
        return self.runner.run(("docker", *args), timeout=timeout, check=check)

    def preflight(self, *, require_compose: bool = False) -> dict[str, object]:
        if shutil.which("docker") is None:
            raise PreflightError("Docker CLI is not installed")
        engine = self._run(
            ("info", "--format", "{{json .ServerVersion}}"), timeout=self.timeouts.inspect
        )
        compose_result = self._run(
            ("compose", "version", "--short"), timeout=self.timeouts.inspect, check=False
        )
        compose = compose_result.returncode == 0
        if require_compose and not compose:
            raise PreflightError("Docker Compose v2 is required for this operation")
        return {"engine": json.loads(engine.stdout), "compose_v2": compose}

    def inspect(self, kind: str, object_id: str) -> dict[str, Any]:
        if kind not in {"container", "network", "volume", "image"}:
            raise ValueError(f"unsupported Docker object kind: {kind}")
        result = self._run((kind, "inspect", object_id), timeout=self.timeouts.inspect)
        try:
            values = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"Docker returned invalid {kind} inspection data") from exc
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise IntegrityError(f"Docker returned unexpected {kind} inspection data")
        return cast(dict[str, Any], values[0])

    def exists(self, kind: str, object_id: str) -> bool:
        if kind not in {"container", "network", "volume"}:
            raise ValueError(f"unsupported Docker object kind: {kind}")
        return (
            self._run(
                (kind, "inspect", object_id), timeout=self.timeouts.inspect, check=False
            ).returncode
            == 0
        )

    @staticmethod
    def _labels(kind: str, inspection: dict[str, Any]) -> dict[str, str]:
        if kind == "container":
            raw = inspection.get("Config", {}).get("Labels", {})
        else:
            raw = inspection.get("Labels", {})
        if not isinstance(raw, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
        ):
            raise IntegrityError(f"Docker {kind} labels are malformed")
        return cast(dict[str, str], raw)

    def validate_owned(self, record: ResourceRecord, ownership: Ownership) -> dict[str, Any]:
        if record.kind not in {"container", "network", "volume"}:
            raise IntegrityError(f"unknown recorded resource kind: {record.kind}")
        if not OBJECT_ID.fullmatch(record.object_id):
            raise IntegrityError("recorded Docker object ID is malformed")
        inspection = self.inspect(record.kind, record.object_id)
        actual_id = inspection.get("Id", inspection.get("ID", inspection.get("Name")))
        if not isinstance(actual_id, str) or not actual_id.startswith(record.object_id):
            raise IntegrityError(f"recorded {record.kind} identity no longer matches")
        labels = self._labels(record.kind, inspection)
        expected = {
            OWNER: "true",
            LAB: ownership.lab_id,
            MANIFEST: ownership.manifest_identity,
            MANIFEST_VERSION: "1",
            RUN: ownership.run_id,
            CREATED: ownership.created_at,
            TRUSTED: str(ownership.trusted).lower(),
        }
        differences = [key for key, value in expected.items() if labels.get(key) != value]
        if differences:
            raise PolicyError(
                f"refusing {record.kind} {record.name}: ownership labels mismatch "
                f"({', '.join(differences)})"
            )
        return inspection

    def pull(self, reference: str) -> None:
        if "@sha256:" not in reference:
            raise PolicyError("Docker pulls require an immutable digest reference")
        self._run(("image", "pull", reference), timeout=self.timeouts.pull)
        inspection = self.inspect("image", reference)
        digests = inspection.get("RepoDigests", [])
        requested_name, requested_digest = reference.rsplit("@", 1)

        def normalized(name: str) -> str:
            name = name.removeprefix("docker.io/")
            return name.removeprefix("library/")

        matching = False
        if isinstance(digests, list):
            for item in digests:
                if not isinstance(item, str) or "@" not in item:
                    continue
                actual_name, actual_digest = item.rsplit("@", 1)
                if (
                    normalized(actual_name) == normalized(requested_name)
                    and actual_digest == requested_digest
                ):
                    matching = True
                    break
        if not matching:
            raise IntegrityError(f"pulled image does not report the requested digest: {reference}")

    def create_network(
        self, name: str, ownership: Ownership, *, internal: bool = True
    ) -> ResourceRecord:
        args = ["network", "create", "--driver", "bridge"]
        if internal:
            args.append("--internal")
        args.extend(ownership.labels("network"))
        args.append(name)
        result = self._run(tuple(args), timeout=self.timeouts.start)
        object_id = result.stdout.strip()
        if not OBJECT_ID.fullmatch(object_id):
            raise IntegrityError("Docker returned an invalid network ID")
        return ResourceRecord("network", name, object_id)

    def create_application(
        self,
        *,
        name: str,
        image: str,
        network: str,
        ownership: Ownership,
        memory_mb: int,
        cpus: float,
        pids: int,
        read_only: bool,
    ) -> ResourceRecord:
        args = [
            "container",
            "create",
            "--name",
            name,
            "--network",
            network,
            "--network-alias",
            "app",
            "--restart",
            "no",
            "--security-opt",
            "no-new-privileges=true",
            "--cap-drop",
            "ALL",
            "--memory",
            f"{memory_mb}m",
            "--cpus",
            f"{cpus:g}",
            "--pids-limit",
            str(pids),
        ]
        if read_only:
            args.extend(
                ("--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m")  # noqa: S108
            )
        args.extend(ownership.labels("application"))
        args.append(image)
        result = self._run(tuple(args), timeout=self.timeouts.start)
        object_id = result.stdout.strip()
        if not OBJECT_ID.fullmatch(object_id):
            raise IntegrityError("Docker returned an invalid container ID")
        return ResourceRecord("container", name, object_id)

    def create_gateway(
        self,
        *,
        name: str,
        image: str,
        network: str,
        upstream_port: int,
        host_port: int,
        ownership: Ownership,
    ) -> ResourceRecord:
        if not 1 <= host_port <= 65535:
            raise PolicyError("host port is outside the valid range")
        args = (
            "container",
            "create",
            "--name",
            name,
            "--network",
            network,
            "--restart",
            "no",
            "--publish",
            f"127.0.0.1:{host_port}:8080",
            "--read-only",
            "--tmpfs",
            "/config:rw,noexec,nosuid,nodev,size=8m",
            "--tmpfs",
            "/data:rw,noexec,nosuid,nodev,size=8m",
            "--security-opt",
            "no-new-privileges=true",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_BIND_SERVICE",
            "--memory",
            "128m",
            "--cpus",
            "0.25",
            "--pids-limit",
            "64",
            *ownership.labels("gateway"),
            image,
            "caddy",
            "reverse-proxy",
            "--from",
            ":8080",
            "--to",
            f"app:{upstream_port}",
        )
        result = self._run(args, timeout=self.timeouts.start)
        object_id = result.stdout.strip()
        if not OBJECT_ID.fullmatch(object_id):
            raise IntegrityError("Docker returned an invalid gateway container ID")
        return ResourceRecord("container", name, object_id)

    def connect_network(self, network: ResourceRecord, container: ResourceRecord) -> None:
        if network.kind != "network" or container.kind != "container":
            raise ValueError("network connection requires a network and container record")
        self._run(
            ("network", "connect", network.object_id, container.object_id),
            timeout=self.timeouts.start,
        )

    def start(self, record: ResourceRecord) -> None:
        if record.kind != "container":
            raise ValueError("only containers can be started")
        self._run(("container", "start", record.object_id), timeout=self.timeouts.start)

    def stop(self, record: ResourceRecord) -> None:
        if record.kind != "container":
            raise ValueError("only containers can be stopped")
        self._run(
            ("container", "stop", "--time", str(int(self.timeouts.stop)), record.object_id),
            timeout=self.timeouts.stop + 5,
        )

    def remove(self, record: ResourceRecord) -> None:
        if record.kind == "container":
            args: tuple[str, ...] = ("container", "rm", "--force", record.object_id)
        elif record.kind == "network":
            args = ("network", "rm", record.object_id)
        elif record.kind == "volume":
            args = ("volume", "rm", record.object_id)
        else:
            raise IntegrityError(f"unsupported cleanup kind: {record.kind}")
        self._run(args, timeout=self.timeouts.cleanup)

    def logs(self, record: ResourceRecord, *, follow: bool, tail: int = 100) -> Result:
        if record.kind != "container":
            raise ValueError("logs require a container")
        args = ["container", "logs", "--tail", str(tail)]
        if follow:
            args.append("--follow")
        args.append(record.object_id)
        # Following is intentionally bounded as well; users can repeat it.
        return self._run(tuple(args), timeout=300, check=False)

    def remove_image(self, reference: str) -> None:
        if "@sha256:" not in reference:
            raise PolicyError("image cleanup requires an immutable digest reference")
        self._run(("image", "rm", reference), timeout=self.timeouts.cleanup)

    def managed_resources(self) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for kind in ("container", "network", "volume"):
            noun = "container" if kind == "container" else kind
            query: tuple[str, ...] = (
                noun,
                "ls",
                "--all",
                "--quiet",
                "--filter",
                f"label={OWNER}=true",
            )
            if kind != "container":
                query = (noun, "ls", "--quiet", "--filter", f"label={OWNER}=true")
            response = self._run(query, timeout=self.timeouts.inspect)
            result[kind] = tuple(line for line in response.stdout.splitlines() if line)
        return result
