"""Contained Docker Engine and Compose v2 adapter."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .errors import IntegrityError, PolicyError, PreflightError
from .models import DIGEST, OCI_NAME
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
OBJECT_ID = re.compile(r"^[0-9a-f]{64}$")
RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def parse_image_reference(reference: str) -> tuple[str, str]:
    parts = reference.rsplit("@", 1)
    if (
        len(parts) != 2
        or OCI_NAME.fullmatch(parts[0]) is None
        or DIGEST.fullmatch(parts[1]) is None
    ):
        raise PolicyError(
            "Docker image references require a canonical fully-qualified OCI name "
            "and immutable sha256 digest"
        )
    return parts[0], parts[1]


@dataclass(frozen=True)
class DockerConnection:
    executable: str
    socket: Path

    @classmethod
    def discover(cls, environment: Mapping[str, str] | None = None) -> DockerConnection:
        values = os.environ if environment is None else environment
        executable = shutil.which("docker", path=values.get("PATH"))
        if executable is None:
            raise PreflightError("Docker CLI is not installed")
        executable_path = Path(executable).resolve(strict=True)
        executable_stat = executable_path.stat()
        if not stat.S_ISREG(executable_stat.st_mode) or not os.access(executable_path, os.X_OK):
            raise PreflightError("Docker CLI is not a regular executable")
        if executable_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PreflightError("Docker CLI must not be group- or world-writable")

        context = values.get("DOCKER_CONTEXT", "")
        if context not in {"", "default"}:
            raise PreflightError("only the local default Docker context is supported")
        configured = values.get("VDY_DOCKER_SOCKET")
        docker_host = values.get("DOCKER_HOST")
        if configured and docker_host:
            raise PreflightError("set only one of VDY_DOCKER_SOCKET or DOCKER_HOST")
        if configured:
            socket_path = Path(configured)
        elif docker_host:
            parsed = urlsplit(docker_host)
            if (
                parsed.scheme != "unix"
                or parsed.netloc
                or parsed.query
                or parsed.fragment
                or not parsed.path
                or "%" in parsed.path
            ):
                raise PreflightError("DOCKER_HOST must identify an absolute local Unix socket")
            socket_path = Path(parsed.path)
        else:
            candidates = [Path("/var/run/docker.sock")]
            runtime_dir = values.get("XDG_RUNTIME_DIR")
            if runtime_dir and Path(runtime_dir).is_absolute():
                candidates.append(Path(runtime_dir) / "docker.sock")
            socket_path = next((item for item in candidates if item.exists()), candidates[0])
        if not socket_path.is_absolute():
            raise PreflightError("Docker socket path must be absolute")
        if socket_path.is_symlink():
            raise PreflightError("Docker socket must not be a symlink")
        try:
            resolved_socket = socket_path.resolve(strict=True)
            socket_stat = resolved_socket.stat()
        except OSError as exc:
            raise PreflightError(f"Docker Unix socket is unavailable: {socket_path}") from exc
        if not stat.S_ISSOCK(socket_stat.st_mode):
            raise PreflightError(f"Docker endpoint is not a Unix socket: {socket_path}")
        if socket_stat.st_uid not in {0, os.getuid(), executable_stat.st_uid}:
            raise PreflightError("Docker Unix socket has an unexpected owner")
        if socket_stat.st_mode & stat.S_IWOTH:
            raise PreflightError("Docker Unix socket must not be world-writable")
        return cls(str(executable_path), resolved_socket)

    def environment(self) -> dict[str, str]:
        return {
            "DOCKER_CLI_HINTS": "false",
            "DOCKER_HOST": f"unix://{self.socket}",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }


@dataclass(frozen=True)
class Timeouts:
    pull: float = 600
    start: float = 30
    health: float = 120
    stop: float = 30
    cleanup: float = 60
    inspect: float = 15

    @classmethod
    def discover(cls, environment: Mapping[str, str] | None = None) -> Timeouts:
        values = os.environ if environment is None else environment
        bounds = {
            "pull": (1.0, 3600.0),
            "start": (1.0, 300.0),
            "health": (1.0, 900.0),
            "stop": (1.0, 300.0),
            "cleanup": (1.0, 600.0),
            "inspect": (1.0, 120.0),
        }
        defaults = cls()
        resolved: dict[str, float] = {}
        for name, (minimum, maximum) in bounds.items():
            raw = values.get(f"VDY_TIMEOUT_{name.upper()}", str(getattr(defaults, name)))
            try:
                parsed = float(raw)
            except ValueError as exc:
                raise PreflightError(f"VDY_TIMEOUT_{name.upper()} must be numeric") from exc
            if not minimum <= parsed <= maximum:
                raise PreflightError(
                    f"VDY_TIMEOUT_{name.upper()} must be between "
                    f"{minimum:g} and {maximum:g} seconds"
                )
            resolved[name] = parsed
        return cls(**resolved)


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
    def __init__(
        self,
        runner: Runner | None = None,
        timeouts: Timeouts | None = None,
        *,
        connection: DockerConnection | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.runner = runner or Runner()
        self._environment = dict(os.environ if environment is None else environment)
        self.timeouts = timeouts or Timeouts.discover(self._environment)
        self._connection = connection

    @property
    def connection(self) -> DockerConnection:
        if self._connection is None:
            self._connection = DockerConnection.discover(self._environment)
        return self._connection

    def _run(self, args: tuple[str, ...], *, timeout: float, check: bool = True) -> Result:
        connection = self.connection
        return self.runner.run(
            (connection.executable, "--host", f"unix://{connection.socket}", *args),
            timeout=timeout,
            check=check,
            env=connection.environment(),
        )

    def preflight(self, *, require_compose: bool = False) -> dict[str, object]:
        system = platform.system().casefold()
        machine = platform.machine().casefold()
        architectures = {
            "x86_64": "linux/amd64",
            "amd64": "linux/amd64",
            "aarch64": "linux/arm64",
            "arm64": "linux/arm64",
            "armv7": "linux/arm/v7",
            "armv7l": "linux/arm/v7",
        }
        if system != "linux" or machine not in architectures:
            raise PreflightError(f"unsupported local Docker platform: {system}/{machine}")
        local_platform = architectures[machine]
        engine = self._run(
            ("info", "--format", "{{json .ServerVersion}}"), timeout=self.timeouts.inspect
        )
        compose_result = self._run(
            ("compose", "version", "--short"), timeout=self.timeouts.inspect, check=False
        )
        compose = compose_result.returncode == 0
        if require_compose and not compose:
            raise PreflightError("Docker Compose v2 is required for this operation")
        return {
            "engine": json.loads(engine.stdout),
            "compose_v2": compose,
            "platform": local_platform,
        }

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
        expected_role = expected_resource_role(record, ownership)
        if record.kind != "volume" and not OBJECT_ID.fullmatch(record.object_id):
            raise IntegrityError("recorded Docker object ID is malformed")
        if record.kind == "volume" and record.object_id != record.name:
            raise IntegrityError("recorded Docker volume identity is malformed")
        inspection = self.inspect(record.kind, record.object_id)
        actual_id = inspection.get("Id", inspection.get("ID", inspection.get("Name")))
        if not isinstance(actual_id, str) or actual_id != record.object_id:
            raise IntegrityError(f"recorded {record.kind} identity no longer matches")
        raw_name = inspection.get("Name")
        actual_name = raw_name.removeprefix("/") if isinstance(raw_name, str) else None
        if actual_name != record.name:
            raise PolicyError(f"refusing {record.kind} {record.name}: resource name mismatch")
        labels = self._labels(record.kind, inspection)
        expected = {
            OWNER: "true",
            LAB: ownership.lab_id,
            MANIFEST: ownership.manifest_identity,
            MANIFEST_VERSION: "1",
            RUN: ownership.run_id,
            CREATED: ownership.created_at,
            TRUSTED: str(ownership.trusted).lower(),
            ROLE: expected_role,
        }
        differences = [key for key, value in expected.items() if labels.get(key) != value]
        if differences:
            raise PolicyError(
                f"refusing {record.kind} {record.name}: ownership labels mismatch "
                f"({', '.join(differences)})"
            )
        return inspection

    def pull(self, reference: str) -> None:
        requested_name, requested_digest = parse_image_reference(reference)
        self._run(("image", "pull", reference), timeout=self.timeouts.pull)
        inspection = self.inspect("image", reference)
        digests = inspection.get("RepoDigests", [])

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
        parse_image_reference(image)
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
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=10m",
            "--log-opt",
            "max-file=2",
            "--security-opt",
            "no-new-privileges=true",
            "--cap-drop",
            "ALL",
            "--memory",
            f"{memory_mb}m",
            "--memory-swap",
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
        parse_image_reference(image)
        if (
            not isinstance(host_port, int)
            or isinstance(host_port, bool)
            or not 1 <= host_port <= 65535
        ):
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
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=10m",
            "--log-opt",
            "max-file=2",
            "--publish",
            f"127.0.0.1:{host_port}:8080",
            "--user",
            "1000:1000",
            "--read-only",
            "--tmpfs",
            "/config:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700",
            "--tmpfs",
            "/data:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700",
            "--security-opt",
            "no-new-privileges=true",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_BIND_SERVICE",
            "--memory",
            "128m",
            "--memory-swap",
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
        parse_image_reference(reference)
        self._run(("image", "rm", reference), timeout=self.timeouts.cleanup)

    def managed_resources(self, lab_id: str | None = None) -> dict[str, tuple[str, ...]]:
        if lab_id is not None and not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", lab_id):
            raise ValueError("invalid lab ID filter")
        result: dict[str, tuple[str, ...]] = {}
        for kind in ("container", "network", "volume"):
            noun = "container" if kind == "container" else kind
            query = [noun, "ls"]
            if kind == "container":
                query.append("--all")
            if kind != "volume":
                query.append("--no-trunc")
            query.extend(("--quiet", "--filter", f"label={OWNER}=true"))
            if lab_id is not None:
                query.extend(("--filter", f"label={LAB}={lab_id}"))
            response = self._run(tuple(query), timeout=self.timeouts.inspect)
            identifiers = tuple(line for line in response.stdout.splitlines() if line)
            pattern = RESOURCE_NAME if kind == "volume" else OBJECT_ID
            if any(not pattern.fullmatch(identifier) for identifier in identifiers):
                raise IntegrityError(f"Docker returned a malformed managed {kind} identifier")
            result[kind] = identifiers
        return result


def expected_resource_role(record: ResourceRecord, ownership: Ownership) -> str:
    if not RESOURCE_NAME.fullmatch(record.name):
        raise IntegrityError("recorded Docker resource name is malformed")
    prefix = f"vdy-{ownership.lab_id}-{ownership.run_id[:12]}-"
    if not record.name.startswith(prefix):
        raise PolicyError(f"refusing {record.kind} {record.name}: deterministic name mismatch")
    suffix = record.name[len(prefix) :]
    if record.kind == "container" and suffix in {"app", "gateway"}:
        return "application" if suffix == "app" else "gateway"
    if record.kind == "network" and suffix in {"net", "ingress"}:
        return "network"
    if record.kind == "volume" and (suffix == "volume" or suffix.startswith("volume-")):
        return "volume"
    raise PolicyError(f"refusing {record.kind} {record.name}: resource role is not recognized")
