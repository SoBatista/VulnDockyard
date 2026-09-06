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
from pathlib import Path, PurePosixPath
from typing import Any, cast
from urllib.parse import urlsplit

from .errors import IntegrityError, PolicyError, PreflightError
from .models import DIGEST, OCI_NAME, EphemeralMount
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
CAPABILITY = re.compile(r"^(?:CAP_)?[A-Z][A-Z0-9_]*$")
ENGINE_VERSION = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?P<suffix>[-+~][0-9A-Za-z.+~_-]+)?$"
)
MINIMUM_ENGINE_VERSION = (28, 0, 0)
MINIMUM_ENGINE_TEXT = ".".join(str(value) for value in MINIMUM_ENGINE_VERSION)
GATEWAY_MODE_IPV4 = "com.docker.network.bridge.gateway_mode_ipv4"
EPHEMERAL_MODE = "0700"
SEED_ROOT = "/vdy-seed"
SEED_READY_MARKER = "VULNDOCKYARD_SEED_READY_V1"
SEED_SCRIPT = (
    'const fs=require("fs");'
    'if(typeof fs.cpSync!=="function"){throw new Error("fs.cpSync unavailable");}'
    "const mounts=JSON.parse(process.argv[1]);"
    "for(const mount of mounts){"
    "fs.cpSync(mount.source,mount.target,{recursive:true,force:false,errorOnExist:true});"
    "}"
    f'process.stdout.write("{SEED_READY_MARKER}\\n");'
    "setInterval(()=>{},2147483647);"
)


def canonical_capabilities(value: object) -> tuple[str, ...]:
    """Normalize Docker's equivalent prefixed capability inspection spelling."""
    if not isinstance(value, list) or any(
        not isinstance(item, str) or CAPABILITY.fullmatch(item) is None for item in value
    ):
        raise IntegrityError("Docker returned malformed Linux capabilities")
    normalized = tuple(item.removeprefix("CAP_") for item in value)
    if len(normalized) != len(set(normalized)):
        raise IntegrityError("Docker returned duplicate Linux capabilities")
    return normalized


def parse_engine_version(value: object) -> tuple[tuple[int, int, int], str]:
    """Parse a Docker server version without accepting ambiguous output."""
    if not isinstance(value, str):
        raise IntegrityError("Docker returned a non-string Engine server version")
    match = ENGINE_VERSION.fullmatch(value)
    if match is None:
        raise IntegrityError(f"Docker returned a malformed Engine server version: {value!r}")
    version = tuple(int(match.group(name)) for name in ("major", "minor", "patch"))
    suffix = match.group("suffix") or ""
    return cast(tuple[int, int, int], version), suffix


def engine_supports_isolated_networking(value: object) -> bool:
    version, suffix = parse_engine_version(value)
    prerelease = bool(
        suffix.startswith("-")
        and re.match(r"-(?:alpha|beta|dev|pre|preview|rc)(?:[.-]|$)", suffix, re.IGNORECASE)
    )
    return version >= MINIMUM_ENGINE_VERSION and not prerelease


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
        try:
            server_version = json.loads(engine.stdout)
        except json.JSONDecodeError as exc:
            raise IntegrityError("Docker returned invalid Engine version JSON") from exc
        version, suffix = parse_engine_version(server_version)
        compose_result = self._run(
            ("compose", "version", "--short"), timeout=self.timeouts.inspect, check=False
        )
        compose = compose_result.returncode == 0
        if require_compose and not compose:
            raise PreflightError("Docker Compose v2 is required for this operation")
        return {
            "engine": server_version,
            "engine_version": {
                "major": version[0],
                "minor": version[1],
                "patch": version[2],
                "suffix": suffix,
            },
            "minimum_engine": MINIMUM_ENGINE_TEXT,
            "isolated_networking": engine_supports_isolated_networking(server_version),
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
        gateway_mode = "isolated" if internal else "nat"
        if internal:
            args.append("--internal")
        args.extend(("--opt", f"{GATEWAY_MODE_IPV4}={gateway_mode}"))
        args.extend(ownership.labels("network"))
        args.append(name)
        result = self._run(tuple(args), timeout=self.timeouts.start)
        object_id = result.stdout.strip()
        if not OBJECT_ID.fullmatch(object_id):
            raise IntegrityError("Docker returned an invalid network ID")
        record = ResourceRecord("network", name, object_id)
        inspection = self.validate_owned(record, ownership)
        try:
            self.validate_network_policy(inspection, internal=internal)
        except (IntegrityError, PolicyError):
            # The exact newly-created object may be removed only after its complete
            # ownership identity has been validated above.
            self.remove(record)
            raise
        return record

    @staticmethod
    def validate_network_policy(inspection: dict[str, Any], *, internal: bool) -> None:
        driver = inspection.get("Driver")
        actual_internal = inspection.get("Internal")
        options = inspection.get("Options")
        if driver != "bridge":
            raise PolicyError("new Docker network does not use the bridge driver")
        if not isinstance(actual_internal, bool) or actual_internal is not internal:
            raise PolicyError("new Docker network has an unexpected Internal setting")
        expected_flags = {
            "Attachable": False,
            "ConfigOnly": False,
            "EnableIPv6": False,
            "Ingress": False,
        }
        if inspection.get("Scope") != "local" or any(
            inspection.get(key) is not value for key, value in expected_flags.items()
        ):
            raise PolicyError("new Docker network has unsafe scope or mode flags")
        if not isinstance(options, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in options.items()
        ):
            raise IntegrityError("new Docker network has malformed driver options")
        expected_options = {
            GATEWAY_MODE_IPV4: "isolated" if internal else "nat",
        }
        if options != expected_options:
            kind = "internal" if internal else "ingress"
            raise PolicyError(f"new Docker {kind} network has unexpected driver options")

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
        seeded_mounts: tuple[tuple[ResourceRecord, EphemeralMount], ...] = (),
        empty_mounts: tuple[EphemeralMount, ...] = (),
        storage_uid: int = 0,
        storage_gid: int = 0,
    ) -> ResourceRecord:
        parse_image_reference(image)
        if not read_only:
            raise PolicyError("runnable application root filesystem must be read-only")
        self._validate_ephemeral_mounts(
            seeded_mounts=seeded_mounts,
            empty_mounts=empty_mounts,
            uid=storage_uid,
            gid=storage_gid,
        )
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
            "--log-opt",
            "compress=true",
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
            "--user",
            f"{storage_uid}:{storage_gid}",
            "--read-only",
        ]
        for volume, mount in seeded_mounts:
            args.extend(
                (
                    "--mount",
                    f"type=volume,src={volume.name},dst={mount.container_path}",
                )
            )
        for mount in empty_mounts:
            args.extend(
                (
                    "--tmpfs",
                    self._direct_tmpfs_spec(mount, uid=storage_uid, gid=storage_gid),
                )
            )
        args.extend(ownership.labels("application"))
        args.append(image)
        result = self._run(tuple(args), timeout=self.timeouts.start)
        object_id = result.stdout.strip()
        if not OBJECT_ID.fullmatch(object_id):
            raise IntegrityError("Docker returned an invalid container ID")
        record = ResourceRecord("container", name, object_id)
        inspection = self.validate_owned(record, ownership)
        try:
            self.validate_application_policy(
                inspection,
                image=image,
                network=network,
                memory_mb=memory_mb,
                cpus=cpus,
                pids=pids,
                seeded_mounts=seeded_mounts,
                empty_mounts=empty_mounts,
                storage_uid=storage_uid,
                storage_gid=storage_gid,
            )
        except (IntegrityError, PolicyError):
            self.remove(record)
            raise
        return record

    @classmethod
    def validate_application_policy(
        cls,
        inspection: dict[str, Any],
        *,
        image: str,
        network: str,
        memory_mb: int,
        cpus: float,
        pids: int,
        seeded_mounts: tuple[tuple[ResourceRecord, EphemeralMount], ...],
        empty_mounts: tuple[EphemeralMount, ...],
        storage_uid: int,
        storage_gid: int,
    ) -> None:
        cls._validate_ephemeral_mounts(
            seeded_mounts=seeded_mounts,
            empty_mounts=empty_mounts,
            uid=storage_uid,
            gid=storage_gid,
        )
        config = inspection.get("Config")
        host = inspection.get("HostConfig")
        mounts = inspection.get("Mounts")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(mounts, list)
        ):
            raise IntegrityError("Docker application inspection is malformed")
        if config.get("Image") != image or config.get("User") != f"{storage_uid}:{storage_gid}":
            raise PolicyError("Docker application has unexpected image or user identity")
        restart = host.get("RestartPolicy")
        if (
            host.get("NetworkMode") != network
            or host.get("PortBindings") not in ({}, None)
            or host.get("PublishAllPorts") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or not isinstance(restart, dict)
            or restart.get("Name") != "no"
        ):
            raise PolicyError("Docker application has unsafe core runtime configuration")
        if (
            any(host.get(key) not in ("", "private") for key in ("PidMode", "IpcMode"))
            or host.get("UsernsMode") == "host"
        ):
            raise PolicyError("Docker application uses a host namespace")
        if host.get("CapDrop") != ["ALL"] or host.get("CapAdd") not in (None, []):
            raise PolicyError("Docker application has unexpected Linux capabilities")
        security_options = host.get("SecurityOpt")
        if (
            not isinstance(security_options, list)
            or "no-new-privileges=true" not in security_options
        ):
            raise PolicyError("Docker application lacks no-new-privileges")
        if host.get("Devices") not in (None, []) or host.get("DeviceRequests") not in (None, []):
            raise PolicyError("Docker application has unexpected device access")
        expected_bytes = memory_mb * 1024 * 1024
        expected_nano_cpus = round(cpus * 1_000_000_000)
        if (
            host.get("Memory") != expected_bytes
            or host.get("MemorySwap") != expected_bytes
            or host.get("NanoCpus") != expected_nano_cpus
            or host.get("PidsLimit") != pids
        ):
            raise PolicyError("Docker application resource limits differ from the reviewed values")
        expected_tmpfs = {
            mount.container_path: cls._direct_tmpfs_spec(
                mount, uid=storage_uid, gid=storage_gid
            ).split(":", 1)[1]
            for mount in empty_mounts
        }
        if host.get("Tmpfs", {}) != expected_tmpfs:
            raise PolicyError("Docker application tmpfs mounts differ from the reviewed values")
        if host.get("LogConfig") != {
            "Type": "local",
            "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
        }:
            raise PolicyError("Docker application log limits differ from the reviewed values")
        expected_volumes = {
            (volume.name, mount.container_path, True) for volume, mount in seeded_mounts
        }
        expected_tmpfs_mounts = {(mount.container_path, True) for mount in empty_mounts}
        actual_volumes: set[tuple[str, str, bool]] = set()
        actual_tmpfs_mounts: set[tuple[str, bool]] = set()
        for mount in mounts:
            if not isinstance(mount, dict):
                raise IntegrityError("Docker application mount inspection is malformed")
            mount_type = mount.get("Type")
            name = mount.get("Name")
            destination = mount.get("Destination")
            writable = mount.get("RW")
            if not isinstance(destination, str) or not isinstance(writable, bool):
                raise PolicyError("Docker application has an unreviewed filesystem mount")
            if mount_type == "volume" and isinstance(name, str):
                actual_volumes.add((name, destination, writable))
            elif mount_type == "tmpfs":
                actual_tmpfs_mounts.add((destination, writable))
            else:
                raise PolicyError("Docker application has an unreviewed filesystem mount")
        if (
            len(actual_volumes) + len(actual_tmpfs_mounts) != len(mounts)
            or actual_volumes != expected_volumes
            or actual_tmpfs_mounts not in (set(), expected_tmpfs_mounts)
        ):
            raise PolicyError("Docker application mount inventory differs from the reviewed values")

    @staticmethod
    def _validate_ephemeral_mount(mount: EphemeralMount) -> None:
        path = PurePosixPath(mount.container_path)
        if (
            not RESOURCE_NAME.fullmatch(mount.name)
            or not mount.name.islower()
            or not mount.container_path.startswith("/")
            or str(path) != mount.container_path
            or mount.container_path == "/"
            or "," in mount.container_path
            or not 1 <= mount.size_mb <= 4096
        ):
            raise PolicyError("ephemeral storage mount is outside the reviewed safe contract")

    @classmethod
    def _validate_ephemeral_mounts(
        cls,
        *,
        seeded_mounts: tuple[tuple[ResourceRecord, EphemeralMount], ...],
        empty_mounts: tuple[EphemeralMount, ...],
        uid: int,
        gid: int,
    ) -> None:
        if (
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or not 0 <= uid <= 65_535
            or not isinstance(gid, int)
            or isinstance(gid, bool)
            or not 0 <= gid <= 65_535
        ):
            raise PolicyError("ephemeral storage ownership is outside the reviewed safe contract")
        names: set[str] = set()
        paths: set[str] = set()
        for volume, mount in seeded_mounts:
            cls._validate_ephemeral_mount(mount)
            if volume.kind != "volume" or volume.object_id != volume.name:
                raise IntegrityError("seeded storage does not reference an exact named volume")
            names.add(mount.name)
            paths.add(mount.container_path)
        for mount in empty_mounts:
            cls._validate_ephemeral_mount(mount)
            names.add(mount.name)
            paths.add(mount.container_path)
        if len(names) != len(seeded_mounts) + len(empty_mounts) or len(paths) != len(names):
            raise IntegrityError("ephemeral storage mounts are duplicated")

    @staticmethod
    def _volume_options(mount: EphemeralMount, *, uid: int, gid: int) -> dict[str, str]:
        return {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": (
                f"size={mount.size_mb}m,uid={uid},gid={gid},mode={EPHEMERAL_MODE},"
                "noexec,nosuid,nodev"
            ),
        }

    @classmethod
    def _direct_tmpfs_spec(cls, mount: EphemeralMount, *, uid: int, gid: int) -> str:
        cls._validate_ephemeral_mount(mount)
        return (
            f"{mount.container_path}:rw,noexec,nosuid,nodev,size={mount.size_mb}m,"
            f"uid={uid},gid={gid},mode={EPHEMERAL_MODE}"
        )

    def create_ephemeral_volume(
        self,
        *,
        name: str,
        mount: EphemeralMount,
        ownership: Ownership,
        uid: int,
        gid: int,
    ) -> ResourceRecord:
        self._validate_ephemeral_mounts(
            seeded_mounts=((ResourceRecord("volume", name, name), mount),),
            empty_mounts=(),
            uid=uid,
            gid=gid,
        )
        options = self._volume_options(mount, uid=uid, gid=gid)
        args = ["volume", "create", "--driver", "local"]
        for key in ("type", "device", "o"):
            args.extend(("--opt", f"{key}={options[key]}"))
        args.extend(ownership.labels(f"volume-{mount.name}"))
        args.append(name)
        result = self._run(tuple(args), timeout=self.timeouts.start)
        if result.stdout.strip() != name:
            raise IntegrityError("Docker returned an unexpected volume identity")
        record = ResourceRecord("volume", name, name)
        inspection = self.validate_owned(record, ownership)
        try:
            self._validate_ephemeral_volume_policy(inspection, options=options)
        except (IntegrityError, PolicyError):
            self.remove(record)
            raise
        return record

    @staticmethod
    def _validate_ephemeral_volume_policy(
        inspection: dict[str, Any], *, options: dict[str, str]
    ) -> None:
        if inspection.get("Driver") != "local":
            raise PolicyError("ephemeral volume does not use Docker's local driver")
        actual = inspection.get("Options")
        if not isinstance(actual, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in actual.items()
        ):
            raise IntegrityError("ephemeral volume options are malformed")
        if actual != options:
            raise PolicyError("ephemeral volume has unexpected driver options")

    def validate_ephemeral_volume(
        self,
        record: ResourceRecord,
        ownership: Ownership,
        mount: EphemeralMount,
        *,
        uid: int,
        gid: int,
    ) -> dict[str, Any]:
        self._validate_ephemeral_mounts(
            seeded_mounts=((record, mount),), empty_mounts=(), uid=uid, gid=gid
        )
        inspection = self.validate_owned(record, ownership)
        self._validate_ephemeral_volume_policy(
            inspection, options=self._volume_options(mount, uid=uid, gid=gid)
        )
        return inspection

    def create_seeder(
        self,
        *,
        name: str,
        image: str,
        ownership: Ownership,
        seeded_mounts: tuple[tuple[ResourceRecord, EphemeralMount], ...],
        uid: int,
        gid: int,
    ) -> ResourceRecord:
        parse_image_reference(image)
        if not seeded_mounts:
            raise IntegrityError("a storage seeder requires at least one reviewed mount")
        self._validate_ephemeral_mounts(
            seeded_mounts=seeded_mounts, empty_mounts=(), uid=uid, gid=gid
        )
        payload = self.seeder_payload(seeded_mounts)
        args = [
            "container",
            "create",
            "--name",
            name,
            "--network",
            "none",
            "--restart",
            "no",
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=10m",
            "--log-opt",
            "max-file=2",
            "--log-opt",
            "compress=true",
            "--user",
            f"{uid}:{gid}",
            "--read-only",
            "--security-opt",
            "no-new-privileges=true",
            "--cap-drop",
            "ALL",
            "--memory",
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "0.25",
            "--pids-limit",
            "64",
        ]
        for volume, mount in seeded_mounts:
            args.extend(
                (
                    "--mount",
                    f"type=volume,src={volume.name},dst={SEED_ROOT}/{mount.name}",
                )
            )
        args.extend(ownership.labels("seeder"))
        args.extend(("--entrypoint", "/nodejs/bin/node", image, "-e", SEED_SCRIPT, payload))
        result = self._run(tuple(args), timeout=self.timeouts.start)
        object_id = result.stdout.strip()
        if not OBJECT_ID.fullmatch(object_id):
            raise IntegrityError("Docker returned an invalid seeder container ID")
        record = ResourceRecord("container", name, object_id)
        inspection = self.validate_owned(record, ownership)
        try:
            self.validate_seeder_policy(
                inspection,
                image=image,
                seeded_mounts=seeded_mounts,
                uid=uid,
                gid=gid,
            )
        except (IntegrityError, PolicyError):
            self.remove(record)
            raise
        return record

    @staticmethod
    def seeder_payload(
        seeded_mounts: tuple[tuple[ResourceRecord, EphemeralMount], ...],
    ) -> str:
        return json.dumps(
            [
                {"source": mount.container_path, "target": f"{SEED_ROOT}/{mount.name}"}
                for _, mount in seeded_mounts
            ],
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def validate_seeder_policy(
        cls,
        inspection: dict[str, Any],
        *,
        image: str,
        seeded_mounts: tuple[tuple[ResourceRecord, EphemeralMount], ...],
        uid: int,
        gid: int,
    ) -> None:
        cls._validate_ephemeral_mounts(
            seeded_mounts=seeded_mounts, empty_mounts=(), uid=uid, gid=gid
        )
        config = inspection.get("Config")
        host = inspection.get("HostConfig")
        mounts = inspection.get("Mounts")
        payload = cls.seeder_payload(seeded_mounts)
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(mounts, list)
        ):
            raise IntegrityError("Docker storage seeder inspection is malformed")
        if (
            config.get("Image") != image
            or config.get("User") != f"{uid}:{gid}"
            or config.get("Entrypoint") != ["/nodejs/bin/node"]
            or config.get("Cmd") != ["-e", SEED_SCRIPT, payload]
        ):
            raise PolicyError("Docker storage seeder has unexpected execution identity")
        settings = inspection.get("NetworkSettings")
        networks = settings.get("Networks") if isinstance(settings, dict) else None
        null_attachment = networks.get("none") if isinstance(networks, dict) else None
        state = inspection.get("State")
        running = state.get("Running") if isinstance(state, dict) else None
        network_id = null_attachment.get("NetworkID") if isinstance(null_attachment, dict) else None
        endpoint_id = (
            null_attachment.get("EndpointID") if isinstance(null_attachment, dict) else None
        )
        valid_stopped_ids = (
            isinstance(network_id, str)
            and (network_id == "" or OBJECT_ID.fullmatch(network_id) is not None)
            and endpoint_id == ""
        )
        valid_running_ids = (
            isinstance(network_id, str)
            and OBJECT_ID.fullmatch(network_id) is not None
            and isinstance(endpoint_id, str)
            and OBJECT_ID.fullmatch(endpoint_id) is not None
        )
        if (
            not isinstance(networks, dict)
            or set(networks) != {"none"}
            or not isinstance(null_attachment, dict)
            or not isinstance(running, bool)
            or (running and not valid_running_ids)
            or (not running and not valid_stopped_ids)
        ):
            raise PolicyError("Docker storage seeder lacks its exact null-network attachment")
        restart = host.get("RestartPolicy")
        if (
            host.get("NetworkMode") != "none"
            or host.get("PortBindings") not in ({}, None)
            or host.get("PublishAllPorts") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or not isinstance(restart, dict)
            or restart.get("Name") != "no"
        ):
            raise PolicyError("Docker storage seeder has unsafe core runtime configuration")
        if (
            any(host.get(key) not in ("", "private") for key in ("PidMode", "IpcMode"))
            or host.get("UsernsMode") == "host"
            or host.get("CapDrop") != ["ALL"]
            or host.get("CapAdd") not in (None, [])
        ):
            raise PolicyError("Docker storage seeder has unsafe namespaces or capabilities")
        security_options = host.get("SecurityOpt")
        if (
            not isinstance(security_options, list)
            or "no-new-privileges=true" not in security_options
            or host.get("Devices") not in (None, [])
            or host.get("DeviceRequests") not in (None, [])
        ):
            raise PolicyError("Docker storage seeder lacks required privilege containment")
        if (
            host.get("Memory") != 128 * 1024 * 1024
            or host.get("MemorySwap") != 128 * 1024 * 1024
            or host.get("NanoCpus") != 250_000_000
            or host.get("PidsLimit") != 64
            or host.get("Tmpfs") not in ({}, None)
            or host.get("LogConfig")
            != {
                "Type": "local",
                "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
            }
        ):
            raise PolicyError("Docker storage seeder resource policy differs from reviewed values")
        expected_mounts = {
            (volume.name, f"{SEED_ROOT}/{mount.name}", True) for volume, mount in seeded_mounts
        }
        actual_mounts: set[tuple[str, str, bool]] = set()
        for mount in mounts:
            if not isinstance(mount, dict):
                raise IntegrityError("Docker storage seeder mount inspection is malformed")
            values = (mount.get("Name"), mount.get("Destination"), mount.get("RW"))
            if mount.get("Type") != "volume" or not (
                isinstance(values[0], str)
                and isinstance(values[1], str)
                and isinstance(values[2], bool)
            ):
                raise PolicyError("Docker storage seeder has an unreviewed filesystem mount")
            actual_mounts.add(cast(tuple[str, str, bool], values))
        if len(actual_mounts) != len(mounts) or actual_mounts != expected_mounts:
            raise PolicyError("Docker storage seeder mounts differ from reviewed values")

    def read_logs(self, record: ResourceRecord, *, timeout: float, tail: int = 20) -> Result:
        if record.kind != "container":
            raise ValueError("logs require a container")
        if not 0 < timeout <= self.timeouts.inspect:
            raise ValueError("log read timeout exceeds the bounded inspection timeout")
        return self._run(
            ("container", "logs", "--tail", str(tail), record.object_id),
            timeout=timeout,
            check=False,
        )

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
            "--log-opt",
            "compress=true",
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
        record = ResourceRecord("container", name, object_id)
        inspection = self.validate_owned(record, ownership)
        try:
            self.validate_gateway_policy(
                inspection,
                image=image,
                network=network,
                upstream_port=upstream_port,
                host_port=host_port,
            )
        except (IntegrityError, PolicyError):
            self.remove(record)
            raise
        return record

    @staticmethod
    def validate_gateway_policy(
        inspection: dict[str, Any],
        *,
        image: str,
        network: str,
        upstream_port: int,
        host_port: int,
    ) -> None:
        config = inspection.get("Config")
        host = inspection.get("HostConfig")
        mounts = inspection.get("Mounts")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(mounts, list)
        ):
            raise IntegrityError("Docker gateway inspection is malformed")
        expected_command = [
            "caddy",
            "reverse-proxy",
            "--from",
            ":8080",
            "--to",
            f"app:{upstream_port}",
        ]
        if (
            config.get("Image") != image
            or config.get("User") != "1000:1000"
            or config.get("Cmd") != expected_command
        ):
            raise PolicyError("Docker gateway has unexpected image, user, or command identity")
        expected_binding = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}]}
        if host.get("PortBindings") != expected_binding:
            raise PolicyError("Docker gateway does not have one exact loopback binding")
        restart = host.get("RestartPolicy")
        if (
            host.get("NetworkMode") != network
            or host.get("PublishAllPorts") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or not isinstance(restart, dict)
            or restart.get("Name") != "no"
        ):
            raise PolicyError("Docker gateway has unsafe core runtime configuration")
        if (
            any(host.get(key) not in ("", "private") for key in ("PidMode", "IpcMode"))
            or host.get("UsernsMode") == "host"
        ):
            raise PolicyError("Docker gateway uses a host namespace")
        if canonical_capabilities(host.get("CapDrop")) != ("ALL",) or canonical_capabilities(
            host.get("CapAdd")
        ) != ("NET_BIND_SERVICE",):
            raise PolicyError("Docker gateway has unexpected Linux capabilities")
        security_options = host.get("SecurityOpt")
        if (
            not isinstance(security_options, list)
            or "no-new-privileges=true" not in security_options
        ):
            raise PolicyError("Docker gateway lacks no-new-privileges")
        if host.get("Devices") not in (None, []) or host.get("DeviceRequests") not in (None, []):
            raise PolicyError("Docker gateway has unexpected device access")
        if (
            host.get("Memory") != 128 * 1024 * 1024
            or host.get("MemorySwap") != 128 * 1024 * 1024
            or host.get("NanoCpus") != 250_000_000
            or host.get("PidsLimit") != 64
        ):
            raise PolicyError("Docker gateway resource limits differ from the reviewed values")
        expected_tmpfs = dict.fromkeys(
            ("/config", "/data"),
            "rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700",
        )
        if host.get("Tmpfs") != expected_tmpfs or mounts:
            raise PolicyError("Docker gateway filesystem mounts differ from the reviewed values")
        if host.get("LogConfig") != {
            "Type": "local",
            "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
        }:
            raise PolicyError("Docker gateway log limits differ from the reviewed values")

    def connect_network(self, network: ResourceRecord, container: ResourceRecord) -> None:
        if network.kind != "network" or container.kind != "container":
            raise ValueError("network connection requires a network and container record")
        self._run(
            ("network", "connect", network.object_id, container.object_id),
            timeout=self.timeouts.start,
        )

    def network_connected(self, network: ResourceRecord, container: ResourceRecord) -> bool:
        if network.kind != "network" or container.kind != "container":
            raise ValueError("network inspection requires a network and container record")
        inspection = self.inspect("container", container.object_id)
        networks = self.container_networks(inspection)
        if network.name not in networks:
            return False
        attached_id = networks[network.name]
        if attached_id and attached_id != network.object_id:
            raise PolicyError("Docker container network attachment identity differs from state")
        return True

    @staticmethod
    def container_networks(inspection: dict[str, Any]) -> dict[str, str]:
        settings = inspection.get("NetworkSettings")
        networks = settings.get("Networks") if isinstance(settings, dict) else None
        if not isinstance(networks, dict):
            raise IntegrityError("Docker container network inspection is malformed")
        state = inspection.get("State")
        created = (
            isinstance(state, dict)
            and state.get("Running") is False
            and state.get("Status") == "created"
        )
        result: dict[str, str] = {}
        for name, attachment in networks.items():
            if (
                not isinstance(name, str)
                or not isinstance(attachment, dict)
                or not isinstance(attachment.get("NetworkID"), str)
            ):
                raise IntegrityError("Docker container network attachment is malformed")
            network_id = attachment["NetworkID"]
            if network_id:
                if not OBJECT_ID.fullmatch(network_id):
                    raise IntegrityError("Docker container network attachment is malformed")
            elif not created or attachment.get("EndpointID") != "":
                raise IntegrityError(
                    "Docker reports an unresolved network attachment outside created state"
                )
            result[name] = network_id
        return result

    @staticmethod
    def validate_network_endpoints(
        inspection: dict[str, Any], *, expected_container_ids: set[str]
    ) -> None:
        raw = inspection.get("Containers")
        if raw is None:
            raw = {}
        if not isinstance(raw, dict) or any(
            not isinstance(object_id, str) or not OBJECT_ID.fullmatch(object_id)
            for object_id in raw
        ):
            raise IntegrityError("Docker network endpoint inspection is malformed")
        actual = set(raw)
        if actual != expected_container_ids:
            raise PolicyError("Docker network endpoints differ from the exact managed topology")

    def configured_network_consumers(self, network: ResourceRecord) -> set[str]:
        """Return all containers, including stopped ones, configured for a network."""
        if (
            network.kind != "network"
            or not RESOURCE_NAME.fullmatch(network.name)
            or not OBJECT_ID.fullmatch(network.object_id)
        ):
            raise IntegrityError("recorded Docker network identity is malformed")
        response = self._run(
            ("container", "ls", "--all", "--no-trunc", "--quiet"),
            timeout=self.timeouts.inspect,
        )
        container_ids = tuple(line for line in response.stdout.splitlines() if line)
        if len(set(container_ids)) != len(container_ids) or any(
            not OBJECT_ID.fullmatch(object_id) for object_id in container_ids
        ):
            raise IntegrityError("Docker returned malformed container inventory")
        consumers: set[str] = set()
        for object_id in container_ids:
            inspection = self.inspect("container", object_id)
            if inspection.get("Id") != object_id:
                raise IntegrityError(
                    "Docker container inventory identity changed during inspection"
                )
            settings = inspection.get("NetworkSettings")
            attachments = settings.get("Networks") if isinstance(settings, dict) else None
            if not isinstance(attachments, dict):
                raise IntegrityError("Docker container network inspection is malformed")
            for name, attachment in attachments.items():
                if not isinstance(name, str) or not isinstance(attachment, dict):
                    raise IntegrityError("Docker container network attachment is malformed")
                attached_id = attachment.get("NetworkID")
                if not isinstance(attached_id, str) or (
                    attached_id and not OBJECT_ID.fullmatch(attached_id)
                ):
                    raise IntegrityError("Docker container network attachment is malformed")
                if attached_id == network.object_id or (not attached_id and name == network.name):
                    consumers.add(object_id)
        return consumers

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
    if record.kind == "container" and suffix in {"app", "gateway", "seeder"}:
        if suffix == "app":
            return "application"
        return suffix
    if record.kind == "network" and suffix in {"net", "ingress"}:
        return "network"
    if record.kind == "volume" and suffix == "volume":
        return "volume"
    if record.kind == "volume" and suffix.startswith("volume-") and len(suffix) > len("volume-"):
        return suffix
    raise PolicyError(f"refusing {record.kind} {record.name}: resource role is not recognized")
