from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from vulndockyard.docker import (
    CREATED,
    GATEWAY_MODE_IPV4,
    LAB,
    MANIFEST,
    MANIFEST_VERSION,
    OWNER,
    RUN,
    SEED_READY_MARKER,
    SEED_SCRIPT,
    TRUSTED,
    Docker,
    DockerConnection,
    Ownership,
    Timeouts,
    engine_supports_isolated_networking,
    parse_engine_version,
)
from vulndockyard.errors import IntegrityError, PolicyError, PreflightError
from vulndockyard.models import EphemeralMount
from vulndockyard.process import Result, Runner
from vulndockyard.state import ResourceRecord


class RecordingRunner(Runner):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[Mapping[str, str] | None] = []
        self.responses: list[Result] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> Result:
        call = tuple(argv)
        self.calls.append(call)
        self.environments.append(env)
        if self.responses:
            return self.responses.pop(0)
        return Result(call, 0, "a" * 64 + "\n", "")


def test_timeout_environment_is_bounded_and_configurable() -> None:
    configured = Timeouts.discover({"VDY_TIMEOUT_PULL": "42"})
    assert configured.pull == 42
    assert configured.health == 120
    with pytest.raises(PreflightError, match="must be numeric"):
        Timeouts.discover({"VDY_TIMEOUT_PULL": "forever"})
    with pytest.raises(PreflightError, match="between"):
        Timeouts.discover({"VDY_TIMEOUT_CLEANUP": "0"})


def ownership() -> Ownership:
    return Ownership("juice-shop", "b" * 64, "c" * 32, "2026-09-06T00:00:00Z", True)


def fake_connection() -> DockerConnection:
    return DockerConnection("docker", Path("/var/run/docker.sock"))


def labels(value: Ownership) -> dict[str, str]:
    return role_labels(value, "application")


def role_labels(value: Ownership, role: str) -> dict[str, str]:
    items = iter(value.labels(role))
    result: dict[str, str] = {}
    for marker, assignment in zip(items, items, strict=True):
        assert marker == "--label"
        key, item = assignment.split("=", 1)
        result[key] = item
    return result


def network_inspection(
    value: Ownership,
    *,
    name: str = "vdy-juice-shop-cccccccccccc-net",
    object_id: str = "a" * 64,
    internal: bool = True,
    driver: str = "bridge",
    options: dict[str, str] | None = None,
) -> dict[str, object]:
    raw = value.labels("network")
    network_labels = {
        raw[index + 1].split("=", 1)[0]: raw[index + 1].split("=", 1)[1]
        for index in range(0, len(raw), 2)
    }
    if options is None:
        options = {GATEWAY_MODE_IPV4: "isolated" if internal else "nat"}
    return {
        "Id": object_id,
        "Name": name,
        "Driver": driver,
        "Scope": "local",
        "Internal": internal,
        "Attachable": False,
        "ConfigOnly": False,
        "EnableIPv6": False,
        "Ingress": False,
        "Options": options,
        "Labels": network_labels,
    }


def gateway_inspection(
    value: Ownership,
    *,
    name: str = "vdy-juice-shop-cccccccccccc-gateway",
    object_id: str = "a" * 64,
    image: str = "docker.io/library/caddy@sha256:" + "2" * 64,
    network: str = "vdy-ingress",
    upstream_port: int = 3000,
    host_port: int = 8080,
) -> dict[str, object]:
    return {
        "Id": object_id,
        "Name": f"/{name}",
        "Config": {
            "Image": image,
            "User": "1000:1000",
            "Cmd": [
                "caddy",
                "reverse-proxy",
                "--from",
                ":8080",
                "--to",
                f"app:{upstream_port}",
            ],
            "Labels": role_labels(value, "gateway"),
        },
        "HostConfig": {
            "NetworkMode": network,
            "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}]},
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "PidMode": "",
            "IpcMode": "private",
            "UsernsMode": "",
            "CapDrop": ["ALL"],
            "CapAdd": ["NET_BIND_SERVICE"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Devices": [],
            "DeviceRequests": None,
            "Memory": 128 * 1024 * 1024,
            "MemorySwap": 128 * 1024 * 1024,
            "NanoCpus": 250_000_000,
            "PidsLimit": 64,
            "Tmpfs": dict.fromkeys(
                ("/config", "/data"),
                "rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700",
            ),
            "LogConfig": {
                "Type": "local",
                "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
            },
        },
        "Mounts": [],
    }


def application_inspection(
    value: Ownership,
    *,
    name: str = "vdy-juice-shop-cccccccccccc-app",
    object_id: str = "a" * 64,
    image: str = "registry.example.test/app@sha256:" + "1" * 64,
    network: str = "vdy-network",
    memory_mb: int = 512,
    cpus: float = 0.5,
    pids: int = 256,
    uid: int = 65532,
    gid: int = 65532,
    mounts: list[dict[str, object]] | None = None,
    tmpfs: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "Id": object_id,
        "Name": f"/{name}",
        "Config": {
            "Image": image,
            "User": f"{uid}:{gid}",
            "Labels": role_labels(value, "application"),
        },
        "HostConfig": {
            "NetworkMode": network,
            "PortBindings": {},
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "PidMode": "",
            "IpcMode": "private",
            "UsernsMode": "",
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges=true"],
            "Devices": [],
            "DeviceRequests": [],
            "Memory": memory_mb * 1024 * 1024,
            "MemorySwap": memory_mb * 1024 * 1024,
            "NanoCpus": round(cpus * 1_000_000_000),
            "PidsLimit": pids,
            "Tmpfs": tmpfs or {},
            "LogConfig": {
                "Type": "local",
                "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
            },
        },
        "Mounts": (mounts or [])
        + [
            {
                "Type": "tmpfs",
                "Source": "",
                "Destination": path,
                "Mode": "",
                "RW": True,
                "Propagation": "",
            }
            for path in (tmpfs or {})
        ],
    }


def seeder_inspection(
    value: Ownership,
    volume: ResourceRecord,
    mount: EphemeralMount,
    *,
    image: str = "registry.example.test/app@sha256:" + "1" * 64,
) -> dict[str, object]:
    payload = json.dumps(
        [{"source": mount.container_path, "target": f"/vdy-seed/{mount.name}"}],
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "Id": "a" * 64,
        "Name": "/vdy-juice-shop-cccccccccccc-seeder",
        "Config": {
            "Image": image,
            "User": "65532:65532",
            "Entrypoint": ["/nodejs/bin/node"],
            "Cmd": ["-e", SEED_SCRIPT, payload],
            "Labels": role_labels(value, "seeder"),
        },
        "HostConfig": {
            "NetworkMode": "none",
            "PortBindings": {},
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "PidMode": "",
            "IpcMode": "private",
            "UsernsMode": "",
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges=true"],
            "Devices": [],
            "DeviceRequests": None,
            "Memory": 128 * 1024 * 1024,
            "MemorySwap": 128 * 1024 * 1024,
            "NanoCpus": 250_000_000,
            "PidsLimit": 64,
            "Tmpfs": None,
            "LogConfig": {
                "Type": "local",
                "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
            },
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": volume.name,
                "Destination": f"/vdy-seed/{mount.name}",
                "RW": True,
            }
        ],
        "NetworkSettings": {"Networks": {"none": {"NetworkID": "", "EndpointID": ""}}},
        "State": {"Running": False},
    }


def test_application_command_has_containment_and_no_publication() -> None:
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([application_inspection(ownership())]), ""),
    ]
    docker = Docker(
        runner,
        Timeouts(),
        connection=fake_connection(),
        environment={
            "DOCKER_CONFIG": "/attacker",
            "DOCKER_CONTEXT": "remote",
            "DOCKER_HOST": "tcp://attacker.invalid:2375",
            "HTTP_PROXY": "http://attacker.invalid",
        },
    )
    record = docker.create_application(
        name="vdy-juice-shop-cccccccccccc-app",
        image="registry.example.test/app@sha256:" + "1" * 64,
        network="vdy-network",
        ownership=ownership(),
        memory_mb=512,
        cpus=0.5,
        pids=256,
        read_only=True,
        storage_uid=65532,
        storage_gid=65532,
    )
    call = next(call for call in runner.calls if call[3:5] == ("container", "create"))
    assert record.object_id == "a" * 64
    assert call[:5] == (
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "container",
        "create",
    )
    assert "--publish" not in call
    assert (call[call.index("--restart")], call[call.index("--restart") + 1]) == ("--restart", "no")
    assert call[call.index("--cap-drop") + 1] == "ALL"
    assert call[call.index("--security-opt") + 1] == "no-new-privileges=true"
    assert call[call.index("--memory") + 1] == "512m"
    assert call[call.index("--memory-swap") + 1] == "512m"
    assert "--read-only" in call
    assert call[call.index("--user") + 1] == "65532:65532"
    assert call[call.index("--log-driver") + 1] == "local"
    assert [call[index + 1] for index, value in enumerate(call) if value == "--log-opt"] == [
        "max-size=10m",
        "max-file=2",
        "compress=true",
    ]
    assert "--privileged" not in call
    assert runner.environments[-1] == fake_connection().environment()


def test_application_command_mounts_only_exact_reviewed_writable_paths() -> None:
    runner = RecordingRunner()
    volume = ResourceRecord(
        "volume",
        "vdy-juice-shop-cccccccccccc-volume-data",
        "vdy-juice-shop-cccccccccccc-volume-data",
    )
    seeded = EphemeralMount("data", "/juice-shop/data", 64)
    empty = EphemeralMount("tmp", "/tmp", 16)  # noqa: S108 - reviewed container path
    inspection = application_inspection(
        ownership(),
        mounts=[
            {
                "Type": "volume",
                "Name": volume.name,
                "Destination": seeded.container_path,
                "RW": True,
            }
        ],
        tmpfs={
            empty.container_path: ("rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700")
        },
    )
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())

    docker.create_application(
        name="vdy-juice-shop-cccccccccccc-app",
        image="registry.example.test/app@sha256:" + "1" * 64,
        network="vdy-network",
        ownership=ownership(),
        memory_mb=512,
        cpus=0.5,
        pids=256,
        read_only=True,
        seeded_mounts=((volume, seeded),),
        empty_mounts=(empty,),
        storage_uid=65532,
        storage_gid=65532,
    )

    call = next(call for call in runner.calls if call[3:5] == ("container", "create"))
    assert call[call.index("--mount") + 1] == (
        "type=volume,src=vdy-juice-shop-cccccccccccc-volume-data,dst=/juice-shop/data"
    )
    assert call[call.index("--tmpfs") + 1] == (
        "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700"  # noqa: S108
    )
    assert "--read-only" in call
    assert "--publish" not in call


def test_application_policy_mismatch_removes_only_exact_validated_container() -> None:
    inspection = application_inspection(ownership())
    assert isinstance(inspection["HostConfig"], dict)
    inspection["HostConfig"]["ReadonlyRootfs"] = False
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())

    with pytest.raises(PolicyError, match="unsafe core runtime"):
        docker.create_application(
            name="vdy-juice-shop-cccccccccccc-app",
            image="registry.example.test/app@sha256:" + "1" * 64,
            network="vdy-network",
            ownership=ownership(),
            memory_mb=512,
            cpus=0.5,
            pids=256,
            read_only=True,
            storage_uid=65532,
            storage_gid=65532,
        )

    assert runner.calls[-1][3:] == ("container", "rm", "--force", "a" * 64)


def test_application_policy_rejects_effective_containment_drift() -> None:
    def validate(inspection: dict[str, object]) -> None:
        Docker.validate_application_policy(
            inspection,
            image="registry.example.test/app@sha256:" + "1" * 64,
            network="vdy-network",
            memory_mb=512,
            cpus=0.5,
            pids=256,
            seeded_mounts=(),
            empty_mounts=(),
            storage_uid=65532,
            storage_gid=65532,
        )

    def rejected(
        group: str,
        key: str,
        value: object,
        message: str,
        error: type[Exception] = PolicyError,
    ) -> None:
        inspection = application_inspection(ownership())
        section = inspection[group]
        assert isinstance(section, dict)
        section[key] = value
        with pytest.raises(error, match=message):
            validate(inspection)

    rejected("Config", "User", "0:0", "image or user")
    rejected("HostConfig", "NetworkMode", "host", "core runtime")
    rejected("HostConfig", "PidMode", "host", "host namespace")
    rejected("HostConfig", "CapDrop", [], "capabilities")
    rejected("HostConfig", "SecurityOpt", [], "no-new-privileges")
    rejected("HostConfig", "Devices", [{}], "device access")
    rejected("HostConfig", "Memory", 0, "resource limits")
    rejected("HostConfig", "Tmpfs", {"/unreviewed": "rw"}, "tmpfs mounts")
    rejected("HostConfig", "LogConfig", None, "log limits")

    malformed_config = application_inspection(ownership())
    malformed_config["Config"] = None
    with pytest.raises(IntegrityError, match="inspection is malformed"):
        validate(malformed_config)

    malformed = application_inspection(ownership())
    malformed["Mounts"] = ["not-an-object"]
    with pytest.raises(IntegrityError, match="mount inspection"):
        validate(malformed)

    unreviewed = application_inspection(ownership())
    unreviewed["Mounts"] = [{"Type": "bind", "Name": "host", "Destination": "/host", "RW": True}]
    with pytest.raises(PolicyError, match="unreviewed filesystem mount"):
        validate(unreviewed)

    unexpected = application_inspection(ownership())
    unexpected["Mounts"] = [{"Type": "volume", "Name": "other", "Destination": "/data", "RW": True}]
    with pytest.raises(PolicyError, match="mount inventory differs"):
        validate(unexpected)


def test_seeded_volume_uses_exact_tmpfs_driver_options_and_identity() -> None:
    value = ownership()
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    name = "vdy-juice-shop-cccccccccccc-volume-data"
    inspection = {
        "Name": name,
        "Driver": "local",
        "Options": {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": "size=64m,uid=65532,gid=65532,mode=0700,noexec,nosuid,nodev",
        },
        "Labels": role_labels(value, "volume-data"),
    }
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, f"{name}\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())

    record = docker.create_ephemeral_volume(
        name=name, mount=mount, ownership=value, uid=65532, gid=65532
    )

    assert record == ResourceRecord("volume", name, name)
    create = runner.calls[0]
    assert [create[index + 1] for index, item in enumerate(create) if item == "--opt"] == [
        "type=tmpfs",
        "device=tmpfs",
        "o=size=64m,uid=65532,gid=65532,mode=0700,noexec,nosuid,nodev",
    ]


def test_seeded_volume_policy_mismatch_removes_only_validated_volume() -> None:
    value = ownership()
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    name = "vdy-juice-shop-cccccccccccc-volume-data"
    inspection = {
        "Name": name,
        "Driver": "local",
        "Options": {"type": "tmpfs", "device": "tmpfs", "o": "size=65m"},
        "Labels": role_labels(value, "volume-data"),
    }
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, f"{name}\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())

    with pytest.raises(PolicyError, match="driver options"):
        docker.create_ephemeral_volume(
            name=name, mount=mount, ownership=value, uid=65532, gid=65532
        )
    assert runner.calls[-1][3:] == ("volume", "rm", name)


def test_seeder_uses_locked_image_fixed_node_script_and_strict_containment() -> None:
    runner = RecordingRunner()
    volume = ResourceRecord(
        "volume",
        "vdy-juice-shop-cccccccccccc-volume-data",
        "vdy-juice-shop-cccccccccccc-volume-data",
    )
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    image = "registry.example.test/app@sha256:" + "1" * 64
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(
            ("docker",),
            0,
            json.dumps([seeder_inspection(ownership(), volume, mount, image=image)]),
            "",
        ),
    ]
    docker = Docker(runner, connection=fake_connection())

    docker.create_seeder(
        name="vdy-juice-shop-cccccccccccc-seeder",
        image=image,
        ownership=ownership(),
        seeded_mounts=((volume, mount),),
        uid=65532,
        gid=65532,
    )

    call = next(call for call in runner.calls if call[3:5] == ("container", "create"))
    assert call[call.index("--network") + 1] == "none"
    assert call[call.index("--user") + 1] == "65532:65532"
    assert call[call.index("--entrypoint") + 1] == "/nodejs/bin/node"
    assert call[-4:] == (image, "-e", SEED_SCRIPT, call[-1])
    assert json.loads(call[-1]) == [{"source": "/juice-shop/data", "target": "/vdy-seed/data"}]
    assert SEED_READY_MARKER in SEED_SCRIPT
    assert "--read-only" in call
    assert call[call.index("--cap-drop") + 1] == "ALL"
    assert call[call.index("--security-opt") + 1] == "no-new-privileges=true"
    assert [call[index + 1] for index, value in enumerate(call) if value == "--log-opt"] == [
        "max-size=10m",
        "max-file=2",
        "compress=true",
    ]
    assert "--privileged" not in call


def test_seeder_policy_mismatch_removes_only_exact_validated_container() -> None:
    volume = ResourceRecord(
        "volume",
        "vdy-juice-shop-cccccccccccc-volume-data",
        "vdy-juice-shop-cccccccccccc-volume-data",
    )
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    inspection = seeder_inspection(ownership(), volume, mount)
    assert isinstance(inspection["HostConfig"], dict)
    inspection["HostConfig"]["NetworkMode"] = "host"
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())

    with pytest.raises(PolicyError, match="unsafe core runtime"):
        docker.create_seeder(
            name="vdy-juice-shop-cccccccccccc-seeder",
            image="registry.example.test/app@sha256:" + "1" * 64,
            ownership=ownership(),
            seeded_mounts=((volume, mount),),
            uid=65532,
            gid=65532,
        )

    assert runner.calls[-1][3:] == ("container", "rm", "--force", "a" * 64)


def test_seeder_policy_rejects_any_effective_network_attachment() -> None:
    volume = ResourceRecord(
        "volume",
        "vdy-juice-shop-cccccccccccc-volume-data",
        "vdy-juice-shop-cccccccccccc-volume-data",
    )
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    inspection = seeder_inspection(ownership(), volume, mount)
    settings = inspection["NetworkSettings"]
    assert isinstance(settings, dict)
    settings["Networks"] = {"foreign": {"NetworkID": "f" * 64}}

    with pytest.raises(PolicyError, match="exact null-network attachment"):
        Docker.validate_seeder_policy(
            inspection,
            image="registry.example.test/app@sha256:" + "1" * 64,
            seeded_mounts=((volume, mount),),
            uid=65532,
            gid=65532,
        )


@pytest.mark.parametrize(
    ("running", "network_id", "endpoint_id"),
    (
        (False, "", ""),
        (False, "d" * 64, ""),
        (True, "d" * 64, "e" * 64),
    ),
)
def test_seeder_policy_accepts_exact_none_attachment_lifecycle_forms(
    running: bool, network_id: str, endpoint_id: str
) -> None:
    volume = ResourceRecord(
        "volume",
        "vdy-juice-shop-cccccccccccc-volume-data",
        "vdy-juice-shop-cccccccccccc-volume-data",
    )
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    inspection = seeder_inspection(ownership(), volume, mount)
    inspection["State"] = {"Running": running}
    inspection["NetworkSettings"] = {
        "Networks": {"none": {"NetworkID": network_id, "EndpointID": endpoint_id}}
    }

    Docker.validate_seeder_policy(
        inspection,
        image="registry.example.test/app@sha256:" + "1" * 64,
        seeded_mounts=((volume, mount),),
        uid=65532,
        gid=65532,
    )


def test_seeder_policy_rejects_none_attachment_ids_inconsistent_with_running_state() -> None:
    volume = ResourceRecord(
        "volume",
        "vdy-juice-shop-cccccccccccc-volume-data",
        "vdy-juice-shop-cccccccccccc-volume-data",
    )
    mount = EphemeralMount("data", "/juice-shop/data", 64)
    inspection = seeder_inspection(ownership(), volume, mount)
    inspection["State"] = {"Running": True}

    with pytest.raises(PolicyError, match="exact null-network attachment"):
        Docker.validate_seeder_policy(
            inspection,
            image="registry.example.test/app@sha256:" + "1" * 64,
            seeded_mounts=((volume, mount),),
            uid=65532,
            gid=65532,
        )


def test_gateway_command_binds_only_loopback_and_fixed_target() -> None:
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([gateway_inspection(ownership())]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())
    docker.create_gateway(
        name="vdy-juice-shop-cccccccccccc-gateway",
        image="docker.io/library/caddy@sha256:" + "2" * 64,
        network="vdy-ingress",
        upstream_port=3000,
        host_port=8080,
        ownership=ownership(),
    )
    call = next(call for call in runner.calls if call[3:5] == ("container", "create"))
    assert call[call.index("--publish") + 1] == "127.0.0.1:8080:8080"
    assert call[call.index("--user") + 1] == "1000:1000"
    assert call[call.index("--cap-add") + 1] == "NET_BIND_SERVICE"
    assert call[call.index("--memory") + 1] == "128m"
    assert call[call.index("--memory-swap") + 1] == "128m"
    assert call[call.index("--log-driver") + 1] == "local"
    assert [call[index + 1] for index, value in enumerate(call) if value == "--log-opt"] == [
        "max-size=10m",
        "max-file=2",
        "compress=true",
    ]
    tmpfs_values = [call[index + 1] for index, value in enumerate(call) if value == "--tmpfs"]
    assert all("uid=1000,gid=1000,mode=0700" in value for value in tmpfs_values)
    assert list(call[-6:]) == ["caddy", "reverse-proxy", "--from", ":8080", "--to", "app:3000"]

    with pytest.raises(PolicyError, match="valid range"):
        docker.create_gateway(
            name="vdy-gateway",
            image="docker.io/library/caddy@sha256:" + "2" * 64,
            network="vdy-ingress",
            upstream_port=3000,
            host_port=True,
            ownership=ownership(),
        )


def test_gateway_policy_mismatch_removes_only_exact_validated_container() -> None:
    inspection = gateway_inspection(ownership())
    assert isinstance(inspection["HostConfig"], dict)
    inspection["HostConfig"]["PortBindings"] = {
        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]  # noqa: S104
    }
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match="exact loopback"):
        docker.create_gateway(
            name="vdy-juice-shop-cccccccccccc-gateway",
            image="docker.io/library/caddy@sha256:" + "2" * 64,
            network="vdy-ingress",
            upstream_port=3000,
            host_port=8080,
            ownership=ownership(),
        )
    assert runner.calls[-1][3:] == ("container", "rm", "--force", "a" * 64)


def test_gateway_policy_rejects_effective_containment_drift() -> None:
    def validate(inspection: dict[str, object]) -> None:
        Docker.validate_gateway_policy(
            inspection,
            image="docker.io/library/caddy@sha256:" + "2" * 64,
            network="vdy-ingress",
            upstream_port=3000,
            host_port=8080,
        )

    def rejected(group: str, key: str, value: object, message: str) -> None:
        inspection = gateway_inspection(ownership())
        section = inspection[group]
        assert isinstance(section, dict)
        section[key] = value
        with pytest.raises(PolicyError, match=message):
            validate(inspection)

    prefixed = gateway_inspection(ownership())
    prefixed_host = prefixed["HostConfig"]
    assert isinstance(prefixed_host, dict)
    prefixed_host["CapDrop"] = ["CAP_ALL"]
    prefixed_host["CapAdd"] = ["CAP_NET_BIND_SERVICE"]
    validate(prefixed)

    rejected("Config", "Cmd", ["sh"], "image, user, or command")
    rejected("HostConfig", "NetworkMode", "host", "core runtime")
    rejected("HostConfig", "IpcMode", "host", "host namespace")
    rejected("HostConfig", "CapAdd", ["SYS_ADMIN"], "capabilities")
    rejected(
        "HostConfig",
        "CapAdd",
        ["CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"],
        "capabilities",
    )
    rejected("HostConfig", "SecurityOpt", [], "no-new-privileges")
    rejected("HostConfig", "DeviceRequests", [{}], "device access")
    rejected("HostConfig", "PidsLimit", 0, "resource limits")
    rejected("HostConfig", "Tmpfs", {}, "filesystem mounts")
    rejected("HostConfig", "LogConfig", None, "log limits")

    malformed = gateway_inspection(ownership())
    malformed["Mounts"] = None
    with pytest.raises(IntegrityError, match="inspection is malformed"):
        validate(malformed)


def test_network_and_cleanup_commands_are_scoped() -> None:
    runner = RecordingRunner()
    value = ownership()
    name = "vdy-juice-shop-cccccccccccc-net"
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([network_inspection(value)]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())
    network = docker.create_network(name, value, internal=True)
    create_call = next(call for call in runner.calls if call[3:5] == ("network", "create"))
    assert "--internal" in create_call
    assert create_call[create_call.index("--opt") + 1] == f"{GATEWAY_MODE_IPV4}=isolated"
    docker.remove(ResourceRecord("container", "app", "d" * 64))
    assert runner.calls[-1] == (
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "container",
        "rm",
        "--force",
        "d" * 64,
    )
    docker.remove(network)
    assert list(runner.calls[-1]) == [
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "network",
        "rm",
        "a" * 64,
    ]
    assert all("prune" not in call for argv in runner.calls for call in argv)


def test_ingress_network_has_explicit_nat_mode_and_no_internal_flag() -> None:
    value = ownership()
    name = "vdy-juice-shop-cccccccccccc-ingress"
    inspection = network_inspection(value, name=name, internal=False)
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())
    assert docker.create_network(name, value, internal=False).object_id == "a" * 64
    create_call = next(call for call in runner.calls if call[3:5] == ("network", "create"))
    assert "--internal" not in create_call
    assert create_call[create_call.index("--opt") + 1] == f"{GATEWAY_MODE_IPV4}=nat"


@pytest.mark.parametrize(
    ("internal", "inspection", "message"),
    (
        (True, network_inspection(ownership(), driver="overlay"), "bridge driver"),
        (
            True,
            network_inspection(ownership(), internal=False, options={}),
            "Internal setting",
        ),
        (
            True,
            network_inspection(ownership(), options={GATEWAY_MODE_IPV4: "nat"}),
            "driver options",
        ),
        (
            False,
            network_inspection(
                ownership(),
                name="vdy-juice-shop-cccccccccccc-ingress",
                internal=False,
                options={GATEWAY_MODE_IPV4: "routed"},
            ),
            "driver options",
        ),
        (
            True,
            {**network_inspection(ownership()), "Attachable": True},
            "unsafe scope or mode flags",
        ),
    ),
)
def test_new_network_policy_mismatch_removes_only_the_validated_object(
    internal: bool, inspection: dict[str, object], message: str
) -> None:
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match=message):
        docker.create_network(str(inspection["Name"]), ownership(), internal=internal)
    assert runner.calls[-1][3:] == ("network", "rm", "a" * 64)


def test_new_network_with_unexpected_ownership_is_not_removed() -> None:
    inspection = network_inspection(ownership())
    assert isinstance(inspection["Labels"], dict)
    inspection["Labels"][OWNER] = "false"
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, "a" * 64 + "\n", ""),
        Result(("docker",), 0, json.dumps([inspection]), ""),
    ]
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match="ownership labels mismatch"):
        docker.create_network(str(inspection["Name"]), ownership(), internal=True)
    assert not any(call[3:5] == ("network", "rm") for call in runner.calls)


def test_pull_requires_digest_and_verifies_repository_identity() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match="immutable"):
        docker.pull("registry.example.test/app:latest")
    reference = "docker.io/library/caddy@sha256:" + "e" * 64
    inspection = [{"RepoDigests": ["caddy@sha256:" + "e" * 64]}]
    runner.responses = [
        Result(("docker",), 0, "", ""),
        Result(("docker",), 0, json.dumps(inspection), ""),
    ]
    docker.pull(reference)
    runner.responses = [
        Result(("docker",), 0, "", ""),
        Result(("docker",), 0, json.dumps([{"RepoDigests": ["other@sha256:" + "e" * 64]}]), ""),
    ]
    with pytest.raises(IntegrityError, match="does not report"):
        docker.pull(reference)


@pytest.mark.parametrize(
    "reference",
    [
        "--host@sha256:" + "1" * 64,
        "example/app@sha256:" + "1" * 64,
        "registry.example.test/app@sha256:" + "1" * 63,
        "registry.example.test/app@sha256:" + "1" * 64 + "\n--privileged",
        "registry.example.test/app@@sha256:" + "1" * 64,
    ],
)
def test_all_image_argv_boundaries_reject_noncanonical_references(reference: str) -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.pull(reference)
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.create_application(
            name="vdy-app",
            image=reference,
            network="vdy-network",
            ownership=ownership(),
            memory_mb=512,
            cpus=0.5,
            pids=256,
            read_only=False,
        )
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.create_gateway(
            name="vdy-gateway",
            image=reference,
            network="vdy-ingress",
            upstream_port=3000,
            host_port=18080,
            ownership=ownership(),
        )
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.remove_image(reference)
    assert runner.calls == []


def test_ownership_validation_requires_every_identity_label() -> None:
    value = ownership()
    name = "vdy-juice-shop-cccccccccccc-app"
    inspection = {"Id": "d" * 64, "Name": f"/{name}", "Config": {"Labels": labels(value)}}
    runner = RecordingRunner()
    runner.responses = [Result(("docker",), 0, json.dumps([inspection]), "")]
    docker = Docker(runner, connection=fake_connection())
    record = ResourceRecord("container", name, "d" * 64)
    assert docker.validate_owned(record, value)["Id"] == "d" * 64
    for key in (OWNER, LAB, MANIFEST, MANIFEST_VERSION, RUN, CREATED, TRUSTED):
        broken = json.loads(json.dumps(inspection))
        broken["Config"]["Labels"][key] = "wrong"
        runner.responses = [Result(("docker",), 0, json.dumps([broken]), "")]
        with pytest.raises(PolicyError, match="ownership labels mismatch"):
            docker.validate_owned(record, value)
    wrong_name = json.loads(json.dumps(inspection))
    wrong_name["Name"] = "/unrelated"
    runner.responses = [Result(("docker",), 0, json.dumps([wrong_name]), "")]
    with pytest.raises(PolicyError, match="name mismatch"):
        docker.validate_owned(record, value)
    wrong_role = json.loads(json.dumps(inspection))
    wrong_role["Config"]["Labels"]["org.vulndockyard.role"] = "gateway"
    runner.responses = [Result(("docker",), 0, json.dumps([wrong_role]), "")]
    with pytest.raises(PolicyError, match="ownership labels mismatch"):
        docker.validate_owned(record, value)


def test_remaining_bounded_docker_operations_construct_exact_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, '"28.1.5+ubuntu"\n', ""),
        Result(("docker",), 0, "2.40.0\n", ""),
    ]
    docker = Docker(runner, Timeouts(stop=2), connection=fake_connection())
    monkeypatch.setattr("vulndockyard.docker.platform.system", lambda: "Linux")
    monkeypatch.setattr("vulndockyard.docker.platform.machine", lambda: "x86_64")
    assert docker.preflight() == {
        "engine": "28.1.5+ubuntu",
        "engine_version": {"major": 28, "minor": 1, "patch": 5, "suffix": "+ubuntu"},
        "minimum_engine": "28.0.0",
        "isolated_networking": True,
        "compose_v2": True,
        "platform": "linux/amd64",
    }
    container = ResourceRecord("container", "app", "d" * 64)
    network = ResourceRecord("network", "net", "e" * 64)
    docker.connect_network(network, container)
    docker.start(container)
    docker.stop(container)
    runner.responses = [Result(("docker",), 0, "line\n", "warning\n")]
    assert docker.logs(container, follow=True).stdout == "line\n"
    docker.remove_image("registry.example.test/app@sha256:" + "f" * 64)
    runner.responses = [
        Result(("docker",), 0, "1" * 64 + "\n", ""),
        Result(("docker",), 0, "2" * 64 + "\n", ""),
        Result(("docker",), 0, "vdy-volume\n", ""),
    ]
    assert docker.managed_resources() == {
        "container": ("1" * 64,),
        "network": ("2" * 64,),
        "volume": ("vdy-volume",),
    }
    assert (
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "network",
        "connect",
        "e" * 64,
        "d" * 64,
    ) in runner.calls
    assert not any("system" in call for argv in runner.calls for call in argv)


def test_network_attachment_inspection_is_exact_and_fail_closed() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    network = ResourceRecord("network", "vdy-net", "e" * 64)
    container = ResourceRecord("container", "vdy-app", "d" * 64)

    runner.responses = [
        Result(
            ("docker",),
            0,
            json.dumps(
                [
                    {
                        "Id": container.object_id,
                        "NetworkSettings": {
                            "Networks": {network.name: {"NetworkID": network.object_id}}
                        },
                    }
                ]
            ),
            "",
        )
    ]
    assert docker.network_connected(network, container)

    runner.responses = [
        Result(
            ("docker",),
            0,
            json.dumps([{"NetworkSettings": {"Networks": {}}}]),
            "",
        )
    ]
    assert not docker.network_connected(network, container)

    runner.responses = [
        Result(
            ("docker",),
            0,
            json.dumps(
                [{"NetworkSettings": {"Networks": {network.name: {"NetworkID": "f" * 64}}}}]
            ),
            "",
        )
    ]
    with pytest.raises(PolicyError, match="attachment identity differs"):
        docker.network_connected(network, container)

    runner.responses = [Result(("docker",), 0, json.dumps([{}]), "")]
    with pytest.raises(IntegrityError, match="network inspection is malformed"):
        docker.network_connected(network, container)


def test_created_container_network_attachment_accepts_only_docker_unresolved_form() -> None:
    network_id = "e" * 64
    created = {
        "State": {"Running": False, "Status": "created"},
        "NetworkSettings": {"Networks": {"vdy-net": {"NetworkID": "", "EndpointID": ""}}},
    }
    assert Docker.container_networks(created) == {"vdy-net": ""}

    for status, endpoint in (("exited", ""), ("created", "f" * 64)):
        malformed = {
            "State": {"Running": False, "Status": status},
            "NetworkSettings": {"Networks": {"vdy-net": {"NetworkID": "", "EndpointID": endpoint}}},
        }
        with pytest.raises(IntegrityError, match="unresolved network attachment"):
            Docker.container_networks(malformed)

    resolved = {
        "State": {"Running": False, "Status": "exited"},
        "NetworkSettings": {"Networks": {"vdy-net": {"NetworkID": network_id, "EndpointID": ""}}},
    }
    assert Docker.container_networks(resolved) == {"vdy-net": network_id}


def test_configured_network_consumers_include_stopped_and_dangling_attachments() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    network = ResourceRecord("network", "vdy-net", "e" * 64)
    attached = "a" * 64
    dangling = "b" * 64
    unrelated = "c" * 64
    runner.responses = [
        Result(("docker",), 0, f"{attached}\n{dangling}\n{unrelated}\n", ""),
        Result(
            ("docker",),
            0,
            json.dumps(
                [
                    {
                        "Id": attached,
                        "NetworkSettings": {
                            "Networks": {network.name: {"NetworkID": network.object_id}}
                        },
                    }
                ]
            ),
            "",
        ),
        Result(
            ("docker",),
            0,
            json.dumps(
                [
                    {
                        "Id": dangling,
                        "NetworkSettings": {"Networks": {network.name: {"NetworkID": ""}}},
                    }
                ]
            ),
            "",
        ),
        Result(
            ("docker",),
            0,
            json.dumps(
                [
                    {
                        "Id": unrelated,
                        "NetworkSettings": {"Networks": {"none": {"NetworkID": ""}}},
                    }
                ]
            ),
            "",
        ),
    ]

    assert docker.configured_network_consumers(network) == {attached, dangling}
    assert runner.calls[0][-5:] == (
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--quiet",
    )


@pytest.mark.parametrize(
    ("value", "parsed", "supported"),
    (
        ("27.5.1", ((27, 5, 1), ""), False),
        ("28.0.0", ((28, 0, 0), ""), True),
        ("28.0.0-rc.1", ((28, 0, 0), "-rc.1"), False),
        ("28.0.1-1~debian.12", ((28, 0, 1), "-1~debian.12"), True),
    ),
)
def test_engine_version_is_parsed_and_compared_without_lexical_ordering(
    value: str, parsed: tuple[tuple[int, int, int], str], supported: bool
) -> None:
    assert parse_engine_version(value) == parsed
    assert engine_supports_isolated_networking(value) is supported


@pytest.mark.parametrize("value", (None, 28, "28", "v28.0.0", "28.0.0.1", "28.00.0"))
def test_engine_version_parser_rejects_ambiguous_values(value: object) -> None:
    with pytest.raises(IntegrityError, match="Engine server version"):
        parse_engine_version(value)


def test_inspection_and_preflight_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(ValueError, match="unsupported"):
        docker.inspect("service", "x")
    runner.responses = [Result(("docker",), 0, "not json", "")]
    with pytest.raises(IntegrityError, match="invalid"):
        docker.inspect("container", "d" * 64)
    runner.responses = [Result(("docker",), 0, "[]", "")]
    with pytest.raises(IntegrityError, match="unexpected"):
        docker.inspect("container", "d" * 64)
    runner.responses = [Result(("docker",), 1, "", "missing")]
    assert not docker.exists("container", "d" * 64)
    docker = Docker(runner, environment={"PATH": "/missing"})
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name, path=None: None)
    with pytest.raises(Exception, match="not installed"):
        docker.preflight()


def test_preflight_rejects_an_unsupported_local_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = Docker(RecordingRunner(), connection=fake_connection())
    monkeypatch.setattr("vulndockyard.docker.platform.system", lambda: "Darwin")
    monkeypatch.setattr("vulndockyard.docker.platform.machine", lambda: "arm64")
    with pytest.raises(PreflightError, match="unsupported local Docker platform"):
        docker.preflight()


def test_connection_accepts_only_a_local_unix_socket_and_sanitizes_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name, path=None: "/bin/true")
    monkeypatch.setattr("vulndockyard.docker.stat.S_ISSOCK", lambda mode: True)
    connection = DockerConnection.discover(
        {
            "PATH": "/usr/bin",
            "DOCKER_HOST": f"unix://{socket_path}",
            "DOCKER_CONFIG": "/attacker/config",
            "HTTP_PROXY": "http://attacker.invalid",
        }
    )
    assert connection.socket == socket_path
    environment = connection.environment()
    assert environment["DOCKER_HOST"] == f"unix://{socket_path}"
    assert "DOCKER_CONFIG" not in environment
    assert "HTTP_PROXY" not in environment
    socket_path.chmod(0o666)
    with pytest.raises(PreflightError, match="world-writable"):
        DockerConnection.discover({"PATH": "/usr/bin", "DOCKER_HOST": f"unix://{socket_path}"})


@pytest.mark.parametrize(
    "environment",
    (
        {"PATH": "/usr/bin", "DOCKER_HOST": "tcp://127.0.0.1:2375"},
        {"PATH": "/usr/bin", "DOCKER_CONTEXT": "remote"},
        {"PATH": "/usr/bin", "VDY_DOCKER_SOCKET": "relative.sock"},
        {
            "PATH": "/usr/bin",
            "VDY_DOCKER_SOCKET": "/var/run/docker.sock",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
        },
    ),
)
def test_connection_rejects_remote_or_ambiguous_endpoints(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name, path=None: "/bin/true")
    with pytest.raises(PreflightError):
        DockerConnection.discover(environment)
