from __future__ import annotations

import copy
import dataclasses
import io
import json
import urllib.request
from types import TracebackType
from typing import Any, Self, cast

import pytest

import vulndockyard.cli as cli
from vulndockyard.catalogue import Catalogue, ReviewedLab, identity, template_identity
from vulndockyard.docker import (
    GATEWAY_MODE_IPV4,
    LAB,
    MANIFEST,
    OWNER,
    SEED_READY_MARKER,
    SEED_SCRIPT,
    Docker,
    Ownership,
    Timeouts,
    expected_resource_role,
)
from vulndockyard.errors import IntegrityError, PolicyError, PreflightError
from vulndockyard.models import Manifest
from vulndockyard.paths import Paths
from vulndockyard.process import Result
from vulndockyard.runtime import Runtime, _NoRedirect, _runtime_policy
from vulndockyard.state import ResourceRecord, RunState, RuntimePolicySnapshot, UpdateJournal


class FakeDocker:
    def __init__(self) -> None:
        self.timeouts = Timeouts(health=0.1)
        self.objects: dict[str, dict[str, Any]] = {}
        self.pulls: list[str] = []
        self.removed: list[str] = []
        self.image_removals: list[str] = []
        self.connections: list[tuple[str, str]] = []
        self.events: list[tuple[str, object]] = []
        self.ports: dict[int, str] = {}
        self.create_count = 0
        self.fail_gateway = False
        self.fail_seeder = False
        self.seeder_ready = True
        self.seeder_exits = False
        self.application_exits = False
        self.engine_version = "28.0.0"
        self.fail_exists_for: set[str] = set()
        self.seeder_specs: list[dict[str, object]] = []

    def _id(self) -> str:
        self.create_count += 1
        return f"{self.create_count:064x}"

    def _network_id(self, name: str) -> str:
        return next(
            object_id
            for object_id, inspection in self.objects.items()
            if inspection.get("Name") == name and "Config" not in inspection
        )

    def _attach(self, network_name: str, container_id: str) -> None:
        network_id = self._network_id(network_name)
        self.objects[network_id]["Containers"][container_id] = {"Name": container_id[:12]}

    @staticmethod
    def _label_map(value: Ownership, role: str) -> dict[str, str]:
        raw = value.labels(role)
        return {
            raw[index + 1].split("=", 1)[0]: raw[index + 1].split("=", 1)[1]
            for index in range(0, len(raw), 2)
        }

    @staticmethod
    def _labels(kind: str, inspection: dict[str, Any]) -> dict[str, str]:
        value = inspection["Config"]["Labels"] if kind == "container" else inspection["Labels"]
        return cast(dict[str, str], value)

    def preflight(self, *, require_compose: bool = False) -> dict[str, object]:
        return {
            "engine": self.engine_version,
            "engine_version": {"major": int(self.engine_version.split(".", 1)[0])},
            "minimum_engine": "28.0.0",
            "isolated_networking": int(self.engine_version.split(".", 1)[0]) >= 28,
            "compose_v2": not require_compose,
            "platform": "linux/amd64",
        }

    def pull(self, reference: str) -> None:
        self.pulls.append(reference)

    def create_network(
        self, name: str, ownership: Ownership, *, internal: bool = True
    ) -> ResourceRecord:
        object_id = self._id()
        self.objects[object_id] = {
            "Id": object_id,
            "Name": name,
            "Labels": self._label_map(ownership, "network"),
            "Driver": "bridge",
            "Scope": "local",
            "Internal": internal,
            "Attachable": False,
            "ConfigOnly": False,
            "EnableIPv6": False,
            "Ingress": False,
            "Options": {GATEWAY_MODE_IPV4: "isolated" if internal else "nat"},
            "Containers": {},
        }
        return ResourceRecord("network", name, object_id)

    @staticmethod
    def validate_network_policy(inspection: dict[str, Any], *, internal: bool) -> None:
        Docker.validate_network_policy(inspection, internal=internal)

    def create_application(self, **values: Any) -> ResourceRecord:
        object_id = self._id()
        owner: Ownership = values["ownership"]
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {
                "Labels": self._label_map(owner, "application"),
                "Image": values["image"],
                "User": f"{values['storage_uid']}:{values['storage_gid']}",
            },
            "HostConfig": {
                "PortBindings": {},
                "PublishAllPorts": False,
                "NetworkMode": values["network"],
                "ReadonlyRootfs": values["read_only"],
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
                "Memory": values["memory_mb"] * 1024 * 1024,
                "MemorySwap": values["memory_mb"] * 1024 * 1024,
                "NanoCpus": round(values["cpus"] * 1_000_000_000),
                "PidsLimit": values["pids"],
                "LogConfig": {
                    "Type": "local",
                    "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
                },
                "Tmpfs": {
                    mount.container_path: (
                        f"rw,noexec,nosuid,nodev,size={mount.size_mb}m,"
                        f"uid={values['storage_uid']},gid={values['storage_gid']},mode=0700"
                    )
                    for mount in values["empty_mounts"]
                },
                "Mounts": [
                    {
                        "Type": "volume",
                        "Source": volume.name,
                        "Target": mount.container_path,
                        "ReadOnly": False,
                        "VolumeOptions": {"NoCopy": True},
                    }
                    for volume, mount in values["seeded_mounts"]
                ],
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": volume.name,
                    "Destination": mount.container_path,
                    "RW": True,
                }
                for volume, mount in values["seeded_mounts"]
            ]
            + [
                {
                    "Type": "tmpfs",
                    "Source": "",
                    "Destination": mount.container_path,
                    "Mode": "",
                    "RW": True,
                    "Propagation": "",
                }
                for mount in values["empty_mounts"]
            ],
            "NetworkSettings": {
                "Networks": {values["network"]: {"NetworkID": "", "EndpointID": ""}}
            },
            "State": {"Running": False, "Status": "created"},
        }
        return ResourceRecord("container", values["name"], object_id)

    @staticmethod
    def validate_application_policy(inspection: dict[str, Any], **values: Any) -> None:
        Docker.validate_application_policy(inspection, **values)

    def create_ephemeral_volume(self, **values: Any) -> ResourceRecord:
        self.create_count += 1
        name = values["name"]
        mount = values["mount"]
        owner: Ownership = values["ownership"]
        options = {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": (
                f"size={mount.size_mb}m,uid={values['uid']},gid={values['gid']},mode=0700,"
                "noexec,nosuid,nodev"
            ),
        }
        self.objects[name] = {
            "Name": name,
            "Driver": "local",
            "Options": options,
            "Labels": self._label_map(owner, f"volume-{mount.name}"),
        }
        self.events.append(("create-volume", mount.name))
        return ResourceRecord("volume", name, name)

    def validate_ephemeral_volume(
        self,
        record: ResourceRecord,
        ownership: Ownership,
        mount: Any,
        *,
        uid: int,
        gid: int,
    ) -> dict[str, Any]:
        inspection = self.validate_owned(record, ownership)
        expected = {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": (f"size={mount.size_mb}m,uid={uid},gid={gid},mode=0700,noexec,nosuid,nodev"),
        }
        if inspection.get("Driver") != "local" or inspection.get("Options") != expected:
            raise PolicyError("ephemeral volume has unexpected driver options")
        return inspection

    def create_persistent_volume(self, **values: Any) -> ResourceRecord:
        self.create_count += 1
        name = values["name"]
        owner: Ownership = values["ownership"]
        self.objects[name] = {
            "Name": name,
            "Driver": "local",
            "Scope": "local",
            "Options": {},
            "Labels": self._label_map(owner, f"volume-{name.rsplit('-volume-', 1)[-1]}"),
            "TestData": {},
        }
        self.events.append(("create-persistent-volume", name))
        return ResourceRecord("volume", name, name)

    def validate_persistent_volume(
        self, record: ResourceRecord, ownership: Ownership
    ) -> dict[str, Any]:
        inspection = self.validate_owned(record, ownership)
        Docker._validate_persistent_volume_policy(inspection)
        return inspection

    def create_seeder(self, **values: Any) -> ResourceRecord:
        if self.fail_seeder:
            raise PreflightError("synthetic seeder failure")
        object_id = self._id()
        owner: Ownership = values["ownership"]
        empty_mounts = values.get("empty_mounts", ())
        persistent = values.get("persistent", False)
        payload = Docker.seeder_payload(
            values["seeded_mounts"],
            empty_mounts=empty_mounts,
            uid=values["uid"],
            gid=values["gid"],
            persistent=persistent,
        )
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {
                "Labels": self._label_map(owner, "seeder"),
                "Image": values["image"],
                "User": "0:0" if persistent else f"{values['uid']}:{values['gid']}",
                "Entrypoint": ["/nodejs/bin/node"],
                "Cmd": ["-e", SEED_SCRIPT, payload],
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
                "CapAdd": ["CHOWN"] if persistent else None,
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
                    "Config": {
                        "compress": "true",
                        "max-file": "2",
                        "max-size": "10m",
                    },
                },
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": volume.name,
                    "Destination": f"/vdy-seed/{mount.name}",
                    "RW": True,
                }
                for volume, mount in (*values["seeded_mounts"], *empty_mounts)
            ],
            "NetworkSettings": {"Networks": {"none": {"NetworkID": "", "EndpointID": ""}}},
            "State": {"Running": False, "Status": "created"},
        }
        self.events.append(("create-seeder", values["image"]))
        self.seeder_specs.append(
            {
                "persistent": persistent,
                "user": "0:0" if persistent else f"{values['uid']}:{values['gid']}",
                "cap_add": ("CHOWN",) if persistent else (),
                "mounts": tuple(
                    mount.name for _, mount in (*values["seeded_mounts"], *empty_mounts)
                ),
            }
        )
        return ResourceRecord("container", values["name"], object_id)

    @staticmethod
    def validate_seeder_policy(inspection: dict[str, Any], **values: Any) -> None:
        Docker.validate_seeder_policy(inspection, **values)

    def create_gateway(self, **values: Any) -> ResourceRecord:
        if self.fail_gateway:
            raise PreflightError("synthetic gateway failure")
        port = values["host_port"]
        if port in self.ports:
            raise PreflightError(f"synthetic port reservation conflict: {port}")
        object_id = self._id()
        owner: Ownership = values["ownership"]
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {
                "Labels": self._label_map(owner, "gateway"),
                "Image": values["image"],
                "User": "1000:1000",
                "Cmd": [
                    "caddy",
                    "reverse-proxy",
                    "--from",
                    ":8080",
                    "--to",
                    f"app:{values['upstream_port']}",
                ],
            },
            "HostConfig": {
                "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]},
                "NetworkMode": values["network"],
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
            "NetworkSettings": {
                "Networks": {values["network"]: {"NetworkID": "", "EndpointID": ""}}
            },
            "State": {"Running": False, "Status": "created"},
        }
        self.ports[port] = object_id
        self.events.append(("create-gateway", port))
        return ResourceRecord("container", values["name"], object_id)

    @staticmethod
    def validate_gateway_policy(
        inspection: dict[str, Any],
        *,
        image: str,
        network: str,
        upstream_port: int,
        host_port: int,
    ) -> None:
        Docker.validate_gateway_policy(
            inspection,
            image=image,
            network=network,
            upstream_port=upstream_port,
            host_port=host_port,
        )

    def connect_network(self, network: ResourceRecord, container: ResourceRecord) -> None:
        assert network.object_id in self.objects and container.object_id in self.objects
        networks = self.objects[container.object_id]["NetworkSettings"]["Networks"]
        if network.name not in networks:
            networks[network.name] = {"NetworkID": "", "EndpointID": ""}
            if self.objects[container.object_id]["State"]["Running"]:
                networks[network.name] = {
                    "NetworkID": network.object_id,
                    "EndpointID": container.object_id,
                }
                self._attach(network.name, container.object_id)
            self.connections.append((network.object_id, container.object_id))

    def network_connected(self, network: ResourceRecord, container: ResourceRecord) -> bool:
        return Docker.network_connected(self, network, container)  # type: ignore[arg-type]

    @staticmethod
    def container_networks(inspection: dict[str, Any]) -> dict[str, str]:
        return Docker.container_networks(inspection)

    @staticmethod
    def validate_network_endpoints(
        inspection: dict[str, Any], *, expected_container_ids: set[str]
    ) -> None:
        Docker.validate_network_endpoints(inspection, expected_container_ids=expected_container_ids)

    def configured_network_consumers(
        self, network: ResourceRecord, *, deadline: float | None = None
    ) -> set[str]:
        del deadline
        consumers: set[str] = set()
        for object_id, inspection in self.objects.items():
            if "Config" not in inspection:
                continue
            settings = inspection.get("NetworkSettings")
            networks = settings.get("Networks") if isinstance(settings, dict) else None
            if not isinstance(networks, dict):
                raise IntegrityError("Docker container network inspection is malformed")
            for name, attachment in networks.items():
                if not isinstance(attachment, dict):
                    raise IntegrityError("Docker container network attachment is malformed")
                attached_id = attachment.get("NetworkID")
                if attached_id == network.object_id or (attached_id == "" and name == network.name):
                    consumers.add(object_id)
        return consumers

    def configured_volume_consumers(
        self, volume: ResourceRecord, *, deadline: float | None = None
    ) -> set[str]:
        del deadline
        consumers: set[str] = set()
        for object_id, inspection in self.objects.items():
            if "Config" not in inspection:
                continue
            mounts = inspection.get("Mounts")
            host = inspection.get("HostConfig")
            if not isinstance(mounts, list) or not isinstance(host, dict):
                raise IntegrityError("Docker container volume inspection is malformed")
            configured = host.get("Mounts")
            configured_mounts = [] if configured is None else configured
            if not isinstance(configured_mounts, list):
                raise IntegrityError("Docker container volume inspection is malformed")
            if any(
                isinstance(mount, dict)
                and mount.get("Type") == "volume"
                and mount.get("Name") == volume.name
                for mount in mounts
            ) or any(
                isinstance(mount, dict)
                and mount.get("Type") == "volume"
                and mount.get("Source") == volume.name
                for mount in configured_mounts
            ):
                consumers.add(object_id)
        return consumers

    def inspect(self, kind: str, object_id: str, *, timeout: float | None = None) -> dict[str, Any]:
        del timeout
        return self.objects[object_id]

    def exists(self, kind: str, object_id: str, *, timeout: float | None = None) -> bool:
        del timeout
        if object_id in self.fail_exists_for:
            raise PreflightError("injected Docker existence inventory failure")
        return object_id in self.objects

    def validate_owned(
        self,
        record: ResourceRecord,
        ownership: Ownership,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        del timeout
        inspection = self.objects[record.object_id]
        labels = self._labels(record.kind, inspection)
        expected = self._label_map(ownership, expected_resource_role(record, ownership))
        if inspection["Name"].removeprefix("/") != record.name:
            raise PolicyError("resource name mismatch")
        if any(labels.get(key) != value for key, value in expected.items()):
            raise PolicyError("ownership labels mismatch")
        return inspection

    def read_logs(self, record: ResourceRecord, *, timeout: float, tail: int = 20) -> Result:
        self.events.append(("seed-log", record.name))
        output = f"{SEED_READY_MARKER}\n" if self.seeder_ready else "seeding\n"
        return Result(("docker", "logs"), 0, output, "")

    def start(self, record: ResourceRecord) -> None:
        role = self._labels("container", self.objects[record.object_id]).get(
            "org.vulndockyard.role"
        )
        exits = (role == "seeder" and self.seeder_exits) or (
            role == "application" and self.application_exits
        )
        running = not exits
        self.objects[record.object_id]["State"] = {
            "Running": running,
            "Status": "running" if running else "exited",
        }
        none_attachment = self.objects[record.object_id]["NetworkSettings"]["Networks"].get("none")
        if isinstance(none_attachment, dict):
            none_attachment["NetworkID"] = "0" * 64
            none_attachment["EndpointID"] = record.object_id if running else ""
        if running:
            for network_name, attachment in self.objects[record.object_id]["NetworkSettings"][
                "Networks"
            ].items():
                if network_name != "none":
                    attachment["NetworkID"] = self._network_id(network_name)
                    attachment["EndpointID"] = record.object_id
                    self._attach(network_name, record.object_id)
        self.events.append(("start", record.name))

    def stop(self, record: ResourceRecord) -> None:
        self.objects[record.object_id]["State"] = {"Running": False, "Status": "exited"}
        none_attachment = self.objects[record.object_id]["NetworkSettings"]["Networks"].get("none")
        if isinstance(none_attachment, dict):
            none_attachment["EndpointID"] = ""
        for attachment in self.objects[record.object_id]["NetworkSettings"]["Networks"].values():
            if isinstance(attachment, dict):
                attachment["EndpointID"] = ""
        for inspection in self.objects.values():
            endpoints = inspection.get("Containers")
            if isinstance(endpoints, dict):
                endpoints.pop(record.object_id, None)
        self.events.append(("stop", record.name))

    def remove(self, record: ResourceRecord, *, timeout: float | None = None) -> None:
        del timeout
        self.removed.append(record.object_id)
        inspection = self.objects[record.object_id]
        self.events.append(("remove", record.name))
        if record.kind == "container":
            binding = inspection.get("HostConfig", {}).get("PortBindings", {}).get("8080/tcp")
            if binding:
                port = int(binding[0]["HostPort"])
                self.ports.pop(port, None)
                self.events.append(("remove-gateway", port))
            for network in self.objects.values():
                endpoints = network.get("Containers")
                if isinstance(endpoints, dict):
                    endpoints.pop(record.object_id, None)
        del self.objects[record.object_id]

    def remove_image(self, reference: str) -> None:
        self.image_removals.append(reference)

    def logs(self, record: ResourceRecord, *, follow: bool, tail: int = 100) -> Result:
        return Result(("docker", "logs"), 0, "application log\n", "")

    def managed_resources(self, *, lab_id: str | None = None) -> dict[str, tuple[str, ...]]:
        result: dict[str, list[str]] = {"container": [], "network": [], "volume": []}
        for object_id, inspection in self.objects.items():
            if "Config" in inspection:
                kind = "container"
            elif inspection.get("Driver") == "local":
                kind = "volume"
            else:
                kind = "network"
            labels = self._labels(kind, inspection)
            if labels.get(OWNER) == "true" and (lab_id is None or labels.get(LAB) == lab_id):
                result[kind].append(object_id)
        return {kind: tuple(object_ids) for kind, object_ids in result.items()}


class ReadyRuntime(Runtime):
    def __init__(self, *, paths: Paths, docker: FakeDocker) -> None:
        super().__init__(
            catalogue=Catalogue(),
            paths=paths,
            docker=docker,  # type: ignore[arg-type]
            temporary_port_selector=lambda excluded: 28080,
            port_checker=lambda port: True,
        )
        self.health_calls = 0
        self.fail_health = False
        self.fail_health_call: int | None = None
        self.snapshot_health: list[RuntimePolicySnapshot] = []

    def _health(self, lab: ReviewedLab, port: int) -> None:
        del lab
        self._record_health(port)

    def _health_snapshot(self, policy: RuntimePolicySnapshot, port: int) -> None:
        self.snapshot_health.append(policy)
        self._record_health(port)

    def _record_health(self, port: int) -> None:
        self.health_calls += 1
        self.docker.events.append(("health", port))  # type: ignore[attr-defined]
        if self.fail_health or self.health_calls == self.fail_health_call:
            raise PreflightError("synthetic candidate identity failure")


def runtime(paths: Paths) -> tuple[ReadyRuntime, FakeDocker, ReviewedLab]:
    docker = FakeDocker()
    value = ReadyRuntime(paths=paths, docker=docker)
    return value, docker, Catalogue().get("juice-shop")


def persistent_review(lab: ReviewedLab) -> ReviewedLab:
    raw = copy.deepcopy(lab.manifest.raw)
    raw["persistence"]["required"] = True
    manifest = Manifest.parse(raw)
    lock = dataclasses.replace(lab.lock, template_sha256=template_identity(manifest))
    return ReviewedLab(manifest, lock, identity(raw))


def preserve_as_previous(value: ReadyRuntime, docker: FakeDocker, lab: ReviewedLab) -> RunState:
    state = value.store.load(lab.manifest.id)
    assert state is not None
    previous = dataclasses.replace(state, manifest_identity="e" * 64)
    for record in previous.resources:
        labels = docker._labels(record.kind, docker.objects[record.object_id])
        labels[MANIFEST] = previous.manifest_identity
    value.store.save(previous)
    return previous


def test_reference_lifecycle_is_idempotent_and_distinct(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    started = value.up(lab, host_port=18080)
    assert started.state == "running"
    assert started.lock_match
    assert started.url == "http://juice-shop.test:18080"
    assert len(started.resources) == 8
    assert len(docker.pulls) == 2
    state = value.store.load(lab.manifest.id)
    assert state is not None
    internal = next(record for record in state.resources if record.name.endswith("-net"))
    ingress = next(record for record in state.resources if record.name.endswith("-ingress"))
    assert docker.objects[internal.object_id]["Internal"] is True
    assert docker.objects[ingress.object_id]["Internal"] is False
    first_run = started.run_id
    first_count = docker.create_count

    repeated = value.up(lab, host_port=18080)
    assert repeated.run_id == first_run
    assert docker.create_count == first_count
    assert len(docker.pulls) == 2

    assert value.stop(lab).state == "stopped"
    assert value.stop(lab).state == "stopped"
    assert value.restart(lab).state == "running"
    rebuilt = value.rebuild(lab)
    assert rebuilt.run_id != first_run
    assert rebuilt.requested_reference == started.requested_reference
    reset = value.reset(lab)
    assert reset.run_id != rebuilt.run_id
    assert value.logs(lab, follow=False) == "application log\n"
    assert value.remove(lab).state == "absent"
    assert value.remove(lab).state == "absent"
    assert docker.objects == {}


def test_new_run_refuses_busy_loopback_port_before_docker_mutation(xdg_paths: Paths) -> None:
    docker = FakeDocker()
    value = ReadyRuntime(paths=xdg_paths, docker=docker)
    value.port_checker = lambda port: False
    lab = Catalogue().get("juice-shop")

    with pytest.raises(PreflightError, match=r"port 18080.*--port"):
        value.up(lab, host_port=18080)

    assert docker.pulls == []
    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None


def test_stopped_gateway_refuses_busy_port_before_restart(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.stop(lab)
    starts_before = tuple(event for event in docker.events if event[0] == "start")
    value.port_checker = lambda port: False

    with pytest.raises(PreflightError, match=r"port 18080.*--port"):
        value.up(lab, host_port=18080)

    assert tuple(event for event in docker.events if event[0] == "start") == starts_before
    state = value.store.load(lab.manifest.id)
    assert state is not None
    assert all(
        not docker.objects[record.object_id]["State"]["Running"]
        for record in state.resources
        if record.kind == "container"
    )


def test_persistent_rebuild_preserves_owned_data_and_reset_replaces_it(
    xdg_paths: Paths,
) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    started = value.up(lab, host_port=18080)
    initial = value.store.load(lab.manifest.id)
    assert initial is not None and initial.phase == "steady"
    application = next(record for record in initial.resources if record.name.endswith("-app"))
    assert docker.objects[application.object_id]["Config"]["User"] == "65532:65532"
    assert docker.seeder_specs[-1] == {
        "persistent": True,
        "user": "0:0",
        "cap_add": ("CHOWN",),
        "mounts": tuple(
            mount.name
            for mount in lab.manifest.ephemeral_storage.seeded
            + lab.manifest.ephemeral_storage.empty
        ),
    }
    initial_volumes = tuple(record for record in initial.resources if record.kind == "volume")
    assert len(initial_volumes) == len(
        lab.manifest.ephemeral_storage.seeded + lab.manifest.ephemeral_storage.empty
    )
    for record in initial_volumes:
        docker.objects[record.object_id]["TestData"]["marker"] = record.name
    initial_transients = {
        record.object_id for record in initial.resources if record.kind != "volume"
    }
    initial_containers = tuple(record for record in initial.resources if record.kind == "container")
    seeder_creations = sum(event[0] == "create-seeder" for event in docker.events)
    rebuild_events_start = len(docker.events)

    rebuilt = value.rebuild(lab)
    after_rebuild = value.store.load(lab.manifest.id)
    assert after_rebuild is not None and after_rebuild.phase == "steady"
    assert rebuilt.run_id == started.run_id == after_rebuild.run_id
    assert tuple(
        record.object_id for record in after_rebuild.resources if record.kind == "volume"
    ) == tuple(record.object_id for record in initial_volumes)
    assert all(
        docker.objects[record.object_id]["TestData"]["marker"] == record.name
        for record in initial_volumes
    )
    assert initial_transients.isdisjoint(docker.objects)
    assert sum(event[0] == "create-seeder" for event in docker.events) == seeder_creations
    rebuild_events = docker.events[rebuild_events_start:]
    for record in initial_containers:
        assert rebuild_events.index(("stop", record.name)) < rebuild_events.index(
            ("remove", record.name)
        )

    reset = value.reset(lab)
    after_reset = value.store.load(lab.manifest.id)
    assert after_reset is not None and after_reset.phase == "steady"
    assert reset.run_id != rebuilt.run_id
    assert all(record.object_id not in docker.objects for record in initial_volumes)
    assert all(
        docker.objects[record.object_id]["TestData"] == {}
        for record in after_reset.resources
        if record.kind == "volume"
    )
    assert value.remove(lab).state == "absent"
    assert docker.objects == {}


def test_persistent_rebuild_rejects_foreign_volume_consumer_before_mutation(
    xdg_paths: Paths,
) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    volume = next(record for record in state.resources if record.kind == "volume")
    foreign_id = "f" * 64
    docker.objects[foreign_id] = {
        "Id": foreign_id,
        "Name": "/foreign-stopped-container",
        "Config": {"Labels": {}, "Image": "unrelated.invalid/image@example"},
        "HostConfig": {
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": volume.name,
                    "Target": "/data",
                    "ReadOnly": False,
                    "VolumeOptions": {"NoCopy": False},
                }
            ]
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": volume.name,
                "Destination": "/data",
                "RW": True,
            }
        ],
        "NetworkSettings": {"Networks": {}},
        "State": {"Running": False, "Status": "exited"},
    }
    removed_before = tuple(docker.removed)

    with pytest.raises(PolicyError, match="unowned container"):
        value.rebuild(lab)

    assert tuple(docker.removed) == removed_before
    assert value.store.load(lab.manifest.id) == state
    assert foreign_id in docker.objects
    del docker.objects[foreign_id]
    assert value.remove(lab).state == "absent"


def test_failed_persistent_rebuild_retains_data_and_resumes_explicitly(
    xdg_paths: Paths,
) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    value.up(lab, host_port=18080)
    initial = value.store.load(lab.manifest.id)
    assert initial is not None
    volumes = tuple(record for record in initial.resources if record.kind == "volume")
    for record in volumes:
        docker.objects[record.object_id]["TestData"]["marker"] = "preserve"
    value.fail_health_call = value.health_calls + 1

    with pytest.raises(PreflightError, match="synthetic candidate identity failure"):
        value.rebuild(lab)

    interrupted = value.store.load(lab.manifest.id)
    assert interrupted is not None and interrupted.phase == "rebuild"
    assert all(
        docker.objects[record.object_id]["TestData"]["marker"] == "preserve" for record in volumes
    )
    assert all(
        not docker.objects[record.object_id]["State"]["Running"]
        for record in interrupted.resources
        if record.kind == "container"
    )
    with pytest.raises(PolicyError, match="interrupted persistent rebuild"):
        value.status(lab)

    value.fail_health_call = None
    resumed = value.up(lab, host_port=18080)
    recovered = value.store.load(lab.manifest.id)
    assert recovered is not None and recovered.phase == "steady"
    assert resumed.run_id == initial.run_id
    assert all(
        docker.objects[record.object_id]["TestData"]["marker"] == "preserve" for record in volumes
    )
    assert value.remove(lab).state == "absent"


@pytest.mark.parametrize("damage", ["missing", "relabeled"])
def test_persistent_rebuild_refuses_missing_or_relabelled_data_before_cleanup(
    xdg_paths: Paths, damage: str
) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    volume = next(record for record in state.resources if record.kind == "volume")
    if damage == "missing":
        del docker.objects[volume.object_id]
    else:
        docker.objects[volume.object_id]["Labels"][LAB] = "other-lab"
    removed_before = tuple(docker.removed)

    with pytest.raises(PolicyError):
        value.rebuild(lab)

    assert tuple(docker.removed) == removed_before
    assert value.store.load(lab.manifest.id) == state


def test_persistent_rebuild_adopts_exact_create_checkpoint_orphan(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    value.up(lab, host_port=18080)
    initial = value.store.load(lab.manifest.id)
    assert initial is not None
    volumes = tuple(record for record in initial.resources if record.kind == "volume")
    create_network = docker.create_network
    interrupted = False

    def create_then_interrupt(*args: Any, **kwargs: Any) -> ResourceRecord:
        nonlocal interrupted
        record = create_network(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return record

    monkeypatch.setattr(docker, "create_network", create_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        value.rebuild(lab)
    pending = value.store.load(lab.manifest.id)
    assert pending is not None and pending.phase == "rebuild"
    orphan = next(
        object_id
        for object_id, inspection in docker.objects.items()
        if "Config" not in inspection and inspection.get("Driver") == "bridge"
    )
    assert all(record.object_id != orphan for record in pending.resources)

    monkeypatch.setattr(docker, "create_network", create_network)
    recovered = value.up(lab, host_port=18080)
    assert recovered.run_id == initial.run_id
    assert orphan in docker.removed
    assert all(record.object_id in docker.objects for record in volumes)
    assert value.remove(lab).state == "absent"


def test_persistent_update_refuses_before_pull_or_runtime_mutation(xdg_paths: Paths) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    pulls_before = tuple(docker.pulls)
    objects_before = set(docker.objects)

    with pytest.raises(PolicyError, match="data migration policy"):
        value.activate_reviewed_update(packaged)

    assert tuple(docker.pulls) == pulls_before
    assert set(docker.objects) == objects_before
    assert value.store.load(lab.manifest.id) == previous
    assert value.store.load_update(lab.manifest.id) is None
    assert value.remove(lab).state == "absent"


def test_reference_runtime_has_exact_bounded_storage_and_no_final_seeder(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    status = value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None

    roles = {resource["role"] for resource in status.resources}
    assert "seeder" not in roles
    assert {role for role in roles if role.startswith("volume-")} == {
        "volume-data",
        "volume-ftp",
        "volume-frontend",
        "volume-csaf",
    }
    application = next(record for record in state.resources if record.name.endswith("-app"))
    inspection = docker.objects[application.object_id]
    assert inspection["HostConfig"]["ReadonlyRootfs"] is True
    assert inspection["HostConfig"]["Tmpfs"] == {
        mount.container_path: (
            f"rw,noexec,nosuid,nodev,size={mount.size_mb}m,uid=65532,gid=65532,mode=0700"
        )
        for mount in lab.manifest.ephemeral_storage.empty
    }
    assert {
        (mount["Name"], mount["Destination"])
        for mount in inspection["Mounts"]
        if mount["Type"] == "volume"
    } == {
        (
            f"vdy-juice-shop-{state.run_id[:12]}-volume-{mount.name}",
            mount.container_path,
        )
        for mount in lab.manifest.ephemeral_storage.seeded
    }
    assert all(
        inspection["Config"]["Image"] != ""
        for inspection in docker.objects.values()
        if "Config" in inspection
    )


def test_stop_then_up_reseeds_tmpfs_without_recreating_volumes(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    started = value.up(lab, host_port=18080)
    first_seeders = [event for event in docker.events if event[0] == "create-seeder"]
    first_volumes = [event for event in docker.events if event[0] == "create-volume"]

    repeated = value.up(lab, host_port=18080)
    assert repeated.run_id == started.run_id
    assert [event for event in docker.events if event[0] == "create-seeder"] == first_seeders

    assert value.stop(lab).state == "stopped"
    resumed = value.up(lab, host_port=18080)
    assert resumed.run_id == started.run_id
    assert len([event for event in docker.events if event[0] == "create-seeder"]) == 2
    assert [event for event in docker.events if event[0] == "create-volume"] == first_volumes
    assert not any(resource["role"] == "seeder" for resource in resumed.resources)


def test_unsafe_development_uses_same_seeding_path_with_untrusted_labels(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    image = "dev.example/app@sha256:" + "f" * 64
    result = value.up(
        lab,
        host_port=18080,
        unsafe_image=image,
        unsafe_development=True,
    )
    assert result.trusted_run is False
    assert ("create-seeder", image) in docker.events
    for inspection in docker.objects.values():
        labels = inspection["Config"]["Labels"] if "Config" in inspection else inspection["Labels"]
        assert labels["org.vulndockyard.trusted"] == "false"


def test_seeder_creation_failure_cleans_checkpointed_volumes_and_networks(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.fail_seeder = True

    with pytest.raises(PreflightError, match="seeder failure"):
        value.up(lab, host_port=18080)

    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None
    assert len(docker.removed) == 6


def test_seeder_without_exact_ready_marker_fails_and_cleans_exact_resources(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.seeder_ready = False
    docker.seeder_exits = True

    with pytest.raises(PreflightError, match="exited before its exact readiness marker"):
        value.up(lab, host_port=18080)

    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None
    assert len(docker.removed) == 7


def test_seeder_must_remain_running_after_its_ready_marker(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.seeder_exits = True

    with pytest.raises(PreflightError, match="exited after reporting readiness"):
        value.up(lab, host_port=18080)

    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None


def test_application_must_remain_running_before_the_seeder_is_removed(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.application_exits = True

    with pytest.raises(PreflightError, match="did not remain running"):
        value.up(lab, host_port=18080)

    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None


@pytest.mark.parametrize("existing_runtime", [False, True])
def test_seeder_must_remain_running_until_application_start_completes(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    existing_runtime: bool,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    if existing_runtime:
        value.up(lab, host_port=18080)
        value.stop(lab)
    start = docker.start

    def start_and_expire_seeder(record: ResourceRecord) -> None:
        start(record)
        inspection = docker.objects[record.object_id]
        role = docker._labels("container", inspection).get("org.vulndockyard.role")
        if role == "application":
            for candidate in docker.objects.values():
                if (
                    "Config" in candidate
                    and docker._labels("container", candidate).get("org.vulndockyard.role")
                    == "seeder"
                ):
                    candidate["State"]["Running"] = False

    monkeypatch.setattr(docker, "start", start_and_expire_seeder)

    with pytest.raises(PreflightError, match="stopped while application started"):
        value.up(lab, host_port=18080)

    assert not any(
        "Config" in inspection
        and docker._labels("container", inspection).get("org.vulndockyard.role") == "seeder"
        for inspection in docker.objects.values()
    )
    if existing_runtime:
        state = value.store.load(lab.manifest.id)
        assert state is not None
        assert all(
            not inspection["State"]["Running"]
            for inspection in docker.objects.values()
            if "Config" in inspection
        )
    else:
        assert docker.objects == {}
        assert value.store.load(lab.manifest.id) is None


def test_old_engine_blocks_lab_execution_but_not_owned_cleanup(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    docker.engine_version = "27.5.1"

    pulls_before = tuple(docker.pulls)
    objects_before = set(docker.objects)
    for operation in (
        lambda: value.pull(lab),
        lambda: value.up(lab, host_port=18080),
        lambda: value.activate_reviewed_update(lab),
        lambda: value.restart(lab),
        lambda: value.rebuild(lab),
        lambda: value.reset(lab),
        lambda: value.verify(lab),
    ):
        with pytest.raises(PreflightError, match=r"28\.0\.0 or newer"):
            operation()
        assert tuple(docker.pulls) == pulls_before
        assert set(docker.objects) == objects_before

    # Stopping and exact-ID cleanup remain available as recovery operations.
    assert value.stop(lab).state == "stopped"
    assert value.residual_audit()["container"]
    assert value.remove(lab).state == "absent"
    assert value.purge(lab).state == "absent"
    assert value.residual_audit() == {"container": (), "network": (), "volume": ()}


def test_old_engine_stop_aborts_an_interrupted_update_without_execution(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    old_gateway = next(record for record in previous.resources if record.name.endswith("-gateway"))
    docker.remove(old_gateway)
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "cutover",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )
    policy = previous.runtime_policy
    assert policy is not None
    rollback_seeder = docker.create_seeder(
        name=f"vdy-{previous.lab_id}-{previous.run_id[:12]}-seeder",
        image=previous.requested_reference,
        ownership=Ownership.from_state(previous),
        seeded_mounts=value._seeded_mounts_from_snapshot(previous, policy),
        uid=policy.ephemeral_storage.uid,
        gid=policy.ephemeral_storage.gid,
    )
    docker.start(rollback_seeder)
    observation_events = tuple(docker.events)
    for observe in (
        lambda: value.status(lab),
        lambda: value.logs(lab, follow=False),
        lambda: value.verify(lab),
    ):
        with pytest.raises(PolicyError, match="interrupted update is pending"):
            observe()
    assert tuple(docker.events) == observation_events

    docker.engine_version = "26.1.5"
    create_count = docker.create_count
    event_count = len(docker.events)

    status = value.stop(lab)

    assert status.state == "degraded"
    assert docker.create_count == create_count
    assert not any(event[0] == "start" for event in docker.events[event_count:])
    assert rollback_seeder.object_id in docker.removed
    assert value.store.load_update(lab.manifest.id) is None
    assert not any(
        labels.get(MANIFEST) == lab.manifest_identity
        for inspection in docker.objects.values()
        for labels in [
            inspection["Config"]["Labels"] if "Config" in inspection else inspection["Labels"]
        ]
    )


def test_interrupted_startup_cleans_only_created_resources(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.fail_gateway = True
    with pytest.raises(PreflightError, match="synthetic"):
        value.up(lab, host_port=18080)
    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None
    assert len(docker.removed) == 8


def test_late_steady_state_topology_failure_cleans_the_new_runtime(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)

    def corrupt_after_identity(selected: ReviewedLab, port: int) -> None:
        del selected, port
        application_id = next(
            object_id
            for object_id, inspection in docker.objects.items()
            if "Config" in inspection
            and docker._labels("container", inspection).get("org.vulndockyard.role")
            == "application"
        )
        docker.objects[application_id]["NetworkSettings"]["Networks"]["foreign"] = {
            "NetworkID": "f" * 64
        }

    monkeypatch.setattr(value, "_health", corrupt_after_identity)

    with pytest.raises(PolicyError, match="unreviewed network attachment"):
        value.up(lab, host_port=18080)

    assert value.store.load(lab.manifest.id) is None
    assert docker.objects == {}


def test_startup_recovers_an_object_created_before_the_next_checkpoint(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    create_network = docker.create_network
    interrupted = False

    def create_then_interrupt(
        name: str, ownership: Ownership, *, internal: bool = True
    ) -> ResourceRecord:
        nonlocal interrupted
        record = create_network(name, ownership, internal=internal)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return record

    monkeypatch.setattr(docker, "create_network", create_then_interrupt)

    with pytest.raises(KeyboardInterrupt):
        value.up(lab, host_port=18080)

    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None
    assert len(docker.removed) == 1


def test_cleanup_adopts_a_seeder_interrupted_before_its_runtime_checkpoint(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.stop(lab)
    create_seeder = docker.create_seeder
    interrupted = False

    def create_then_interrupt(**values: Any) -> ResourceRecord:
        nonlocal interrupted
        record = create_seeder(**values)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return record

    monkeypatch.setattr(docker, "create_seeder", create_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        value.up(lab, host_port=18080)
    seeder = next(
        ResourceRecord("container", inspection["Name"], object_id)
        for object_id, inspection in docker.objects.items()
        if "Config" in inspection
        and docker._labels("container", inspection).get("org.vulndockyard.role") == "seeder"
    )
    with pytest.raises(PolicyError, match="without usable runtime state"):
        value.status(lab)

    monkeypatch.setattr(docker, "create_seeder", create_seeder)
    assert value.stop(lab).state == "stopped"
    assert seeder.object_id in docker.removed
    assert value.remove(lab).state == "absent"
    assert docker.objects == {}


def test_reviewed_update_current_and_no_runtime_are_non_mutating(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    absent = value.activate_reviewed_update(lab)
    assert absent.outcome == "no-runtime"
    assert docker.pulls == []

    started = value.up(lab, host_port=18080)
    created = docker.create_count
    current = value.activate_reviewed_update(lab)
    assert current.outcome == "already-current"
    assert current.active_run_id == started.run_id
    assert docker.create_count == created


def test_cli_activates_only_installed_reviewed_candidate_after_readiness(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    previous_ids = {record.object_id for record in previous.resources}
    monkeypatch.setattr(cli, "Runtime", lambda catalogue=None: value)
    monkeypatch.setattr(
        cli,
        "check_latest",
        lambda selected: (_ for _ in ()).throw(AssertionError("discovery must not activate")),
    )

    assert cli.main(["--json", "update", "juice-shop"]) == 0
    result = json.loads(capsys.readouterr().out)["data"]["results"][0]
    assert result["outcome"] == "activated"
    assert result["previous_run_id"] == previous.run_id
    assert result["candidate_manifest_identity"] == lab.manifest_identity
    active = value.store.load(lab.manifest.id)
    assert active is not None and active.manifest_identity == lab.manifest_identity
    assert active.run_id != previous.run_id
    assert previous_ids.isdisjoint(docker.objects)
    assert len(docker.objects) == 8


def test_update_smokes_on_temporary_port_before_exact_gateway_cutover(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    preserve_as_previous(value, docker, lab)
    docker.events.clear()

    value.activate_reviewed_update(lab)

    assert docker.events.index(("create-gateway", 28080)) < docker.events.index(("health", 28080))
    assert docker.events.index(("health", 28080)) < docker.events.index(("remove-gateway", 28080))
    first_old_removal = docker.events.index(("remove-gateway", 18080))
    final_creation = docker.events.index(("create-gateway", 18080))
    assert docker.events.index(("remove-gateway", 28080)) < first_old_removal
    assert first_old_removal < final_creation
    assert final_creation < docker.events.index(("health", 18080))
    assert docker.ports == {18080: next(iter(docker.ports.values()))}
    assert value.store.load_update(lab.manifest.id) is None


def test_final_port_failure_recreates_prior_gateway_and_running_state(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    old_gateway = next(record for record in previous.resources if record.name.endswith("-gateway"))
    unchanged_ids = {record.object_id for record in previous.resources if record != old_gateway}
    value.fail_health_call = value.health_calls + 2
    docker.events.clear()

    with pytest.raises(PreflightError, match="candidate identity failure"):
        value.activate_reviewed_update(lab)

    restored = value.store.load(lab.manifest.id)
    assert restored is not None
    assert restored.run_id == previous.run_id
    assert restored.manifest_identity == previous.manifest_identity
    restored_gateway = next(
        record for record in restored.resources if record.name.endswith("-gateway")
    )
    assert restored_gateway.object_id != old_gateway.object_id
    assert unchanged_ids.issubset(docker.objects)
    assert docker.events.index(("create-gateway", 28080)) < docker.events.index(
        ("remove-gateway", 18080)
    )
    final_candidate = docker.events.index(("create-gateway", 18080))
    final_failure = docker.events.index(("health", 18080))
    restored_creation = docker.events.index(("create-gateway", 18080), final_candidate + 1)
    assert final_candidate < final_failure < restored_creation
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in restored.resources
        if record.kind == "container"
    )
    assert docker.ports == {18080: restored_gateway.object_id}
    assert value.store.load_update(lab.manifest.id) is None


def test_execution_recovery_rolls_back_an_interrupted_cutover(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    candidate_inspections = value._validate_state(candidate)
    temporary_gateway = next(
        record
        for record, inspection in zip(candidate.resources, candidate_inspections, strict=True)
        if record.kind == "container"
        and docker._labels(record.kind, inspection).get("org.vulndockyard.role") == "gateway"
    )
    docker.remove(temporary_gateway)
    candidate = dataclasses.replace(
        candidate,
        host_port=previous.host_port,
        resources=tuple(record for record in candidate.resources if record != temporary_gateway),
    )
    old_gateway = next(record for record in previous.resources if record.name.endswith("-gateway"))
    docker.remove(old_gateway)
    ingress = next(record for record in candidate.resources if record.name.endswith("-ingress"))
    internal = next(record for record in candidate.resources if record.name.endswith("-net"))
    unjournaled_gateway = docker.create_gateway(
        name=temporary_gateway.name,
        image=lab.manifest.images[1].reference,
        network=ingress.name,
        upstream_port=lab.manifest.services[0].internal_port,
        host_port=previous.host_port,
        ownership=Ownership.from_state(candidate),
    )
    docker.connect_network(internal, unjournaled_gateway)
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "cutover",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )

    value._recover_update(lab)
    status = value._status(lab)

    assert status.run_id == previous.run_id
    assert status.state == "running"
    assert value.store.load_update(lab.manifest.id) is None
    assert unjournaled_gateway.object_id not in docker.objects
    assert docker.ports.keys() == {18080}


def test_execution_recovery_adopts_an_exact_unjournaled_rollback_gateway(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    old_gateway = next(record for record in previous.resources if record.name.endswith("-gateway"))
    ingress = next(record for record in previous.resources if record.name.endswith("-ingress"))
    internal = next(record for record in previous.resources if record.name.endswith("-net"))
    docker.remove(old_gateway)
    replacement = docker.create_gateway(
        name=old_gateway.name,
        image=previous.gateway_reference,
        network=ingress.name,
        upstream_port=previous.upstream_port,
        host_port=previous.host_port,
        ownership=Ownership.from_state(previous),
    )
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "cutover",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )

    value._recover_update(lab)
    status = value._status(lab)

    restored = value.store.load(lab.manifest.id)
    assert restored is not None
    assert status.run_id == previous.run_id
    assert replacement in restored.resources
    assert replacement.object_id in docker.objects
    assert docker.ports == {18080: replacement.object_id}
    assert (internal.object_id, replacement.object_id) in docker.connections
    assert value.store.load_update(lab.manifest.id) is None


def test_ready_journal_completes_cleanup_after_interruption(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    original_cleanup = value._cleanup

    def interrupt_old_cleanup(state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        if state.run_id == previous.run_id:
            raise PreflightError("synthetic cleanup interruption")
        original_cleanup(state, coexisting=coexisting)

    monkeypatch.setattr(value, "_cleanup", interrupt_old_cleanup)
    with pytest.raises(PreflightError, match="cleanup interruption"):
        value.activate_reviewed_update(lab)
    journal = value.store.load_update(lab.manifest.id)
    assert journal is not None and journal.phase == "ready"
    active = value.store.load(lab.manifest.id)
    assert active is not None and active.run_id == journal.candidate.run_id

    monkeypatch.setattr(value, "_cleanup", original_cleanup)
    value._recover_update(lab)
    recovered = value._status(lab)

    assert recovered.run_id == active.run_id
    assert recovered.lock_match
    assert value.store.load_update(lab.manifest.id) is None
    assert len(docker.objects) == 8


def test_ready_journal_restores_previous_if_candidate_degrades_before_recovery(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    original_cleanup = value._cleanup

    def interrupt_old_cleanup(state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        if state.run_id == previous.run_id:
            raise PreflightError("synthetic cleanup interruption")
        original_cleanup(state, coexisting=coexisting)

    monkeypatch.setattr(value, "_cleanup", interrupt_old_cleanup)
    with pytest.raises(PreflightError, match="cleanup interruption"):
        value.activate_reviewed_update(lab)
    journal = value.store.load_update(lab.manifest.id)
    assert journal is not None and journal.phase == "ready"
    candidate_ids = {record.object_id for record in journal.candidate.resources}
    application = next(
        record for record in journal.candidate.resources if record.name.endswith("-app")
    )
    docker.stop(application)

    monkeypatch.setattr(value, "_cleanup", original_cleanup)
    with pytest.raises(PreflightError, match="prior deployment restored"):
        value._recover_update(lab)

    restored = value.store.load(lab.manifest.id)
    assert restored is not None and restored.run_id == previous.run_id
    assert value.store.load_update(lab.manifest.id) is None
    assert not candidate_ids.intersection(docker.objects)
    assert value._status(lab).state == "running"


def test_ready_journal_rechecks_health_before_discarding_previous(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    original_cleanup = value._cleanup

    def interrupt_old_cleanup(state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        if state.run_id == previous.run_id:
            raise PreflightError("synthetic cleanup interruption")
        original_cleanup(state, coexisting=coexisting)

    monkeypatch.setattr(value, "_cleanup", interrupt_old_cleanup)
    with pytest.raises(PreflightError, match="cleanup interruption"):
        value.activate_reviewed_update(lab)
    journal = value.store.load_update(lab.manifest.id)
    assert journal is not None and journal.phase == "ready"
    candidate_ids = {record.object_id for record in journal.candidate.resources}

    monkeypatch.setattr(value, "_cleanup", original_cleanup)
    value.fail_health_call = value.health_calls + 1
    with pytest.raises(
        PreflightError,
        match="failed validation or readiness; prior deployment restored",
    ):
        value._recover_update(lab)

    restored = value.store.load(lab.manifest.id)
    assert restored is not None and restored.run_id == previous.run_id
    assert value.store.load_update(lab.manifest.id) is None
    assert not candidate_ids.intersection(docker.objects)
    assert value._status(lab).state == "running"


def test_ready_journal_policy_drift_restores_previous_before_discarding_it(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    original_cleanup = value._cleanup

    def interrupt_old_cleanup(state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        if state.run_id == previous.run_id:
            raise PreflightError("synthetic cleanup interruption")
        original_cleanup(state, coexisting=coexisting)

    monkeypatch.setattr(value, "_cleanup", interrupt_old_cleanup)
    with pytest.raises(PreflightError, match="cleanup interruption"):
        value.activate_reviewed_update(lab)
    journal = value.store.load_update(lab.manifest.id)
    assert journal is not None and journal.phase == "ready"
    candidate_ids = {record.object_id for record in journal.candidate.resources}
    application = next(
        record for record in journal.candidate.resources if record.name.endswith("-app")
    )
    docker.objects[application.object_id]["HostConfig"]["Memory"] = 1

    monkeypatch.setattr(value, "_cleanup", original_cleanup)
    with pytest.raises(
        PreflightError,
        match="failed validation or readiness; prior deployment restored",
    ):
        value._recover_update(lab)

    restored = value.store.load(lab.manifest.id)
    assert restored is not None and restored.run_id == previous.run_id
    assert value.store.load_update(lab.manifest.id) is None
    assert not candidate_ids.intersection(docker.objects)
    assert value._status(lab).state == "running"


def test_ready_journal_retains_evidence_when_transactional_restore_fails(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    original_cleanup = value._cleanup

    def interrupt_old_cleanup(state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        if state.run_id == previous.run_id:
            raise PreflightError("synthetic cleanup interruption")
        original_cleanup(state, coexisting=coexisting)

    monkeypatch.setattr(value, "_cleanup", interrupt_old_cleanup)
    with pytest.raises(PreflightError, match="cleanup interruption"):
        value.activate_reviewed_update(lab)
    journal = value.store.load_update(lab.manifest.id)
    assert journal is not None and journal.phase == "ready"
    application = next(
        record for record in journal.candidate.resources if record.name.endswith("-app")
    )
    docker.objects[application.object_id]["HostConfig"]["Memory"] = 1
    monkeypatch.setattr(
        value,
        "_restore_previous_update",
        lambda selected, update: (_ for _ in ()).throw(
            PolicyError("synthetic rollback ownership failure")
        ),
    )

    with pytest.raises(PreflightError, match="rollback also failed; update journal retained"):
        value._recover_update(lab)

    assert value.store.load_update(lab.manifest.id) == journal


def test_cli_failed_candidate_restores_previous_runtime_and_discards_candidate(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    previous_ids = {record.object_id for record in previous.resources}
    value.fail_health = True
    monkeypatch.setattr(cli, "Runtime", lambda catalogue=None: value)
    monkeypatch.setattr(
        cli,
        "check_latest",
        lambda selected: (_ for _ in ()).throw(AssertionError("discovery must not activate")),
    )

    assert cli.main(["update", "juice-shop"]) == 5
    assert "candidate identity failure" in capsys.readouterr().err
    assert value.store.load(lab.manifest.id) == previous
    assert set(docker.objects) == previous_ids
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in previous.resources
        if record.kind == "container"
    )


def test_update_preserves_a_stopped_runtime_as_stopped(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.stop(lab)
    previous = preserve_as_previous(value, docker, lab)

    result = value.activate_reviewed_update(lab)

    assert result.outcome == "activated"
    assert result.status.state == "stopped"
    active = value.store.load(lab.manifest.id)
    assert active is not None and active.run_id != previous.run_id
    assert all(
        not docker.objects[record.object_id]["State"]["Running"]
        for record in active.resources
        if record.kind == "container"
    )


def test_failed_update_restores_exact_prior_running_roles(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    docker.stop(gateway)
    previous = preserve_as_previous(value, docker, lab)
    value.fail_health = True

    with pytest.raises(PreflightError, match="candidate identity failure"):
        value.activate_reviewed_update(lab)

    assert value.store.load(lab.manifest.id) == previous
    running_by_role = {
        docker._labels(record.kind, docker.objects[record.object_id]).get(
            "org.vulndockyard.role"
        ): docker.objects[record.object_id]["State"]["Running"]
        for record in previous.resources
        if record.kind == "container"
    }
    assert running_by_role == {"application": True, "gateway": False}


def test_interrupted_rollback_reseeds_before_restarting_the_prior_application(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    for record in previous.resources:
        if record.kind == "container":
            docker.stop(record)
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "staged",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )
    docker.events.clear()

    value._recover_update(lab)

    seed_event = next(index for index, event in enumerate(docker.events) if event[0] == "seed-log")
    app_start = next(
        index
        for index, event in enumerate(docker.events)
        if event == ("start", next(r.name for r in previous.resources if r.name.endswith("-app")))
    )
    assert seed_event < app_start
    assert value.snapshot_health == [previous.runtime_policy]
    assert not any(
        docker._labels("container", inspection).get("org.vulndockyard.role") == "seeder"
        for inspection in docker.objects.values()
        if "Config" in inspection
    )


def test_rollback_adopts_an_unjournaled_seeder_after_the_create_checkpoint_window(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    for record in previous.resources:
        if record.kind == "container":
            docker.stop(record)
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "staged",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )
    create_seeder = docker.create_seeder
    interrupted = False

    def create_then_interrupt(**values: Any) -> ResourceRecord:
        nonlocal interrupted
        record = create_seeder(**values)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return record

    monkeypatch.setattr(docker, "create_seeder", create_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        value._recover_update(lab)
    orphan = next(
        ResourceRecord("container", inspection["Name"], object_id)
        for object_id, inspection in docker.objects.items()
        if "Config" in inspection
        and docker._labels("container", inspection).get("org.vulndockyard.role") == "seeder"
    )
    pending = value.store.load_update(lab.manifest.id)
    assert pending is not None and orphan not in pending.previous.resources

    monkeypatch.setattr(docker, "create_seeder", create_seeder)
    value._recover_update(lab)

    assert orphan.object_id in docker.removed
    assert value.store.load_update(lab.manifest.id) is None
    assert not any(
        docker._labels("container", inspection).get("org.vulndockyard.role") == "seeder"
        for inspection in docker.objects.values()
        if "Config" in inspection
    )


def test_rollback_health_failure_retains_the_recovery_journal(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    for record in previous.resources:
        if record.kind == "container":
            docker.stop(record)
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "staged",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )
    value.fail_health_call = value.health_calls + 1

    with pytest.raises(PreflightError, match="candidate identity failure"):
        value._recover_update(lab)

    assert value.store.load_update(lab.manifest.id) is not None
    value.fail_health_call = None
    value._recover_update(lab)
    assert value.store.load_update(lab.manifest.id) is None


def test_update_rejects_a_candidate_not_bound_to_its_reviewed_lock(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    pulls_before = tuple(docker.pulls)
    arbitrary = dataclasses.replace(lab.manifest.images[0], name="attacker.invalid/image")
    bad_manifest = dataclasses.replace(lab.manifest, images=(arbitrary, *lab.manifest.images[1:]))
    candidate = dataclasses.replace(lab, manifest=bad_manifest)
    with pytest.raises(IntegrityError, match="do not match its immutable lock"):
        value.activate_reviewed_update(candidate)
    assert tuple(docker.pulls) == pulls_before
    assert value.store.load(lab.manifest.id) == previous


def test_update_rejects_effective_drift_in_the_preserved_rollback_base(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    application = next(record for record in previous.resources if record.name.endswith("-app"))
    docker.objects[application.object_id]["HostConfig"]["Memory"] = 0
    pulls_before = tuple(docker.pulls)

    with pytest.raises(PolicyError, match="resource limits differ"):
        value.activate_reviewed_update(lab)

    assert tuple(docker.pulls) == pulls_before
    assert value.store.load_update(lab.manifest.id) is None


def test_interrupted_update_revalidates_rollback_base_before_candidate_cleanup(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "staged",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )
    application = next(record for record in previous.resources if record.name.endswith("-app"))
    docker.objects[application.object_id]["HostConfig"]["Memory"] = 0
    removed_before = tuple(docker.removed)
    candidate_ids = {record.object_id for record in candidate.resources}

    with pytest.raises(PolicyError, match="resource limits differ"):
        value._recover_update(lab)

    assert tuple(docker.removed) == removed_before
    assert candidate_ids.issubset(docker.objects)
    assert value.store.load_update(lab.manifest.id) is not None


def test_update_refuses_legacy_state_without_a_complete_policy_snapshot(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    legacy = dataclasses.replace(previous, schema_version=2, runtime_policy=None)
    value.store.save(legacy)
    pulls_before = tuple(docker.pulls)

    with pytest.raises(PolicyError, match="complete containment rollback snapshot"):
        value.activate_reviewed_update(lab)

    assert tuple(docker.pulls) == pulls_before
    assert value.store.load(lab.manifest.id) == legacy


@pytest.mark.parametrize("operation", ["stop", "remove", "purge"])
def test_cleanup_operations_accept_exact_owned_legacy_state(
    xdg_paths: Paths, operation: str
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    current = value.store.load(lab.manifest.id)
    assert current is not None
    legacy = dataclasses.replace(current, schema_version=2, runtime_policy=None)
    value.store.save(legacy)

    result = getattr(value, operation)(lab)

    if operation == "stop":
        assert result.state == "stopped"
        assert value.store.load(lab.manifest.id) == legacy
        assert docker.objects
        assert not any(
            inspection.get("State", {}).get("Running") for inspection in docker.objects.values()
        )
    else:
        assert result.state == "absent"
        assert value.store.load(lab.manifest.id) is None
        assert docker.objects == {}


def test_next_start_recovers_exact_owned_partial_checkpoint(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        lab.manifest.id,
        lab.manifest_identity,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    partial = docker.create_network("vdy-juice-shop-aaaaaaaaaaaa-net", ownership)
    value.store.save(
        RunState.create(
            lab_id=lab.manifest.id,
            run_id=ownership.run_id,
            manifest_identity=lab.manifest_identity,
            host_port=18080,
            trusted=True,
            requested_reference=lab.manifest.images[0].reference,
            resolved_digest=lab.manifest.images[0].digest,
            resources=(partial,),
            created_at=ownership.created_at,
        )
    )
    recovered = value.up(lab, host_port=18080)
    assert recovered.state == "running"
    assert recovered.run_id != ownership.run_id
    assert partial.object_id in docker.removed


@pytest.mark.parametrize(
    ("operation", "expected_state"),
    (
        ("up", "running"),
        ("restart", "running"),
        ("rebuild", "running"),
        ("reset", "running"),
        ("stop", "absent"),
        ("remove", "absent"),
        ("purge", "absent"),
    ),
)
def test_interrupted_persistent_provisioning_cleans_exact_partial_resources(
    xdg_paths: Paths, operation: str, expected_state: str
) -> None:
    value, docker, packaged = runtime(xdg_paths)
    lab = persistent_review(packaged)
    owner = Ownership(
        lab.manifest.id,
        lab.manifest_identity,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    internal = docker.create_network("vdy-juice-shop-aaaaaaaaaaaa-net", owner, internal=True)
    ingress = docker.create_network("vdy-juice-shop-aaaaaaaaaaaa-ingress", owner, internal=False)
    mount = lab.manifest.ephemeral_storage.seeded[0]
    volume = docker.create_persistent_volume(
        name=f"vdy-juice-shop-aaaaaaaaaaaa-volume-{mount.name}", ownership=owner
    )
    docker.objects[volume.object_id]["TestData"]["partial"] = True
    interrupted = RunState.create(
        lab_id=lab.manifest.id,
        run_id=owner.run_id,
        manifest_identity=lab.manifest_identity,
        host_port=18080,
        trusted=True,
        requested_reference=lab.manifest.images[0].reference,
        resolved_digest=lab.manifest.images[0].digest,
        resources=(internal, ingress, volume),
        gateway_reference=lab.manifest.images[1].reference,
        upstream_port=lab.manifest.services[0].internal_port,
        runtime_policy=_runtime_policy(lab),
        created_at=owner.created_at,
        phase="provisioning",
    )
    value.store.save(interrupted)

    if operation == "up":
        events_before_observation = tuple(docker.events)
        with pytest.raises(PolicyError, match="interrupted provisioning"):
            value.status(lab)
        assert tuple(docker.events) == events_before_observation

    result = value.up(lab, host_port=18080) if operation == "up" else getattr(value, operation)(lab)

    assert result.state == expected_state
    assert {internal.object_id, ingress.object_id, volume.object_id}.issubset(docker.removed)
    assert all(
        inspection.get("TestData", {}).get("partial") is not True
        for inspection in docker.objects.values()
    )
    if expected_state == "running":
        recovered = value.store.load(lab.manifest.id)
        assert recovered is not None
        assert recovered.phase == "steady"
        assert recovered.run_id != owner.run_id
        assert recovered.host_port == 18080
        assert value.remove(lab).state == "absent"
    assert docker.objects == {}


def test_next_start_adopts_resource_created_before_its_checkpoint(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        lab.manifest.id,
        lab.manifest_identity,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    value.store.save(
        RunState.create(
            lab_id=lab.manifest.id,
            run_id=ownership.run_id,
            manifest_identity=lab.manifest_identity,
            host_port=18080,
            trusted=True,
            requested_reference=lab.manifest.images[0].reference,
            resolved_digest=lab.manifest.images[0].digest,
            resources=(),
            gateway_reference=lab.manifest.images[1].reference,
            upstream_port=lab.manifest.services[0].internal_port,
            created_at=ownership.created_at,
        )
    )
    uncheckpointed = docker.create_network(
        "vdy-juice-shop-aaaaaaaaaaaa-net", ownership, internal=True
    )

    recovered = value.up(lab, host_port=18080)

    assert recovered.state == "running"
    assert recovered.run_id != ownership.run_id
    assert uncheckpointed.object_id in docker.removed


def test_existing_state_requires_exact_ownership_and_manifest_identity(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    application = next(record for record in state.resources if record.name.endswith("-app"))
    docker.objects[application.object_id]["Config"]["Labels"]["org.vulndockyard.lab-id"] = "other"
    with pytest.raises(PolicyError, match="ownership"):
        value.up(lab, host_port=18080)
    with pytest.raises(PolicyError, match="ownership"):
        value.remove(lab)


def test_cleanup_prevalidates_every_resource_before_removing_anything(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    docker.objects[gateway.object_id]["Name"] = "unrelated"
    removed_before = tuple(docker.removed)
    with pytest.raises(PolicyError, match="name mismatch"):
        value.remove(lab)
    assert tuple(docker.removed) == removed_before
    assert len(docker.objects) == 8
    assert value.store.load(lab.manifest.id) == state


def test_cleanup_preserves_state_when_existence_inventory_fails(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    application = next(record for record in state.resources if record.name.endswith("-app"))
    docker.fail_exists_for.add(application.object_id)
    removed_before = tuple(docker.removed)

    with pytest.raises(PreflightError, match="existence inventory failure"):
        value.remove(lab)

    assert tuple(docker.removed) == removed_before
    assert value.store.load(lab.manifest.id) == state
    assert application.object_id in docker.objects


def test_runtime_inventory_never_infers_ownership_from_an_id_prefix(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    container = next(record for record in state.resources if record.kind == "container")
    monkeypatch.setattr(
        docker,
        "managed_resources",
        lambda lab_id=None: {
            "container": (container.object_id[:12],),
            "network": (),
            "volume": (),
        },
    )

    with pytest.raises(PolicyError, match="without usable runtime state"):
        value.stop(lab)


def test_missing_state_orphans_are_never_inferred_or_removed(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        lab.manifest.id,
        lab.manifest_identity,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    orphan = docker.create_network("vdy-juice-shop-aaaaaaaaaaaa-net", ownership)
    with pytest.raises(PolicyError, match="without usable runtime state"):
        value.remove(lab)
    with pytest.raises(PolicyError, match="unrecorded managed Docker resources"):
        value.up(lab, host_port=18080)
    assert orphan.object_id in docker.objects
    assert docker.removed == []


def test_single_lab_start_blocks_unrecorded_resources_from_any_lab(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        "other",
        "b" * 64,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    orphan = docker.create_network("vdy-other-aaaaaaaaaaaa-net", ownership)
    with pytest.raises(PolicyError, match="unrecorded managed Docker resources"):
        value.up(lab, host_port=18080)
    assert orphan.object_id in docker.objects
    assert docker.pulls == []


def test_unsafe_override_never_inherits_trust(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, _, lab = runtime(xdg_paths)
    image = "dev.example/app@sha256:" + "f" * 64
    with pytest.raises(PolicyError, match="requires --unsafe-development"):
        value.up(lab, unsafe_image=image)
    result = value.up(lab, host_port=18080, unsafe_image=image, unsafe_development=True)
    assert not result.trusted_run
    assert not result.lock_match
    assert result.trust_level == "untrusted-development"
    assert result.requested_reference == image
    monkeypatch.setattr(cli, "Runtime", lambda catalogue=None: value)
    assert cli.main(["--json", "status", "juice-shop"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["data"][0]["trust_level"] == "untrusted-development"
    assert document["data"][0]["lock_match"] is False
    assert cli.main(["status", "juice-shop"]) == 0
    human = capsys.readouterr().out
    assert "UNTRUSTED development run" in human
    assert "Trust: untrusted-development" in human
    value.stop(lab)
    with pytest.raises(PolicyError, match="preserved runtime is an untrusted"):
        value.up(lab, host_port=18080)
    resumed = value.up(lab, host_port=18080, unsafe_development=True)
    assert resumed.run_id == result.run_id
    assert not resumed.trusted_run
    with pytest.raises(PolicyError, match="does not match the preserved untrusted runtime"):
        value.up(
            lab,
            host_port=18080,
            unsafe_image="dev.example/other@sha256:" + "e" * 64,
            unsafe_development=True,
        )
    with pytest.raises(PolicyError, match="immutable"):
        value.up(
            lab,
            unsafe_image="--host/app@sha256:" + "f" * 64,
            unsafe_development=True,
        )


@pytest.mark.parametrize("role", ["application", "gateway"])
def test_status_fails_closed_when_a_container_image_differs_from_lock(
    xdg_paths: Paths, role: str
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    record = next(
        record
        for record in state.resources
        if record.kind == "container"
        and docker._labels(record.kind, docker.objects[record.object_id]).get(
            "org.vulndockyard.role"
        )
        == role
    )
    docker.objects[record.object_id]["Config"]["Image"] = (
        "attacker.invalid/image@sha256:" + "9" * 64
    )

    with pytest.raises(PolicyError, match="unexpected image"):
        value.status(lab)


def test_restart_and_rebuild_refuse_to_replace_preserved_old_lock(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    previous_ids = set(docker.objects)
    removed_before = tuple(docker.removed)
    created_before = docker.create_count

    with pytest.raises(PolicyError, match="use update"):
        value.restart(lab)
    with pytest.raises(PolicyError, match="use update"):
        value.rebuild(lab)

    assert value.store.load(lab.manifest.id) == previous
    assert set(docker.objects) == previous_ids
    assert tuple(docker.removed) == removed_before
    assert docker.create_count == created_before
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in previous.resources
        if record.kind == "container"
    )


def test_restart_and_rebuild_refuse_an_untrusted_reference_before_cleanup(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    image = "dev.example/app@sha256:" + "f" * 64
    value.up(lab, host_port=18080, unsafe_image=image, unsafe_development=True)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    ids_before = set(docker.objects)
    removed_before = tuple(docker.removed)

    with pytest.raises(PolicyError, match="restart refuses an untrusted"):
        value.restart(lab)
    with pytest.raises(PolicyError, match="reference differs"):
        value.rebuild(lab)

    assert value.store.load(lab.manifest.id) == state
    assert set(docker.objects) == ids_before
    assert tuple(docker.removed) == removed_before
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in state.resources
        if record.kind == "container"
    )


def test_pull_fails_before_docker_for_an_unsupported_host_architecture(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    images = tuple(
        dataclasses.replace(image, architectures=("linux/arm64",)) for image in lab.manifest.images
    )
    manifest = dataclasses.replace(lab.manifest, images=images)
    unsupported = dataclasses.replace(lab, manifest=manifest)
    with pytest.raises(PreflightError, match="does not support linux/amd64"):
        value.pull(unsupported)
    assert docker.pulls == []


def test_pull_requires_reviewed_smoke_evidence_for_the_host_platform(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    manifest = dataclasses.replace(lab.manifest, verification_platforms=("linux/arm64",))
    unverified = dataclasses.replace(lab, manifest=manifest)

    with pytest.raises(PreflightError, match="no reviewed smoke-test evidence for linux/amd64"):
        value.pull(unverified)

    assert docker.pulls == []


def test_single_lab_default_and_egress_acknowledgement(xdg_paths: Paths) -> None:
    value, _, juice = runtime(xdg_paths)
    value.up(juice, host_port=18080)
    with pytest.raises(PolicyError, match="is quarantined"):
        value.up(Catalogue().get("crapi"), host_port=18081)


def test_purge_images_uses_only_locked_digest_references(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.purge(lab, images=True)
    assert set(docker.image_removals) == {image.reference for image in lab.lock.images}

    docker.image_removals.clear()
    unresolved = Catalogue().get("crapi")
    value.purge(unresolved, images=True)
    assert docker.image_removals == []

    pinned_quarantine = Catalogue().get("dvwa")
    value.purge(pinned_quarantine, images=True)
    assert set(docker.image_removals) == {
        image.reference for image in pinned_quarantine.lock.images
    }


class HealthResponse(io.BytesIO):
    def __init__(self, value: bytes, url: str) -> None:
        super().__init__(value)
        self.url = url

    def geturl(self) -> str:
        return self.url

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def test_real_health_checks_application_identity_and_functionality(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    docker = FakeDocker()
    runtime_value = Runtime(paths=xdg_paths, docker=docker)  # type: ignore[arg-type]
    bodies = iter((b"<title>OWASP Juice Shop</title>", b'{"passwordHashLeakChallenge":true}'))
    monkeypatch.setattr(
        "vulndockyard.runtime._open_local_health",
        lambda request, timeout: HealthResponse(next(bodies), request.full_url),
    )
    runtime_value._health(juice_shop, 18080)


def test_health_identity_mismatch_times_out_truthfully(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    docker = FakeDocker()
    runtime_value = Runtime(paths=xdg_paths, docker=docker, sleeper=lambda value: None)  # type: ignore[arg-type]
    moments = iter((0.0, 0.0, 1.0, 1.0))
    monkeypatch.setattr("vulndockyard.runtime.time.monotonic", lambda: next(moments, 1.0))
    monkeypatch.setattr(
        "vulndockyard.runtime._open_local_health",
        lambda request, timeout: HealthResponse(b"wrong application", request.full_url),
    )
    with pytest.raises(PreflightError, match="identity verification timed out"):
        runtime_value._health(juice_shop, 18080)


def test_health_rejects_an_effective_url_change(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    runtime_value = Runtime(paths=xdg_paths, docker=FakeDocker())  # type: ignore[arg-type]
    monkeypatch.setattr(
        "vulndockyard.runtime._open_local_health",
        lambda request, timeout: HealthResponse(b"OWASP Juice Shop", "http://attacker.invalid/"),
    )
    with pytest.raises(IntegrityError, match="escaped its fixed loopback URL"):
        runtime_value._health(juice_shop, 18080)


def test_health_uses_the_lower_reviewed_manifest_timeout(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    docker = FakeDocker()
    docker.timeouts = Timeouts(health=120)
    raw = dict(juice_shop.manifest.raw)
    raw["health_check"] = {**raw["health_check"], "timeout_seconds": 2}
    reviewed = dataclasses.replace(
        juice_shop, manifest=dataclasses.replace(juice_shop.manifest, raw=raw)
    )
    timeouts: list[float] = []

    def ready(request: urllib.request.Request, *, timeout: float) -> HealthResponse:
        timeouts.append(timeout)
        return HealthResponse(b"OWASP Juice Shop passwordHashLeakChallenge", request.full_url)

    monkeypatch.setattr("vulndockyard.runtime._open_local_health", ready)
    Runtime(paths=xdg_paths, docker=docker)._health(reviewed, 18080)  # type: ignore[arg-type]
    assert timeouts and set(timeouts) == {2.0}


def test_health_redirect_handler_never_follows_redirects() -> None:
    request = urllib.request.Request("http://127.0.0.1:8080/")
    _NoRedirect().redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "http://attacker.invalid/",
    )


def test_runtime_pull_verify_open_and_residual_audit(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, _docker, lab = runtime(xdg_paths)
    assert value.pull(lab) == tuple(image.reference for image in lab.manifest.images)
    value.up(lab, host_port=18080)
    assert value.verify(lab).lock_match
    monkeypatch.setattr("vulndockyard.runtime.webbrowser.open", lambda url: True)
    assert value.open(lab) == "http://juice-shop.test:18080"
    audit = value.residual_audit()
    assert len(audit["container"]) == 2
    assert len(audit["network"]) == 2
    assert len(audit["volume"]) == 4
    value.stop(lab)
    with pytest.raises(PolicyError, match="not running"):
        value.verify(lab)
    with pytest.raises(PolicyError, match="not running"):
        value.open(lab)


def test_runtime_rejects_invalid_port_egress_and_multiple_state(xdg_paths: Paths) -> None:
    value, _, lab = runtime(xdg_paths)
    for invalid_port in (0, True):
        with pytest.raises(PolicyError, match="between 1 and 65535"):
            value.up(lab, host_port=invalid_port)
    egress_manifest = dataclasses.replace(lab.manifest, outbound_required=True)
    egress_lab = dataclasses.replace(lab, manifest=egress_manifest)
    with pytest.raises(PolicyError, match="acknowledge-egress"):
        value.up(egress_lab, host_port=18080)
    value.store.save(
        RunState.create(
            lab_id="other",
            run_id="a" * 32,
            manifest_identity="b" * 64,
            host_port=18081,
            trusted=True,
            requested_reference="registry.example.test/app@sha256:" + "c" * 64,
            resolved_digest="sha256:" + "c" * 64,
            resources=(),
        )
    )
    with pytest.raises(PolicyError, match="another lab"):
        value.up(lab, host_port=18080)


def test_status_reports_partially_running_layout_as_degraded(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    application = next(record for record in state.resources if record.name.endswith("-app"))
    docker.stop(application)

    assert value.status(lab).state == "degraded"


@pytest.mark.parametrize("role", ["application", "gateway"])
def test_status_fails_closed_after_a_required_network_is_disconnected(
    xdg_paths: Paths, role: str
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    container = next(
        record
        for record in state.resources
        if record.kind == "container"
        and docker._labels(record.kind, docker.objects[record.object_id]).get(
            "org.vulndockyard.role"
        )
        == role
    )
    networks = docker.objects[container.object_id]["NetworkSettings"]["Networks"]
    networks.pop(next(name for name in networks if name.endswith("-net")))

    with pytest.raises(PolicyError, match="lost a required network attachment"):
        value.status(lab)


def test_status_rejects_extra_container_networks_and_foreign_endpoints(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    application = next(record for record in state.resources if record.name.endswith("-app"))
    internal = next(record for record in state.resources if record.name.endswith("-net"))

    networks = docker.objects[application.object_id]["NetworkSettings"]["Networks"]
    networks["foreign"] = {"NetworkID": "f" * 64}
    with pytest.raises(PolicyError, match="unreviewed network attachment"):
        value.status(lab)
    networks.pop("foreign")

    docker.objects[internal.object_id]["Containers"]["f" * 64] = {"Name": "foreign"}
    with pytest.raises(PolicyError, match="endpoints differ"):
        value.status(lab)


def test_cleanup_rejects_stopped_foreign_configured_network_consumer(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    internal = next(record for record in state.resources if record.name.endswith("-net"))
    foreign_id = "f" * 64
    docker.objects[foreign_id] = {
        "Id": foreign_id,
        "Name": "/foreign-stopped-container",
        "Config": {"Labels": {}, "Image": "unrelated@example"},
        "HostConfig": {},
        "NetworkSettings": {"Networks": {internal.name: {"NetworkID": internal.object_id}}},
        "State": {"Running": False},
    }
    removed_before = tuple(docker.removed)

    with pytest.raises(PolicyError, match="configured on an unowned container"):
        value.remove(lab)

    assert tuple(docker.removed) == removed_before
    assert foreign_id in docker.objects
    assert value.store.load(lab.manifest.id) == state


def test_repeated_up_repairs_only_a_missing_reviewed_network_attachment(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    started = value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    internal = next(record for record in state.resources if record.name.endswith("-net"))
    docker.objects[gateway.object_id]["NetworkSettings"]["Networks"].pop(internal.name)
    docker.objects[internal.object_id]["Containers"].pop(gateway.object_id)

    recovered = value.up(lab, host_port=18080)

    assert recovered.run_id == started.run_id
    assert docker.network_connected(internal, gateway)


def test_acknowledged_required_egress_attaches_only_app_to_reviewed_ingress(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    egress_manifest = dataclasses.replace(lab.manifest, outbound_required=True)
    egress_lab = dataclasses.replace(lab, manifest=egress_manifest)

    with pytest.raises(PolicyError, match="acknowledge-egress"):
        value.up(egress_lab, host_port=18080)
    assert docker.connections == []

    value.up(egress_lab, host_port=18080, acknowledge_egress=True)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    ingress = next(record for record in state.resources if record.name.endswith("-ingress"))
    application = next(record for record in state.resources if record.name.endswith("-app"))
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    internal = next(record for record in state.resources if record.name.endswith("-net"))
    assert set(docker.connections) == {
        (internal.object_id, gateway.object_id),
        (ingress.object_id, application.object_id),
    }
    assert docker.objects[ingress.object_id]["Internal"] is False
