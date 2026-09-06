from __future__ import annotations

import dataclasses
import io
from types import TracebackType
from typing import Any, Self, cast

import pytest

from vulndockyard.catalogue import Catalogue, ReviewedLab
from vulndockyard.docker import ROLE, Ownership, Timeouts
from vulndockyard.errors import PolicyError, PreflightError
from vulndockyard.paths import Paths
from vulndockyard.process import Result
from vulndockyard.runtime import Runtime
from vulndockyard.state import ResourceRecord, RunState


class FakeDocker:
    def __init__(self) -> None:
        self.timeouts = Timeouts(health=0.1)
        self.objects: dict[str, dict[str, Any]] = {}
        self.pulls: list[str] = []
        self.removed: list[str] = []
        self.image_removals: list[str] = []
        self.create_count = 0
        self.fail_gateway = False

    def _id(self) -> str:
        self.create_count += 1
        return f"{self.create_count:064x}"

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
        return {"engine": "test", "compose_v2": not require_compose}

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
            "Internal": internal,
        }
        return ResourceRecord("network", name, object_id)

    def create_application(self, **values: Any) -> ResourceRecord:
        object_id = self._id()
        owner: Ownership = values["ownership"]
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {"Labels": self._label_map(owner, "application")},
            "State": {"Running": False},
        }
        return ResourceRecord("container", values["name"], object_id)

    def create_gateway(self, **values: Any) -> ResourceRecord:
        if self.fail_gateway:
            raise PreflightError("synthetic gateway failure")
        object_id = self._id()
        owner: Ownership = values["ownership"]
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {"Labels": self._label_map(owner, "gateway")},
            "State": {"Running": False},
        }
        return ResourceRecord("container", values["name"], object_id)

    def connect_network(self, network: ResourceRecord, container: ResourceRecord) -> None:
        assert network.object_id in self.objects and container.object_id in self.objects

    def inspect(self, kind: str, object_id: str) -> dict[str, Any]:
        return self.objects[object_id]

    def exists(self, kind: str, object_id: str) -> bool:
        return object_id in self.objects

    def validate_owned(self, record: ResourceRecord, ownership: Ownership) -> dict[str, Any]:
        inspection = self.objects[record.object_id]
        labels = self._labels(record.kind, inspection)
        expected = self._label_map(ownership, labels[ROLE])
        if any(labels.get(key) != value for key, value in expected.items()):
            raise PolicyError("ownership labels mismatch")
        return inspection

    def start(self, record: ResourceRecord) -> None:
        self.objects[record.object_id]["State"]["Running"] = True

    def stop(self, record: ResourceRecord) -> None:
        self.objects[record.object_id]["State"]["Running"] = False

    def remove(self, record: ResourceRecord) -> None:
        self.removed.append(record.object_id)
        del self.objects[record.object_id]

    def remove_image(self, reference: str) -> None:
        self.image_removals.append(reference)

    def logs(self, record: ResourceRecord, *, follow: bool, tail: int = 100) -> Result:
        return Result(("docker", "logs"), 0, "application log\n", "")

    def managed_resources(self) -> dict[str, tuple[str, ...]]:
        return {"container": (), "network": (), "volume": ()}


class ReadyRuntime(Runtime):
    def __init__(self, *, paths: Paths, docker: FakeDocker) -> None:
        super().__init__(catalogue=Catalogue(), paths=paths, docker=docker)  # type: ignore[arg-type]
        self.health_calls = 0

    def _health(self, lab: ReviewedLab, port: int) -> None:
        self.health_calls += 1


def runtime(paths: Paths) -> tuple[ReadyRuntime, FakeDocker, ReviewedLab]:
    docker = FakeDocker()
    value = ReadyRuntime(paths=paths, docker=docker)
    return value, docker, Catalogue().get("juice-shop")


def test_reference_lifecycle_is_idempotent_and_distinct(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    started = value.up(lab, host_port=18080)
    assert started.state == "running"
    assert started.lock_match
    assert started.url == "http://juice-shop.test:18080"
    assert len(started.resources) == 4
    assert len(docker.pulls) == 2
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


def test_interrupted_startup_cleans_only_created_resources(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.fail_gateway = True
    with pytest.raises(PreflightError, match="synthetic"):
        value.up(lab, host_port=18080)
    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None
    assert len(docker.removed) == 3


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


def test_unsafe_override_never_inherits_trust(xdg_paths: Paths) -> None:
    value, _, lab = runtime(xdg_paths)
    image = "dev.example/app@sha256:" + "f" * 64
    with pytest.raises(PolicyError, match="requires --unsafe-development"):
        value.up(lab, unsafe_image=image)
    result = value.up(lab, host_port=18080, unsafe_image=image, unsafe_development=True)
    assert not result.trusted_run
    assert not result.lock_match
    assert result.requested_reference == image


def test_single_lab_default_and_egress_acknowledgement(xdg_paths: Paths) -> None:
    value, _, juice = runtime(xdg_paths)
    value.up(juice, host_port=18080)
    with pytest.raises(PolicyError, match="is quarantined"):
        value.up(Catalogue().get("crapi"), host_port=18081)


def test_purge_images_uses_only_locked_digest_references(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.purge(lab, images=True)
    assert set(docker.image_removals) == {image.reference for image in lab.manifest.images}


class HealthResponse(io.BytesIO):
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
        "vulndockyard.runtime.urllib.request.urlopen",
        lambda request, timeout: HealthResponse(next(bodies)),
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
        "vulndockyard.runtime.urllib.request.urlopen",
        lambda request, timeout: HealthResponse(b"wrong application"),
    )
    with pytest.raises(PreflightError, match="identity verification timed out"):
        runtime_value._health(juice_shop, 18080)


def test_runtime_pull_verify_open_and_residual_audit(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    assert value.pull(lab) == tuple(image.reference for image in lab.manifest.images)
    value.up(lab, host_port=18080)
    assert value.verify(lab).lock_match
    monkeypatch.setattr("vulndockyard.runtime.webbrowser.open", lambda url: True)
    assert value.open(lab) == "http://juice-shop.test:18080"
    assert value.residual_audit() == {"container": (), "network": (), "volume": ()}
    value.stop(lab)
    with pytest.raises(PolicyError, match="not running"):
        value.verify(lab)
    with pytest.raises(PolicyError, match="not running"):
        value.open(lab)


def test_runtime_rejects_invalid_port_egress_and_multiple_state(xdg_paths: Paths) -> None:
    value, _, lab = runtime(xdg_paths)
    with pytest.raises(PolicyError, match="between 1 and 65535"):
        value.up(lab, host_port=0)
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
            requested_reference="example/app@sha256:" + "c" * 64,
            resolved_digest="sha256:" + "c" * 64,
            resources=(),
        )
    )
    with pytest.raises(PolicyError, match="another lab"):
        value.up(lab, host_port=18080)
